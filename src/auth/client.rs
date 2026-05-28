//! High-level RADIUS authentication helpers built on
//! [`radius_tokio::client::RadiusClient`].
//!
//! The upstream client owns the UDP socket, retry policy, identifier
//! allocation, and Request/Message-Authenticator sealing. This module
//! adds:
//!
//! * PPP-method-specific request building via [`super::request`].
//! * [`AccessOutcome`] → [`AuthResult`] projection.
//! * [`EapSession`] for the multi-round-trip EAP pass-through loop
//!   (Access-Challenge → forward EAP-Request to PPP → receive
//!   EAP-Response → Access-Request with echoed `State` → repeat).

use std::net::SocketAddr;

use radius_tokio::{
    client::{AccessOutcome, ClientError, RadiusClient},
    dict::rfc,
    eap,
};

use crate::auth::{AuthAccept, AuthError, request::AccessRequestCtx};

/// Either an Access-Accept payload or a recoverable auth failure.
pub type AuthResult = Result<AuthAccept, AuthError>;

impl From<ClientError> for AuthError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Io(io_err) => AuthError::Transport(TransportError::Io(io_err)),
            ClientError::Timeout => AuthError::Transport(TransportError::Timeout),
            other => AuthError::Transport(TransportError::Other(other.to_string())),
        }
    }
}

/// Transport-layer failure summary. Kept as a thin newtype over the
/// upstream [`ClientError`] so call sites have a stable enum to
/// `match` on without depending on `radius_tokio::client`'s exact
/// variant set.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("no reply within retry budget")]
    Timeout,
    #[error("{0}")]
    Other(String),
}

/// PAP authentication round-trip.
pub async fn authenticate_pap(
    client: &RadiusClient,
    peer: SocketAddr,
    secret: &[u8],
    ctx: &AccessRequestCtx<'_>,
    password: &[u8],
) -> AuthResult {
    let outcome = client
        .access_request(peer, secret, |buf, ra| {
            super::request::apply_pap(buf, ctx, ra, secret, password)
        })
        .await?;
    project_terminal(outcome, secret)
}

/// MS-CHAPv2 authentication round-trip.
#[allow(clippy::too_many_arguments)]
pub async fn authenticate_mschapv2(
    client: &RadiusClient,
    peer: SocketAddr,
    secret: &[u8],
    ctx: &AccessRequestCtx<'_>,
    authenticator_challenge: &[u8; 16],
    chap_ident: u8,
    peer_challenge: &[u8; 16],
    nt_response: &[u8; 24],
    flags: u8,
) -> AuthResult {
    let outcome = client
        .access_request(peer, secret, |buf, _ra| {
            super::request::apply_mschapv2(
                buf,
                ctx,
                authenticator_challenge,
                chap_ident,
                peer_challenge,
                nt_response,
                flags,
            )
        })
        .await?;
    project_terminal(outcome, secret)
}

/// EAP pass-through state for a single session.
///
/// Holds the opaque `State` attribute echoed across rounds. Drop it
/// (or call [`EapSession::reset`]) when the session ends.
#[derive(Debug, Default)]
pub struct EapSession {
    state: Option<Vec<u8>>,
}

/// Result of one round of the EAP loop.
#[derive(Debug)]
pub enum EapStep {
    /// RADIUS returned Access-Challenge. The driving task must
    /// forward `eap_request` to the PPP peer, await its
    /// EAP-Response, then call [`EapSession::step`] again.
    Continue { eap_request: Vec<u8> },
    /// RADIUS returned Access-Accept. EAP is done.
    Accept(AuthAccept),
    /// RADIUS returned Access-Reject.
    Reject(Option<String>),
}

impl EapSession {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Discard any retained `State` so the next request starts a
    /// fresh EAP conversation.
    pub fn reset(&mut self) {
        self.state = None;
    }

    /// Forward one EAP packet (Identity-Response on the first call,
    /// the peer's response to the previous EAP-Request afterwards)
    /// and await the next Access-Challenge / -Accept / -Reject.
    pub async fn step(
        &mut self,
        client: &RadiusClient,
        peer: SocketAddr,
        secret: &[u8],
        ctx: &AccessRequestCtx<'_>,
        eap_from_peer: &[u8],
    ) -> Result<EapStep, AuthError> {
        let state = self.state.as_deref();
        let outcome = client
            .access_request(peer, secret, |buf, _ra| {
                super::request::apply_eap(buf, ctx, eap_from_peer, state)
            })
            .await?;

        match outcome {
            AccessOutcome::Accept {
                authenticator,
                attributes,
            } => {
                self.reset();
                let accept = super::reply::decode_accept(&attributes, secret, &authenticator)?;
                Ok(EapStep::Accept(accept))
            }
            AccessOutcome::Reject { attributes, .. } => {
                self.reset();
                Ok(EapStep::Reject(super::reply::reject_reason(&attributes)))
            }
            AccessOutcome::Challenge { attributes, .. } => {
                // Reassemble the EAP-Request payload across however
                // many EAP-Message attributes the server emitted.
                let eap_request = eap::reassemble(&attributes);
                if eap_request.is_empty() {
                    return Err(AuthError::Malformed(
                        "Access-Challenge without EAP-Message",
                    ));
                }
                // Echo the new State on the next round.
                self.state = radius_tokio::attributes::first(&attributes, rfc::attrs::STATE)
                    .map(<[u8]>::to_vec);
                Ok(EapStep::Continue { eap_request })
            }
        }
    }
}

fn project_terminal(outcome: AccessOutcome, secret: &[u8]) -> AuthResult {
    match outcome {
        AccessOutcome::Accept {
            authenticator,
            attributes,
        } => super::reply::decode_accept(&attributes, secret, &authenticator),
        AccessOutcome::Reject { attributes, .. } => {
            Err(AuthError::Rejected(super::reply::reject_reason(&attributes)))
        }
        AccessOutcome::Challenge { .. } => Err(AuthError::UnexpectedChallenge),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use radius_tokio::{Code, PacketBuffer, Reply};
    use tokio::net::UdpSocket;

    /// Spin up a one-shot RADIUS responder on a UDP socket; reply to
    /// the first datagram with the supplied builder. Returns the
    /// bound `SocketAddr` plus a join handle.
    async fn one_shot_responder<F>(
        secret: Vec<u8>,
        mut respond: F,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>)
    where
        F: FnMut(u8, [u8; 16]) -> PacketBuffer + Send + 'static,
    {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = sock.local_addr().expect("addr");
        let h = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = sock.recv_from(&mut buf).await.expect("recv");
            let datagram = &buf[..n];
            // Identifier byte at offset 1, Request Authenticator at 4..20.
            let id = datagram[1];
            let mut ra = [0u8; 16];
            ra.copy_from_slice(&datagram[4..20]);
            let reply = respond(id, ra);
            // Reply::seal_for + Code only; here we receive a
            // pre-sealed PacketBuffer from the closure.
            sock.send_to(reply.as_bytes(), peer).await.expect("send");
            drop(secret); // suppress unused warning
        });
        (addr, h)
    }

    fn ctx() -> AccessRequestCtx<'static> {
        AccessRequestCtx {
            username: "alice",
            calling_station_id: None,
            nas_identifier: None,
        }
    }

    #[tokio::test]
    async fn pap_accept_round_trip() {
        use radius_tokio::dict::rfc;
        use std::net::Ipv4Addr;

        let secret = b"shh".to_vec();
        let secret_for_server = secret.clone();
        let (server_addr, _h) = one_shot_responder(secret.clone(), move |id, ra| {
            let mut reply = Reply::new(Code::ACCESS_ACCEPT, id);
            reply
                .add(rfc::attrs::FRAMED_IP_ADDRESS, Ipv4Addr::new(10, 9, 8, 7))
                .unwrap();
            reply.seal_for(&ra, &secret_for_server)
        })
        .await;

        let client = RadiusClient::bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind client");
        let accept = authenticate_pap(&client, server_addr, &secret, &ctx(), b"pw")
            .await
            .expect("accept");
        assert_eq!(accept.framed_ip, Ipv4Addr::new(10, 9, 8, 7));
    }

    #[tokio::test]
    async fn pap_reject_round_trip() {
        let secret = b"shh".to_vec();
        let secret_for_server = secret.clone();
        let (server_addr, _h) = one_shot_responder(secret.clone(), move |id, ra| {
            let mut reply = Reply::new(Code::ACCESS_REJECT, id);
            reply.add(rfc::attrs::REPLY_MESSAGE, "bad password").unwrap();
            reply.seal_for(&ra, &secret_for_server)
        })
        .await;

        let client = RadiusClient::bind("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind client");
        let err = authenticate_pap(&client, server_addr, &secret, &ctx(), b"pw")
            .await
            .unwrap_err();
        match err {
            AuthError::Rejected(Some(m)) => assert_eq!(m, "bad password"),
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}
