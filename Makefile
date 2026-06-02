# sstp-server top-level Makefile
#
# Wrappers around `cargo` (userspace daemon) and the out-of-tree
# `kmod/` Kbuild (kernel module). The real build systems remain
# authoritative; this file exists to give packagers and operators
# the standard `make / make install / make clean` surface and to
# provide stable target names that `debian/rules` can call into.
#
# Layout / staging variables follow GNU coding standards so
# distro packaging (`dh_auto_install`) works out of the box:
#
#   DESTDIR     staging root prepended to every install path
#   PREFIX      /usr by default
#   EXEC_PREFIX $(PREFIX)
#   BINDIR      $(EXEC_PREFIX)/bin
#   SBINDIR     $(EXEC_PREFIX)/sbin
#   SYSCONFDIR  /etc
#   LIBDIR      $(EXEC_PREFIX)/lib
#   UNITDIR     $(LIBDIR)/systemd/system
#   DOCDIR      $(PREFIX)/share/doc/sstp-server
#   SRCDIR_DKMS $(PREFIX)/src
#
# Toggle individual sub-builds with the corresponding `*_ENABLE`
# variable. By default the userspace daemon builds; the kmod is
# opt-in via `make kmod` because it requires kernel headers.

PACKAGE      := sstp-server
VERSION      := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
KMOD_NAME    := sstp
KMOD_VERSION := $(VERSION)

DESTDIR     ?=
PREFIX      ?= /usr
EXEC_PREFIX ?= $(PREFIX)
BINDIR      ?= $(EXEC_PREFIX)/bin
SBINDIR     ?= $(EXEC_PREFIX)/sbin
SYSCONFDIR  ?= /etc
LIBDIR      ?= $(EXEC_PREFIX)/lib
UNITDIR     ?= $(LIBDIR)/systemd/system
UDEVDIR     ?= $(LIBDIR)/udev/rules.d
DOCDIR      ?= $(PREFIX)/share/doc/$(PACKAGE)
SRCDIR_DKMS ?= $(PREFIX)/src

# Cargo profile. Override with `make PROFILE=dev` for a debug build.
PROFILE     ?= release
CARGO       ?= cargo
CARGO_FLAGS ?=
ifeq ($(PROFILE),release)
CARGO_PROFILE_FLAG := --release
TARGET_DIR := target/release
else
CARGO_PROFILE_FLAG :=
TARGET_DIR := target/debug
endif

# Kernel build directory for the out-of-tree kmod. Honour KDIR /
# KERNELDIR / KERNEL_SRC since different distros / DKMS pass
# different names.
KDIR ?= $(KERNEL_SRC)
ifeq ($(KDIR),)
KDIR := $(KERNELDIR)
endif
ifeq ($(KDIR),)
KDIR := /lib/modules/$(shell uname -r)/build
endif

INSTALL         ?= install
INSTALL_PROGRAM ?= $(INSTALL) -m 0755
INSTALL_DATA    ?= $(INSTALL) -m 0644
INSTALL_DIR     ?= $(INSTALL) -d -m 0755

# ---------------------------------------------------------------------------
# Phony-target manifest.
# ---------------------------------------------------------------------------

.PHONY: all build release debug check test clippy fmt fmt-check \
        clean distclean \
        install install-bin install-systemd install-config install-docs \
        install-logrotate install-certbot-hook install-udev install-kmod-src \
        kmod kmod-clean kmod-install \
        dist deb help

all: build

help:
	@echo "Targets:"
	@echo "  build / release / debug   build the userspace daemon"
	@echo "  test / clippy / fmt-check tree-wide checks"
	@echo "  install                   install daemon + systemd unit + config"
	@echo "  install-kmod-src          install kmod sources for DKMS"
	@echo "  kmod                      build the kmod against KDIR=$(KDIR)"
	@echo "  kmod-install              modules_install into the running kernel"
	@echo "  kmod-clean                clean the kmod tree"
	@echo "  clean / distclean         remove build artifacts"
	@echo "  deb                       build .deb via dpkg-buildpackage -uc -us"
	@echo "Variables: DESTDIR PREFIX SYSCONFDIR UNITDIR KDIR PROFILE"

# ---------------------------------------------------------------------------
# Userspace build.
# ---------------------------------------------------------------------------

build release:
	$(CARGO) build $(CARGO_PROFILE_FLAG) --bin sstp-server --bin sstp-server-cli $(CARGO_FLAGS)

debug:
	$(CARGO) build --bin sstp-server --bin sstp-server-cli $(CARGO_FLAGS)

check:
	$(CARGO) check --bin sstp-server --bin sstp-server-cli $(CARGO_FLAGS)

test:
	$(CARGO) test --bin sstp-server $(CARGO_FLAGS)

clippy:
	$(CARGO) clippy --bin sstp-server --bin sstp-server-cli -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

# ---------------------------------------------------------------------------
# Userspace install. Splits cleanly so debian/rules can call the
# pieces it wants and skip the ones dh_install* takes over.
# ---------------------------------------------------------------------------

install: install-bin install-systemd install-config install-docs install-logrotate install-certbot-hook install-udev

install-bin:
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROGRAM) $(TARGET_DIR)/sstp-server $(DESTDIR)$(SBINDIR)/sstp-server
	$(INSTALL_PROGRAM) $(TARGET_DIR)/sstp-server-cli $(DESTDIR)$(SBINDIR)/sstp-server-cli

install-systemd:
	$(INSTALL_DIR) $(DESTDIR)$(UNITDIR)
	$(INSTALL_DATA) packaging/systemd/sstp-server.service \
	    $(DESTDIR)$(UNITDIR)/sstp-server.service

install-config:
	$(INSTALL_DIR) $(DESTDIR)$(SYSCONFDIR)/sstp-server
	$(INSTALL_DATA) packaging/sstp-server.env \
	    $(DESTDIR)$(SYSCONFDIR)/sstp-server/sstp-server.env

install-docs:
	$(INSTALL_DIR) $(DESTDIR)$(DOCDIR)
	$(INSTALL_DATA) README.md $(DESTDIR)$(DOCDIR)/README.md
	$(INSTALL_DATA) docs/admin-guide.md $(DESTDIR)$(DOCDIR)/admin-guide.md
	$(INSTALL_DATA) docs/data-path.md $(DESTDIR)$(DOCDIR)/data-path.md

install-logrotate:
	$(INSTALL_DIR) $(DESTDIR)$(SYSCONFDIR)/logrotate.d
	$(INSTALL_DATA) packaging/sstp-server.logrotate \
	    $(DESTDIR)$(SYSCONFDIR)/logrotate.d/sstp-server

install-certbot-hook:
	$(INSTALL_DIR) $(DESTDIR)$(PREFIX)/share/$(PACKAGE)
	$(INSTALL_PROGRAM) packaging/certbot-deploy-hook.sh \
	    $(DESTDIR)$(PREFIX)/share/$(PACKAGE)/certbot-deploy-hook.sh

install-udev:
	$(INSTALL_DIR) $(DESTDIR)$(UDEVDIR)
	$(INSTALL_DATA) packaging/udev/99-sstp-server.rules \
	    $(DESTDIR)$(UDEVDIR)/99-sstp-server.rules

# Stage the kmod sources for DKMS (used by debian/rules of the
# `*-dkms` binary package). Mirrors the kmod/ tree under
# /usr/src/sstp-<version>/ together with dkms.conf.
install-kmod-src:
	$(INSTALL_DIR) $(DESTDIR)$(SRCDIR_DKMS)/$(KMOD_NAME)-$(KMOD_VERSION)
	cp -a kmod/. $(DESTDIR)$(SRCDIR_DKMS)/$(KMOD_NAME)-$(KMOD_VERSION)/
	$(INSTALL_DATA) packaging/dkms.conf \
	    $(DESTDIR)$(SRCDIR_DKMS)/$(KMOD_NAME)-$(KMOD_VERSION)/dkms.conf
	sed -i 's/@VERSION@/$(KMOD_VERSION)/g' \
	    $(DESTDIR)$(SRCDIR_DKMS)/$(KMOD_NAME)-$(KMOD_VERSION)/dkms.conf

# ---------------------------------------------------------------------------
# Kernel module — delegates to kmod/Makefile (which delegates to
# Kbuild). KDIR can be overridden; defaults to the running kernel.
# ---------------------------------------------------------------------------

kmod:
	$(MAKE) -C kmod KDIR=$(KDIR)

kmod-clean:
	$(MAKE) -C kmod KDIR=$(KDIR) clean

kmod-install:
	$(MAKE) -C kmod KDIR=$(KDIR) modules_install

# ---------------------------------------------------------------------------
# Cleanup.
# ---------------------------------------------------------------------------

clean:
	$(CARGO) clean
	$(MAKE) -C kmod clean 2>/dev/null || true

distclean: clean
	rm -rf debian/.debhelper debian/sstp-server debian/sstp-server-dkms \
	       debian/files debian/*.substvars debian/*.log debian/debhelper-build-stamp

# ---------------------------------------------------------------------------
# Source tarball + Debian package.
# ---------------------------------------------------------------------------

dist:
	git archive --format=tar.gz --prefix=$(PACKAGE)-$(VERSION)/ \
	    -o $(PACKAGE)_$(VERSION).orig.tar.gz HEAD

deb:
	dpkg-buildpackage -uc -us -b
