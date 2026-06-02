# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Convenience wrapper. The real build is driven by Kbuild.

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# Pass `DEBUG=1` to enable verbose pr_debug() / sstp_dbg() output
# in dmesg. Defaults to 0 so production builds carry no overhead.
DEBUG ?= 0

CLANG_FORMAT ?= clang-format
# In-tree C sources only; generated *.mod.c is excluded.
FORMAT_SRCS  := $(filter-out %.mod.c,$(wildcard $(PWD)/*.c)) $(wildcard $(PWD)/*.h) \
		$(wildcard $(PWD)/include/uapi/*.h)

.PHONY: all clean modules_install format format-check

all:
	$(MAKE) -C $(KDIR) M=$(PWD) DEBUG=$(DEBUG) modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Reformat all C sources/headers in the kmod tree per kmod/.clang-format
# (Linux kernel style: tabs, 100-col, K&R braces, etc).
format:
	@command -v $(CLANG_FORMAT) >/dev/null 2>&1 || { \
		echo "error: $(CLANG_FORMAT) not found; install clang-format" >&2; exit 1; }
	$(CLANG_FORMAT) -i --style=file $(FORMAT_SRCS)

# CI-friendly: fails non-zero if any source would be reformatted.
format-check:
	@command -v $(CLANG_FORMAT) >/dev/null 2>&1 || { \
		echo "error: $(CLANG_FORMAT) not found; install clang-format" >&2; exit 1; }
	@fail=0; for f in $(FORMAT_SRCS); do \
		if ! $(CLANG_FORMAT) --style=file --dry-run --Werror "$$f" >/dev/null 2>&1; then \
			echo "needs formatting: $$f"; fail=1; \
		fi; \
	done; exit $$fail
