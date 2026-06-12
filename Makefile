obj-m += ytblock.o
ytblock-objs := src/ytblock.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
DESTDIR ?=

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -f src/*.o src/*.ko src/*.mod.c Module.symvers modules.order

install: all
	@if [ "$(shell id -u)" -ne 0 ]; then \
		echo "Re-running install as root..."; \
		exec sudo $(MAKE) install; \
	fi
	@echo "Unloading module to release file protection..."
	@rmmod ytblock 2>/dev/null || \
	 (echo "  0" > /sys/kernel/ytblock/enabled 2>/dev/null; \
	  rmmod ytblock 2>/dev/null) || true
	@KO_FILE="$(DESTDIR)/lib/modules/$(shell uname -r)/extra/ytblock.ko"; \
	if [ -f "$$KO_FILE" ] && command -v chattr >/dev/null 2>&1; then \
		chattr -i "$$KO_FILE" 2>/dev/null; \
	fi
	install -d $(DESTDIR)/lib/modules/$(shell uname -r)/extra
	install -m 644 ytblock.ko $(DESTDIR)/lib/modules/$(shell uname -r)/extra/
	depmod -a
	install -d $(DESTDIR)/etc/modules-load.d
	echo "ytblock" > $(DESTDIR)/etc/modules-load.d/ytblock.conf
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 ytblockctl $(DESTDIR)/usr/local/bin/ytblockctl
	install -d $(DESTDIR)/etc/ytblock
	install -d $(DESTDIR)/etc/ytblock/keys
	install -d $(DESTDIR)/var/lib/ytblock
	@KO_FILE="/lib/modules/$(shell uname -r)/extra/ytblock.ko"; \
	if command -v chattr >/dev/null 2>&1; then \
		chattr +i "$$KO_FILE" 2>/dev/null && echo "  File: immutable" || echo "  Warning: could not set immutable flag"; \
	fi
	modprobe ytblock 2>/dev/null || true
	@/usr/local/bin/ytblockctl block youtube.com www.youtube.com m.youtube.com youtu.be ytimg.com googlevideo.com gvt2.com 2>/dev/null || true
	@echo ""
	@echo "ytblock installed (disabled by default)."
	@echo "  ytblockctl enable 60   — block for 60 minutes"
	@echo "  ytblockctl disable     — stop blocking"
	@echo "  ytblockctl status      — check status"
	@echo "  ytblockctl unblock     — remove module entirely"
	@echo ""

uninstall:
	@if [ "$(shell id -u)" -ne 0 ]; then \
		echo "Re-running uninstall as root..."; \
		exec sudo $(MAKE) uninstall; \
	fi
	@echo "Unloading module..."
	@if [ -d /sys/kernel/ytblock ]; then \
		echo 0 > /sys/kernel/ytblock/enabled 2>/dev/null; \
		sleep 1; \
		rmmod -f ytblock 2>/dev/null || true; \
	fi
	@HOSTS_FILE="/etc/hosts"; \
	MOD_LOAD="/etc/modules-load.d/ytblock.conf"; \
	DOMAINS="/etc/ytblock/domains.conf"; \
	for f in "$$HOSTS_FILE" "$$MOD_LOAD" "$$DOMAINS"; do \
		if [ -f "$$f" ] && command -v chattr >/dev/null 2>&1; then \
			chattr -i "$$f" 2>/dev/null || true; \
		fi; \
	done; \
	HOSTS_MARKER="# ytblock managed entries - do not edit manually"; \
	if grep -q "$$HOSTS_MARKER" "$$HOSTS_FILE" 2>/dev/null; then \
		sed -i "/$$HOSTS_MARKER/,/^$$/d" "$$HOSTS_FILE"; \
		echo "  Cleaned ytblock entries from /etc/hosts"; \
	fi
	@KO_FILE="/lib/modules/$(shell uname -r)/extra/ytblock.ko"; \
	for f in "$$KO_FILE" "$$MOD_LOAD" "$$DOMAINS"; do \
		if [ -f "$$f" ] && command -v chattr >/dev/null 2>&1; then \
			chattr -i "$$f" 2>/dev/null || true; \
		fi; \
	done
	rm -f $(DESTDIR)/etc/modules-load.d/ytblock.conf
	rm -f $(DESTDIR)/usr/local/bin/ytblockctl
	@KO_FILE="$(DESTDIR)/lib/modules/$(shell uname -r)/extra/ytblock.ko"; \
	if [ -f "$$KO_FILE" ] && command -v chattr >/dev/null 2>&1; then \
		chattr -i "$$KO_FILE" 2>/dev/null || true; \
	fi
	rm -f $(DESTDIR)/lib/modules/$(shell uname -r)/extra/ytblock.ko
	rm -rf $(DESTDIR)/var/lib/ytblock
	rm -rf $(DESTDIR)/etc/ytblock
	depmod -a
	@echo "ytblock uninstalled."

test:
	@echo "Running integration tests (requires root)..."
	@if [ "$(shell id -u)" -ne 0 ]; then \
		echo "Re-running tests as root..."; \
		exec sudo ./test.sh; \
	else \
		exec ./test.sh; \
	fi

.PHONY: all clean install uninstall test