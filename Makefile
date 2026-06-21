obj-m += kblocker.o
kblocker-objs := src/kblocker.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
DESTDIR ?=

all: kblockerctl
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

kblockerctl: cmd/kblockerctl/main.go
	cd cmd/kblockerctl && go build -o ../../kblockerctl .

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -f src/*.o src/*.ko src/*.mod.c Module.symvers modules.order kblockerctl

install: all
	@if [ "$(shell id -u)" -ne 0 ]; then \
		echo "Re-running install as root..."; \
		exec sudo $(MAKE) install; \
	fi
	@echo "Unloading module to release file protection..."
	@rmmod kblocker 2>/dev/null || \
	 (echo "  0" > /sys/kernel/kblocker/enabled 2>/dev/null; \
	  rmmod kblocker 2>/dev/null) || true
	@KO_FILE="$(DESTDIR)/lib/modules/$(shell uname -r)/extra/kblocker.ko"; \
	if [ -f "$$KO_FILE" ] && command -v chattr >/dev/null 2>&1; then \
		chattr -i "$$KO_FILE" 2>/dev/null; \
	fi
	install -d $(DESTDIR)/lib/modules/$(shell uname -r)/extra
	install -m 644 kblocker.ko $(DESTDIR)/lib/modules/$(shell uname -r)/extra/
	depmod -a
	install -d $(DESTDIR)/etc/modules-load.d
	echo "kblocker" > $(DESTDIR)/etc/modules-load.d/kblocker.conf
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 kblockerctl $(DESTDIR)/usr/local/bin/kblockerctl
	install -d $(DESTDIR)/etc/kblocker
	install -d $(DESTDIR)/etc/kblocker/keys
	install -d $(DESTDIR)/var/lib/kblocker
	@KO_FILE="/lib/modules/$(shell uname -r)/extra/kblocker.ko"; \
	if command -v chattr >/dev/null 2>&1; then \
		chattr +i "$$KO_FILE" 2>/dev/null && echo "  File: immutable" || echo "  Warning: could not set immutable flag"; \
	fi
	modprobe kblocker 2>/dev/null || true
	@/usr/local/bin/kblockerctl block youtube.com www.youtube.com m.youtube.com youtu.be ytimg.com googlevideo.com gvt2.com 2>/dev/null || true
	@echo ""
	@echo "kblocker installed (disabled by default)."
	@echo "  kblockerctl enable 60   — block for 60 minutes"
	@echo "  kblockerctl disable     — stop blocking"
	@echo "  kblockerctl status      — check status"
	@echo "  kblockerctl unblock     — remove module entirely"
	@echo ""

uninstall:
	@if [ "$(shell id -u)" -ne 0 ]; then \
		echo "Re-running uninstall as root..."; \
		exec sudo $(MAKE) uninstall; \
	fi
	@echo "Unloading module..."
	@if [ -d /sys/kernel/kblocker ]; then \
		echo 0 > /sys/kernel/kblocker/enabled 2>/dev/null; \
		sleep 1; \
		rmmod -f kblocker 2>/dev/null || true; \
	fi
	@HOSTS_FILE="/etc/hosts"; \
	MOD_LOAD="/etc/modules-load.d/kblocker.conf"; \
	DOMAINS="/etc/kblocker/domains.conf"; \
	for f in "$$HOSTS_FILE" "$$MOD_LOAD" "$$DOMAINS"; do \
		if [ -f "$$f" ] && command -v chattr >/dev/null 2>&1; then \
			chattr -i "$$f" 2>/dev/null || true; \
		fi; \
	done; \
	HOSTS_MARKER="# kblocker managed entries - do not edit manually"; \
	if grep -q "$$HOSTS_MARKER" "$$HOSTS_FILE" 2>/dev/null; then \
		sed -i "/$$HOSTS_MARKER/,/^$$/d" "$$HOSTS_FILE"; \
		echo "  Cleaned kblocker entries from /etc/hosts"; \
	fi
	@KO_FILE="/lib/modules/$(shell uname -r)/extra/kblocker.ko"; \
	for f in "$$KO_FILE" "$$MOD_LOAD" "$$DOMAINS"; do \
		if [ -f "$$f" ] && command -v chattr >/dev/null 2>&1; then \
			chattr -i "$$f" 2>/dev/null || true; \
		fi; \
	done
	@if [ -d /var/lib/kblocker ]; then \
		find /var/lib/kblocker -type f -exec chattr -i {} \; 2>/dev/null || true; \
	fi
	rm -f $(DESTDIR)/etc/modules-load.d/kblocker.conf
	rm -f $(DESTDIR)/usr/local/bin/kblockerctl
	@KO_FILE="$(DESTDIR)/lib/modules/$(shell uname -r)/extra/kblocker.ko"; \
	if [ -f "$$KO_FILE" ] && command -v chattr >/dev/null 2>&1; then \
		chattr -i "$$KO_FILE" 2>/dev/null || true; \
	fi
	rm -f $(DESTDIR)/lib/modules/$(shell uname -r)/extra/kblocker.ko
	rm -rf $(DESTDIR)/var/lib/kblocker
	rm -rf $(DESTDIR)/etc/kblocker
	depmod -a
	@echo "kblocker uninstalled."

test:
	@echo "Running integration tests (requires root)..."
	@if [ "$(shell id -u)" -ne 0 ]; then \
		echo "Re-running tests as root..."; \
		exec sudo ./test.sh; \
	else \
		exec ./test.sh; \
	fi

.PHONY: all clean install uninstall test kblockerctl
