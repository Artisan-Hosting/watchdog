obj-m := awdog.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
MODULE := $(PWD)/awdog.ko
MOKDIR := $(HOME)/mok
SIGN_PRIV := $(MOKDIR)/MOK.priv
SIGN_DER  := $(MOKDIR)/MOK.der

# find sign-file dynamically
SIGN_TOOL := $(shell \
	if [ -x /usr/src/linux-headers-$(uname -r)/scripts/sign-file ]; then \
		echo /usr/src/linux-headers-$(uname -r)/scripts/sign-file; \
	elif [ -x /usr/lib/modules/$(uname -r)/build/scripts/sign-file ]; then \
		echo /usr/lib/modules/$(uname -r)/build/scripts/sign-file; \
	elif [ -x /usr/src/kernels/$(uname -r)/scripts/sign-file ]; then \
		echo /usr/src/kernels/$(uname -r)/scripts/sign-file; \
	else \
		echo "sign-file-not-found"; \
	fi)

.PHONY: all clean sign sign_production sign_devmachine install uninstall

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

sign:
	@echo "[+] Signing $(MODULE)"
	@if [ "$(SIGN_TOOL)" = "sign-file-not-found" ]; then \
		echo "[-] sign-file not found for kernel $(shell uname -r)"; exit 1; fi
	sudo "$(SIGN_TOOL)" sha256 "$(SIGN_PRIV)" "$(SIGN_DER)" "$(MODULE)"
	@modinfo "$(MODULE)" | egrep 'signer|sig_key|sig_hashalgo'

sign_production: sign

sign_devmachine: sign

install: sign
	@echo "[+] Installing $(MODULE) to /lib/modules/$(shell uname -r)/extra/"
	sudo mkdir -p /lib/modules/$(shell uname -r)/extra/
	sudo cp -v "$(MODULE)" /lib/modules/$(shell uname -r)/extra/
	sudo depmod -a
	sudo modprobe awdog
	@echo "[✓] awdog module installed and loaded"

uninstall:
	@echo "[+] Removing awdog module"
	-sudo modprobe -r awdog
	-sudo rm -vf /lib/modules/$(shell uname -r)/extra/awdog.ko
	sudo depmod -a


# needed to install tmp2-tss-devel on fedora