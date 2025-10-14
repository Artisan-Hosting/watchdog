obj-m := awdog.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
MODULE := $(PWD)/awdog.ko
MOKDIR := $(HOME)/mok
SIGN_PRIV := $(MOKDIR)/MOK.priv
SIGN_DER  := $(MOKDIR)/MOK.der

.PHONY: all clean sign sign_production sign_devmachine install uninstall

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

sign:
	@echo "[+] Signing $(MODULE)"
	sign-file sha256 "$(SIGN_PRIV)" "$(SIGN_DER)" "$(MODULE)"
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