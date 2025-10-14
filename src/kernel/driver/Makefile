obj-m := awdog.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
MODULE := ./awdog.ko

# default 
.PHONY: all sign_production

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

sign_production: 
	SIGN=$(echo /usr/src/linux-headers-$(uname -r)/scripts/sign-file)
	$SIGN sha256 ~/mok/MOK.priv ~/mok/MOK.der $MODULE
	modinfo $MODULE | egrep 'signer|sig_key|sig_hashalgo'

sign_devmachine: 
	SIGN=$(echo /usr/lib/modules/$(uname -r)/build/scripts/sign-file)
	"$SIGN" sha256 ~/mok/MOK.priv ~/mok/MOK.der "$MODULE"
	modinfo "$MODULE" | egrep 'signer|sig_key|sig_hashalgo'

install:
	cp -v $MODULE /lib/modules/$(uname -r)/extra/
	depmod -a 
	modprobe awdog

# needed to install tmp2-tss-devel on fedora