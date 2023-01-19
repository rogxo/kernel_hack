MODULE_NAME := entry

ifneq ($(KERNELRELEASE),)
	obj-m := $(MODULE_NAME).o
else
	KERN_DIR ?= /usr/src/linux-headers-$(shell uname -r)/
	PWD := $(shell pwd)
endif

default:
	$(MAKE) -C $(KERN_DIR) M=$(PWD) modules
	rm -rf *.o *~ core .depend .*.cmd *.mod.c .tmp_versions *.symvers *.order *.mod
	mkdir build && mv $(MODULE_NAME).ko build/$(MODULE_NAME).ko

clean:
	rm -rf build
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions *.symvers *.order *.mod

