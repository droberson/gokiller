
# The current directory and kernel root are passed to sub-makes as argument
KROOT ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# CC := gcc-8
obj-m += gokiller.o

allofit: modules

modules:
	@$(MAKE) -C $(KROOT) M=$(PWD) CC=$(CC) modules

modules_install:
	@$(MAKE) -C $(KROOT) M=$(PWD) modules_install

kernel_clean:
	@$(MAKE) -C $(KROOT) M=$(PWD) clean

clean: kernel_clean
	rm -rf Module.symvers modules.order gokiller.o.ur-safe


.PHONY: modules modules_install clean
