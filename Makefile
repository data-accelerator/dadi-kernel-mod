CONFIG_MODULE_SIG=n

MYPROC=vbd
obj-m += vbd.o

MODE_LOOP=y

ccflags-y := -std=gnu11 -Wno-declaration-after-statement

vbd-$(CONFIG_DADI_LOOP) := overlay_vbd.o lsmt.o zfile.o
vbd-$(CONFIG_DADI_DM) := dm-ovbd.o lsmt.o

export KROOT=/lib/modules/$(shell uname -r)/build

allofit:  ovbd-loop

ovbd-loop: kernel_clean
	@$(MAKE) -C $(KROOT) M=$(PWD) -e CONFIG_DADI_LOOP=y modules

ovbd-dm: kernel_clean
	@$(MAKE) -C $(KROOT) M=$(PWD) -e CONFIG_DADI_DM=y modules

modules: clean
	@$(MAKE) -C $(KROOT) M=$(PWD) modules

kernel_clean:
	@$(MAKE) -C $(KROOT) M=$(PWD) -e CONFIG_DADI_DM=y -e CONFIG_DADI_LOOP=y clean

.PHONY: clean
clean: kernel_clean
	rm -rf Module.symvers modules.order
