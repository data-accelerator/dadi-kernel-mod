CONFIG_MODULE_SIG=n

MYPROC=vbd
obj-m += vbd.o

ccflags-y := -std=gnu11 -Wno-declaration-after-statement

vbd-$(CONFIG_DADI_LOOP) := overlay_vbd.o lsmt.o zfile.o vfsfile.o blkfile.o
vbd-$(CONFIG_DADI_DM) := dm-ovbd.o dm-lsmt.o dm-zfile.o lsmt.o zfile.o vfsfile.o blkfile.o
vbd-$(CONFIG_DEBUG_MOD) := lsmt.o zfile.o vfsfile.o blkfile.o debug.o

%.o: %.mod

export KROOT=/lib/modules/$(shell uname -r)/build

allofit:  ovbd-dm

debug: 
	@$(MAKE) -C $(KROOT) M=$(PWD) -e CONFIG_DEBUG_MOD=y modules

ovbd-loop: clean
	@$(MAKE) -C $(KROOT) M=$(PWD) -e CONFIG_DADI_LOOP=y modules

ovbd-dm: clean
	@$(MAKE) -C $(KROOT) M=$(PWD) -e CONFIG_DADI_DM=y modules

modules: 
	@$(MAKE) -C $(KROOT) M=$(PWD) modules

kernel_clean:
	@$(MAKE) -C $(KROOT) M=$(PWD) -e CONFIG_DADI_DM=y -e CONFIG_DADI_LOOP=y clean

.PHONY: clean
clean: kernel_clean
	rm -rf Module.symvers modules.order
