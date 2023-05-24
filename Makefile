CONFIG_ZFILE_CLEANUP_CACHE=y
CONFIG_ZFILE_READAHEAD=y
CONFIG_ZFILE_HEAD_OVERWRITE=n

MYPROC=vbd
obj-m += vbd.o

ccflags-y := -std=gnu11 -Wno-declaration-after-statement -O2

ccflags-$(CONFIG_ZFILE_CLEANUP_CACHE) += -DZFILE_CLEANUP_CACHE
ccflags-$(CONFIG_ZFILE_READAHEAD) += -DZFILE_READAHEAD
ccflags-$(CONFIG_ZFILE_HEAD_OVERWRITE) += -DZFILE_HEAD_OVERWRITE

vbd-y := dm-ovbd.o dm-lsmt.o dm-zfile.o dm-lsmtformat.o dm-zfileformat.o dm-ovbd-blkfile.o


export KROOT=/lib/modules/$(shell uname -r)/build

allofit:  ovbd-dm

ovbd-dm: clean
	@$(MAKE) -C $(KROOT) M=$(PWD) modules

modules: 
	@$(MAKE) -C $(KROOT) M=$(PWD) modules

kernel_clean:
	@$(MAKE) -C $(KROOT) M=$(PWD) clean

.PHONY: clean
clean: kernel_clean
	rm -rf Module.symvers modules.order
