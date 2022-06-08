CONFIG_MODULE_SIG=n
CONFIG_ZFILE_CLEANUP_CACHE=y
CONFIG_ZFILE_DECOMPRESS_SHORTCUT=y
CONFIG_ZFILE_READAHEAD=y
CONFIG_ZFILE_INPLACE_DECOMPRESS=n
CONFIG_OVBD_DEBUG=n

MYPROC=vbd
obj-m += vbd.o

ccflags-y := -std=gnu11 -Wno-declaration-after-statement -O3

ccflags-$(CONFIG_OVBD_DEBUG) += -DOVBD_DEBUG
ccflags-$(CONFIG_ZFILE_CLEANUP_CACHE) += -DZFILE_CLEANUP_CACHE
ccflags-$(CONFIG_ZFILE_DECOMPRESS_SHORTCUT) += -DZFILE_DECOMPRESS_SHORTCUT
ccflags-$(CONFIG_ZFILE_READAHEAD) += -DZFILE_READAHEAD
ccflags-$(CONFIG_ZFILE_INPLACE_DECOMPRESS) += -DZFILE_INPLACE_DECOMPRESS

vbd-y := dm-ovbd.o dm-lsmt.o dm-zfile.o lsmt.o zfile.o vfsfile.o blkfile.o


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
