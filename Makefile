CONFIG_MODULE_SIG=n

MYPROC=vbd
obj-m += vbd.o

ccflags-y := -std=gnu11 -Wno-declaration-after-statement -O3

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
