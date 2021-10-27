# dadi-kernel-mod

dadi overlay-bd device driver / device-mapper

Usage,

`make [KDOOT=linux_kernel_dir] [ovbd-loop|ovbd-dm]`

`KROOT` set as kernel module develop kit path, ignored to use host kernel build environment

## ovbd-loop

This is a basic sample for dadi overlay-bd image block-device driver,
currently implemented just like loop-device in kernel, reading image file via vfs to feed bio
read requests.

### Build

`make ovbd-loop`

Or just 

`make`

### Use

The image file should be LSMT-File on ZFile, image path can be configured by parameter.
Currently it supports only one-layer image.

`insmod ./vbd.ko backfile=<image file absolute path>`

if succeed, a read-only device called `/dev/vbd0` should appeared, 

`mount /dev/vdb0 <mount point>`

## ovbd-dm

This is another example, driven in device-mapper framework, take a device which is filled by LSMT-File blobs.

### Build

To build it, using
`make ovbd-dm`

To use it, currently should know the image block-device size. (Which should be read by LSMT-File tailer, but 
the cli tools are not ready by now).

### Use

First of all, install the module

`insmod vbd.ko`

It can be simply get ready by loop device:

`losetup -f --show -r --direct-io <LSMTFile absolute path>`

Say the loop device is `/dev/loop0` for example. Now able to create mapped device using `dmsetup`

`dmsetup create --concise "vbd0,,,ro,0 2290872 lsmt_target 1 /dev/loop0"`

Here the `vbd0` is device name for mapped-device (as `/dev/mapper/vbd0`), set `ro` flag to make sure
device is read-only. 
In table part, the target type is `lsmt_target`, then follows a parameter to referes LSMT layers number
(Currently supports only one layer). then the list of image devices.

After the mapped-device ready, it could able to mount

`mount /dev/mapper/vbd0 <mount point>`
