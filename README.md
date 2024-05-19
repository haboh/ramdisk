# Ramdisk

Ramdisk is a block device that stores data in RAM.

## Build

```
make
```

## Installation

```
sudo insmod ram-disk.ko
```

## Removal

```
sudo rmmod ram-disk
```

## Usage example

```
sudo mkfs.ext4 /dev/myblockdevice

sudo mkdir /mnt/ramdisk

sudo mount /dev/myblockdevice /mnt/ramdisk

cd /mnt/ramdisk

touch testfile.txt

echo "Hello, RAM-disk!" > testfile.txt

cat testfile.txt

sudo umount /mnt/ramdisk
```
