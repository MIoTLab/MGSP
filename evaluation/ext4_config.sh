#!/bin/bash

PMEM_PATH="/mnt/pmem"

sudo mkdir $PMEM_PATH
sudo rm -rf $PMEM_PATH/*
sudo rm -rf $PMEM_PATH/.*
sudo umount $PMEM_PATH
sudo mkfs.ext4 -F -b 4096 /dev/pmem0
sudo mount -o dax /dev/pmem0 $PMEM_PATH
sudo chown -R $USER:$USER $PMEM_PATH

