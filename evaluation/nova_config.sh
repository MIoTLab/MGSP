#!/bin/bash

PMEM_PATH="/mnt/pmem"

sudo mkdir $PMEM_PATH
sudo rm -rf $PMEM_PATH/*
sudo rm -rf $PMEM_PATH/.*
sudo umount $PMEM_PATH
sudo mount -t NOVA -o init /dev/pmem0 $PMEM_PATH
sudo chown -R $USER:$USER $PMEM_PATH

