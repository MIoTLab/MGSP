# Multi-Granularity Shadow Paging

## Environment
To install PMDK on Ubuntu 18.04 or later
```bash
$ sudo apt install libpmem-dev
```
Install other dependencies
```bash
$ sudo apt install gcc make numactl
```
## Compile the FIO
```bash
$ cd evaluation/fio/src
$ ./configure
$ make
```
## Set up the file system
```bash
$ cd evaluation
$ sudo ./ext4_config.sh
or 
$ sudo ./nova_config.sh
```  

Before running these scripts, please make sure that the ```/dev/pmem0``` device exists. It can be the real PM device or DRAM emulated PM device. For the latter, you can refer to the [SplitFS](https://www.github.com/chjs/splitfs). 32GB DRAM is enough for the MGSP, but the Libnvmmio may need more for the mul-threads workloads.
The default monut point is ```/mnt/pmem```. If you want to change it, please modify the ```PMEM_PATH``` variable in the ```ext4_config.sh``` or ```nova_config.sh``` script and ```evaluation/script/run.sh```.  
Before setting up the NOVA, you need to install the NOVA kernel. Please refer to [NOVA](https://www.github.com/NVSL/linux-nova) for more details.

## Run the evaluation
```bash
$ cd evaluation/fio/script
$ sudo ./run_all.sh
```

These scripts will run the evaluation for MGSP, Ext4-DAX and Libnvmmio. The results will be stored in ```evaluation/fio/result```. For NOVA, you can run the same scripts with ```NOVA``` attached to the script name after setting up the kernel. For example, ```sudo ./run_all.sh NOVA```.