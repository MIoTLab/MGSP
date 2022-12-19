# Multi-Granularity Shadow Paging

**Multi-Granularity Shadow Paging (MGSP)** is a novel crash consistency mechanism for direct access memory-mapped I/O (DAX-MMIO) on Non-Volatile Memory (NVM). MGSP introduces the concept of **shadow log**, combining the advantages of shadow paging and logging. The shadow log avoids the double-write problem by switching the roles of data blocks between redo and undo logs when needed. In addition, a multi-granularity strategy is designed to provide high-performance updating and locking for reducing runtime overhead, where strong consistency is preserved with a lock-free metadata log. 

MGSP is implemented based on [Libnvmmio](https://www.usenix.org/conference/atc20/presentation/choi). This artifact provides the source code of MGSP, the baseline [Libnvmmio](https://www.usenix.org/conference/atc20/presentation/choi), and the benchmark [FIO](https://github.com/axboe/fio), along the scripts to compile the code and set up the underlying file system. We also provide the scripts to run the evaluation.

## Artifact Structure
```
MGSP
├──evaluation
│   ├── fio
│   │   ├── result
│   |   ├── script
│   │   ├── src
│   |   └── README.md
│   ├── libnvmmio
│   │   └── src
│   ├── ext4_config.sh
│   └── nova_config.sh
├── src
├── LICENSE
└── README.md
```
## Prerequisites
### Hardware
* Inter Optane DC Persistent Memory (PM) and Intel Xeon CPU  
Our testbed is equipped with 4 Inter DCPMM 200 Series (512GB) and 2 Intel Xeon Gold 5317 (2.6GHz, 24 cores). If the PM device is not available, you can use the DRAM emulated PM device. Please refer to the [here](https://www.intel.com/content/www/us/en/developer/articles/training/how-to-emulate-persistent-memory-on-an-intel-architecture-server.html) for more details. 32GB DRAM emulated PM is enough for MGSP. But the Libnvmmio may need more for the mul-threads workloads. You can change the workload size or the [configuration](evaluation/libnvmmio/src/config.h) of Libnvmmio if needed. 
### Software
* PMDK. We use [PMDK](https://pmem.io/pmdk/) to access the PM device. To install PMDK on Ubuntu, you can run the following command.
```bash
$ sudo apt install libpmem-dev
```
* Other dependencies. We use make and gcc to compile the source code. The numactl is used to bind the process to the specific CPU core.
```bash
$ sudo apt install gcc make numactl
```
The OS of our testbed is Ubuntu 18.04 with kernel 5.1.0. We choose this setting for comparsion with NOVA. 
## Compile and setup
### Compile the benchmark and source code
```bash
$ cd evaluation/fio/src
$ ./configure && make
$ cd ../../libnvmmio/src && make
$ cd ../../../src && make
```
### Set up the file system
```bash
$ cd evaluation
$ sudo ./ext4_config.sh
or 
$ sudo ./nova_config.sh
```  

Before set up the file system, please make sure that the ```/dev/pmem0``` device exists. It can be the real PM device or DRAM emulated PM device. The default monut point is ```/mnt/pmem```. If you want to change it, please modify the ```PMEM_PATH``` variable in the ```ext4_config.sh``` or ```nova_config.sh``` script and ```evaluation/script/run.sh```.  
Before setting up the NOVA, you need to install the NOVA kernel. Please refer to [NOVA](https://www.github.com/NVSL/linux-nova) for more details.

## Run the evaluation
```bash
$ cd evaluation/fio/script
$ sudo ./run_all.sh
```

These scripts will run the evaluation for MGSP, Ext4-DAX and Libnvmmio. The results will be stored in ```evaluation/fio/result```. For NOVA, you can run the same scripts with ```NOVA``` attached to the script name after setting up the kernel. For example, ```sudo ./run_all.sh NOVA```. Example results are provided in ```evaluation/fio/result/example_result```. See more details about the evaluation and experiment customization in ```evaluation/fio/README.md```.

## Contact
If you have any questions, please contact us at ```hc.du@my.cityu.edu.hk```.

## License
This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
* [Libnvmmio](https://www.usenix.org/conference/atc20/presentation/choi)
* [FIO](https://github.com/axboe/fio)
* [NOVA](https://www.github.com/NVSL/linux-nova)
* [PMDK](https://pmem.io/pmdk/)
