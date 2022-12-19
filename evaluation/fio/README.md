# FIO
[FIO](https://github.com/axboe/fio) is a popular benchmark for measuring file I/O performance.

## Install FIO

```bash
$ cd src
$ ./configure && make
```

## Run evaluation with FIO
```bash
$ cd scripts
$ sudo ./run_all.sh
```
This script runs the following three scripts. You can also run them individually.
* ```micro.sh```: This script runs the basic read/write experiment. It will take about 90 minutes.
* ```mix.sh```: This script runs the mixed read-write workload. It will take about 20 minutes.
* ```mul-thread.sh```: This script runs the multi-thread experiment. It will take about 60 minutes.

The results of MGSP, Libnvmmio and Ext4-DAX or NOVA will be stored in ```result```, depending on the file system you set up.

You can also specify the file system by passing the file system name as the first argument. For example, ```sudo ./run_all.sh MGSP```. To run the evaluation with NOVA, you need to set up the NOVA kernel first.

## Experiment customization

All the above scripts are customizable. You can change the number of threads, the file size, the I/O size, etc. We also provide a ```run.sh``` script to run the evaluation with customized parameters. All other scripts call this script. For example, to run the MGSP with 1GB file and 4KB write, you can run the following command.

```bash
$ cd scripts
$ sudo ./run.sh MGSP write 1G 4K
```
The meaning of all the arguments are as follows.
```bash
$ sudo ./run.sh [file system] [operation] [file size] [block size] [fsync interval] [num of threads] [ratio of write] [run time] [ramp time]
    file system: MGSP, libnvmmio, [ext4], NOVA
    operation: read, [write], randread, randwrite, readwrite, randrw
    file size: 512M, [1G], 10G, ...
    block size: 256, 1K, [4K], 16K, ...
    fsync interval: 0, [1], 10, 100, ...
    num of threads: [1], 2, 4, 8, ...
    ratio of write: [0], 10, 50, ..., 100
    run time: [10], 30, 50, ... (seconds)
    ramp time: 10, 30, [50], ... (seconds)
```
The default values are in square brackets. This script runs FIO using ```LD_PRELOAD``` to intercept the calls during runtime, and only the fils opened with ```O_ATOMIC (01000000000)``` will be intercepted. This FIO benchmark has been modified with this flag. Other applications can also use this flag to use MGSP, and run like this:
```bash
$ sudo LD_PRELOAD=MGSP/src/mgsp.so ./your_app
```