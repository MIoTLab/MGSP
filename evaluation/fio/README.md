# FIO
[FIO](https://github.com/axboe/fio) is a popular benchmark for measuring file I/O performance.
You can measure the performance of Libnvmmio using FIO.

## Install FIO

```bash
$ cd src
$ ./configure && make -j 16
```

## Run FIO using MGSP
```bash
$ cd scripts
$ ./run.sh MGSP 
```
This run.sh script runs FIO using ```LD_PRELOAD``` to intercept the calls during runtime.