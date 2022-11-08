#!/bin/bash

# sudo ./run.sh ext4 write 1g 4k 1 1 0 10 50

PMEM_PATH="/mnt/pmem"

rm -rf $PMEM_PATH/*
rm -rf $PMEM_PATH/.lib*
sync && echo 3 > /proc/sys/vm/drop_caches

fs="ext4"
op="write"
filesize="1g"
bs="4k"
fsync="1"
thread="1"
mixratio="0"
runtime="10"
ramptime="50"

if [ "$#" -gt "0" ]; then fs=$1; fi
if [ "$#" -gt "1" ]; then op=$2; fi
if [ "$#" -gt "2" ]; then filesize=$3; fi
if [ "$#" -gt "3" ]; then bs=$4; fi
if [ "$#" -gt "4" ]; then fsync=$5; fi
if [ "$#" -gt "5" ]; then thread=$6; fi
if [ "$#" -gt "6" ]; then mixratio=$7; fi
if [ "$#" -gt "7" ]; then runtime=$8; fi
if [ "$#" -gt "8" ]; then ramptime=$9; fi

echo run $fs $op $filesize $bs $fsync $thread $mixratio $runtime $ramptime

if test $fs = "MGSP"
then 
LD_PRELOAD=../../../src/mgsp.so \
PMEM_PATH=$PMEM_PATH \
numactl --cpunodebind=0 --membind=0 \
../src/fio \
--sync=0 \
--name=test \
--ioengine=sync \
--rw=$op \
--directory=$PMEM_PATH \
--filesize=$filesize \
--bs=$bs \
--rwmixwrite=$mixratio \
--fsync $fsync \
--thread --numjobs=$thread \
--filename text.txt \
--ramp_time=$ramptime \
--runtime=$runtime --time_based
elif test $fs = "libnvmmio"
then 
LD_PRELOAD=../../libnvmmio/src/libnvmmio.so \
PMEM_PATH=$PMEM_PATH \
numactl --cpunodebind=0 --membind=0 \
../src/fio \
--sync=0 \
--name=test \
--ioengine=sync \
--rw=$op \
--directory=$PMEM_PATH \
--filesize=$filesize \
--bs=$bs \
--rwmixwrite=$mixratio \
--fsync $fsync \
--thread --numjobs=$thread \
--filename test.txt \
--ramp_time=$ramptime \
--runtime=$runtime --time_based
else
numactl --cpunodebind=0 --membind=0 \
../src/fio \
--sync=0 \
--name=test \
--ioengine=sync \
--rw=$op \
--directory=$PMEM_PATH \
--filesize=$filesize \
--bs=$bs \
--rwmixwrite=$mixratio \
--fsync $fsync \
--thread --numjobs=$thread \
--filename test.txt \
--ramp_time=$ramptime \
--runtime=$runtime --time_based
fi