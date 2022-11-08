#!/bin/bash

make -C ../../../src clean
make -C ../../../src

make -C ../../libnvmmio/src clean
make -C ../../libnvmmio/src

filesystem="MGSP ext4 libnvmmio"
operations="readwrite randrw"
block_size="4k"
file_size="1g"
file_sync="1"
thread_num="1"
mixratio="0 10 20 30 40 50 60 70 80 90 100"
ramptime="10"
runtime="10"

if [ "$#" -gt "0" ]; then filesystem=$1; fi

result="../result/mix-parameter.txt"
#rm $result
#touch $result

run_mix()
{
    for op in $operations
    do
        echo $op >> $result
        for f_s in $file_size
        do
            for sync in $file_sync
            do
                for fs in $filesystem
                do
                    echo $fs >> $result
                    for bs in $block_size
                    do
                        echo $bs >> $result;
                        fsync=$sync
                        fs_=$fs
                        if test $fs = "libnvmmio-wo-fsync"
                        then
                            fs_="libnvmmio"
                            fsync="0"
                        elif test $fs = "ext4-wo-fsync"
                        then 
                            fs_="ext4"
                            fsync="0"
                        fi
                        rpt=$ramptime
                        rt=$runtime
                        if test $fs_ = "ext4"
                        then
                            rpt="50"
                        fi
                        for tn in $thread_num
                        do
                            for mr in $mixratio
                            do
                                echo "write_ratio = $mr " >> $result
                                ./run.sh $fs_ $op $f_s $bs $fsync $tn $mr  $rt $rpt | tee tmp; cat tmp | grep run=1 >> $result; 
                            done
                        done
                    done
                done
            done
        done
    done
}

run_mix

