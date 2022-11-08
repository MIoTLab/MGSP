#!/bin/bash

make -C ../../../src clean
make -C ../../../src

make -C ../../libnvmmio/src clean
make -C ../../libnvmmio/src

filesystem="MGSP ext4 libnvmmio"
operations="write randwrite"
block_size="1k 4k 16k"
file_size="1g"
file_sync="1"
thread_num="1 2 4 8 16"
mixratio="0"
ramptime="10"
runtime="10"

if [ "$#" -gt "0" ]; then filesystem=$1; fi

result="../result/multhread.txt"
#rm $result
#touch $result

run_multhread()
{
	for op in $operations
	do
	    echo $op >> $result
	    for f_s in $file_size
	    do
		for fs in $filesystem
		do
		    echo $fs >> $result
		    for bs in $block_size
		    do
		        echo $bs >> $result
				for tn in $thread_num
				do
				    echo "thread_num = $tn " >> $result
				    for sync in $file_sync
                        do
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
                                ./run.sh $fs_ $op $f_s $bs $fsync $tn 0 $rt $rpt | tee tmp; cat tmp | grep run=1 >> $result; 
                        done
                    done
                done
            done
        done
    done
}

run_multhread

