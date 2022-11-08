#!/bin/bash

if [ "$#" -gt "0" ]; then fs=$1; fi

./micro.sh $fs
./mix.sh $fs
./mul-thread.sh $fs
