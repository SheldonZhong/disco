#!/usr/bin/env bash

caps="8         9    10    11    12     13     14     15
      16       18    20    22    24     26     28     30
      32       36    40    44    48     52     56     60
      64       72    80    88    96    104    112    120
      128     144   160   176   192    208    224    240
      256     288   320   352   384    416    448    480
      512     576   640   704   768    832    896    960
      1024   1152  1280  1408  1536   1664   1792   1920
      2048   2304  2560  2816  3072   3328   3584   3840
      4096   4608  5120  5632  6144   6656   7168   7680
      8192   9216 10240 11264 12288  13312  14336  15360
      16384 18432 20480 22528 24576  26624  28672  30720
      32768 36864 40960 45056 49152  53248  57344  61440
      65536 73728 81920 90112 98304 106496 114688 122880"

basedir=$(dirname "$0")

LRU_SIM="${basedir}/../lru/lru.out"

if ! [ -f "$LRU_SIM"  ]; then
  echo "$LRU_SIM does not exist."
  pushd $PWD
  cd "${basedir}/../lru"
  make
  popd
fi

if [ $# -lt 1 ]; then
  echo "usage $0 <trace folder>"
  exit 1
fi

csv_fn=$1.csv

if [ -f "$csv_fn" ]; then
  echo $csv_fn already exists. I do not want to append it
  exit 1
fi

if [ -x "$(command -v parallel)" ]; then
  parallel $LRU_SIM -c {1} -f {2} -v ::: $caps ::: $1/*.trace | tee -a $csv_fn
else
  echo Wawrning: parallel is not installed. It will take a long time to run
  for cap in $caps; do
    for trace in $1/*.trace; do
      echo "$LRU_SIM -c $cap -f $trace -v"
      $LRU_SIM -c $cap -f $trace -v | tee -a $csv_fn
    done
  done
fi


