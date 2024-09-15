#!/usr/bin/env bash

set -e

if [ "$#" -ne 3 ]; then
  echo "${0} <mem> <filename> <disk>"
  exit
fi

base=${2%.log}

mem=${1}

if grep -q "rdb" ${base}-err.log; then
  rgen_col=7
else
  rgen_col=6
fi

data_line=$(grep "total" ${base}-err.log)

rgen_arg_col=$(($rgen_col + 1))

rgen=$(echo ${data_line} | awk -v rgen_arg_col="$rgen_arg_col" '{print $rgen_arg_col}')

case $rgen in
  shuffle|uniform)
    pass_col=$(($rgen_col + 4))
    ;;
  unizipf)
    pass_col=$(($rgen_col + 5))
    ;;
  *)
    echo "rgen ${rgen} num args not defined"
    exit 0
    ;;
esac

thread_col=$(($pass_col + 1))
klen_col=$(($pass_col + 8))
vlen_col=$(($pass_col + 9))
num_ops_col=$(($pass_col + 11))


klen=$(echo ${data_line} | awk -v klen_col="$klen_col" '{print $klen_col}')
vlen=$(echo ${data_line} | awk -v vlen_col="$vlen_col" '{print $vlen_col}')
thread=$(echo ${data_line} | awk -v thread_col="$thread_col" '{print $thread_col}')
num_ops=$(echo ${data_line} | awk -v num_ops_col="$num_ops_col" '{print $num_ops_col}')
nsec=$(echo ${data_line} | awk '{print $2}')
sysname=$(echo ${data_line} | awk '{print $4}')

nkv_col=$(($rgen_col + 3))

nkv=$(echo ${data_line} | awk -v nkv_col="$nkv_col" '{print $nkv_col}')

ops=$(echo "scale=5; $num_ops / $nsec" | bc)

io_results=$($(dirname "$0")/extract_io.sh $2 $3)

echo -n $sysname,$mem,$klen,$vlen,$thread,$nkv,$rgen,$nsec,$num_ops,$ops,
echo "$io_results"

