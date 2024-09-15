#!/usr/bin/env bash

set -e

if [ "$#" -ne 2 ]; then
  echo "${0} <mem> <filename>"
  exit
fi

base=${2%.log}

mem=${1}

if grep -q "rdb" ${base}-out.log; then
  rgen_col=7
else
  rgen_col=6
fi

rgen_arg_col=$(($rgen_col + 1))

file_basename=$(basename ${base})

workload=${file_basename:0:6}

# unizipf: A, B, C, E, F
# latest: D

if grep -q "latest" ${base}-out.log; then
  pass_col=$(($rgen_col+3))
else
  pass_col=$(($rgen_col+5))
fi

# data_line=$(tail -n 2 ${base}-out.log | head -n 1)
data_line=$(tail -n 1 ${base}-out.log | head -n 1)

klen_col=$(($pass_col + 11))
klen=$(echo ${data_line} | awk -v klen_col="$klen_col" '{print $klen_col}')
vlen_col=$(($pass_col + 12))
vlen=$(echo ${data_line}| awk -v vlen_col="$vlen_col" '{print $vlen_col}')

nset_col=$(($pass_col + 15))
nset=$(echo ${data_line} | awk -v nset_col="$nset_col" '{print $nset_col}')

nupd_col=$(($pass_col + 18))
nupd=$(echo ${data_line} | awk -v nupd_col="$nupd_col" '{print $nupd_col}')

nget_col=$(($pass_col + 21))
nget=$(echo ${data_line} | awk -v nget_col="$nget_col" '{print $nget_col}')

nscan_col=$(($pass_col + 24))
nscan=$(echo ${data_line} | awk -v nscan_col="$nscan_col" '{print $nscan_col}')

nops=$(($nset + $nupd + $nget + $nscan))

rgen=$(echo ${data_line} | awk -v rgen_col="$rgen_arg_col" '{print $rgen_col}')
nsec=$(echo ${data_line} | awk '{print $2}')
sysname=$(echo ${data_line} | awk '{print $4}')

ops=$(echo "scale=5; $nops / $nsec" | bc)

# echo sysname,workload,mem,klen,vlen,rgen,nsec,nops,ops,nset,nupd,nget,nscan,write_io,read_io
echo $sysname,$workload,$mem,$klen,$vlen,$rgen,$nsec,$nops,$ops,$nset,$nupd,$nget,$nscan

# for col in sysname workload mem klen vlen rgen nsec nops ops nset nupd nget nscan write_io read_io; do
#   echo $col: ${!col}
# done
