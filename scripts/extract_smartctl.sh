#!/usr/bin/env bash

set -e

if [ "$#" -ne 1 ]; then
  echo "Needs a file name of the main log file"
  exit
fi

base=${1%.log}

write_end=$(grep "Logical Sectors Written" ${base}-end-smart.log | awk '{print $4}')
write_start=$(grep "Logical Sectors Written" ${base}-start-smart.log | awk '{print $4}')
read_end=$(grep "Logical Sectors Read" ${base}-end-smart.log | awk '{print $4}')
read_start=$(grep "Logical Sectors Read" ${base}-start-smart.log | awk '{print $4}')

if [ -z "$write_end" ]; then
  write_end=$(grep "Blocks received from initiator" ${base}-end-smart.log | awk '{print $6}')
fi

if [ -z "$write_end" ]; then
  write_end=$(grep "Host Write Commands" ${base}-end-smart.log | awk '{print $4}' | tr -d ",")
fi

if [ -z "$write_start" ]; then
  write_start=$(grep "Blocks received from initiator" ${base}-start-smart.log | awk '{print $6}')
fi

if [ -z "$write_start" ]; then
  write_start=$(grep "Host Write Commands" ${base}-start-smart.log | awk '{print $4}' | tr -d ",")
fi

if [ -z "$read_end" ]; then
  read_end=$(grep "Blocks sent to initiator" ${base}-end-smart.log | awk '{print $6}')
fi

if [ -z "$read_end" ]; then
  read_end=$(grep "Host Read Commands" ${base}-end-smart.log | awk '{print $4}' | tr -d ",")
fi

if [ -z "$read_start" ]; then
  read_start=$(grep "Blocks sent to initiator" ${base}-start-smart.log | awk '{print $6}')
fi

if [ -z "$read_start" ]; then
  read_start=$(grep "Host Read Commands" ${base}-start-smart.log | awk '{print $4}' | tr -d ",")
fi

write_diff=$((${write_end} - ${write_start}))
read_diff=$((${read_end} - ${read_start}))

tot_write=$(python -c "print(($write_diff if $write_diff >= 0 else $write_diff + 2 ** 32))")
tot_read=$(python -c "print(($read_diff if $read_diff >= 0 else $read_diff + 2 ** 32))")

tot_write_bytes=$(python -c "print($tot_write * 512)")
tot_read_bytes=$(python -c "print($tot_read * 512)")

echo Write I/O: $tot_write
echo Read I/O: $tot_read

echo Write bytes: $tot_write_bytes
echo Read bytes: $tot_read_bytes
