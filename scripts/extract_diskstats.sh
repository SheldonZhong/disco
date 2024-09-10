#!/usr/bin/env bash

set -e

if [ "$#" -ne 2 ]; then
  echo "<filename> <disk>"
  exit
fi

base=${1%.log}

drive=$(basename $2)

write_end=$(grep -w ${drive} ${base}-end-smart.log | awk '{print $8}')
write_start=$(grep -w ${drive} ${base}-start-smart.log | awk '{print $8}')
read_end=$(grep -w ${drive} ${base}-end-smart.log | awk '{print $4}')
read_start=$(grep -w ${drive} ${base}-start-smart.log | awk '{print $4}')

write_diff=$((${write_end} - ${write_start}))
read_diff=$((${read_end} - ${read_start}))

swrite_end=$(grep -w ${drive} ${base}-end-smart.log | awk '{print $10}')
swrite_start=$(grep -w ${drive} ${base}-start-smart.log | awk '{print $10}')
sread_end=$(grep -w ${drive} ${base}-end-smart.log | awk '{print $6}')
sread_start=$(grep -w ${drive} ${base}-start-smart.log | awk '{print $6}')

swrite_diff=$((${write_end} - ${write_start}))
sread_diff=$((${read_end} - ${read_start}))

echo Write: $write_diff
echo Read: $read_diff

echo Sector write: $swrite_diff
echo Sector read: $sread_diff
