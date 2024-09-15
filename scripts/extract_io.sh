#!/usr/bin/env bash

set -e

if [ "$#" -ne 2 ]; then
  echo "${0} <filename> <disk>"
  exit
fi

base=${1%.log}

bio_write_io=$(grep "Write I/O" ${base}-bio.log | awk '{print $3}')
bio_read_io=$(grep "Read I/O" ${base}-bio.log | awk '{print $3}')
bio_write_bytes=$(grep "Write bytes" ${base}-bio.log | awk '{print $3}')
bio_read_bytes=$(grep "Read bytes" ${base}-bio.log | awk '{print $3}')

diskstats=$($(dirname "$0")/extract_diskstats.sh ${base}.log $2)

stats_write_io=$(echo "$diskstats" | grep "Write:" | awk '{print $2}')
stats_read_io=$(echo "$diskstats" | grep "Read:" | awk '{print $2}')
stats_write_sectors=$(echo "$diskstats" | grep "Sector write:" | awk '{print $3}')
stats_read_sectors=$(echo "$diskstats" | grep "Sector read:" | awk '{print $3}')

smartctl=$($(dirname "$0")/extract_smartctl.sh ${base})

sctl_write_io=$(echo "$smartctl" | grep "Write I/O:" | awk '{print $3}')
sctl_read_io=$(echo "$smartctl" | grep "Read I/O:" | awk '{print $3}')
sctl_write_bytes=$(echo "$smartctl" | grep "Write bytes:" | awk '{print $3}')
sctl_read_bytes=$(echo "$smartctl" | grep "Read bytes:" | awk '{print $3}')

 echo -n $bio_write_io,$bio_read_io,$bio_write_bytes,$bio_read_bytes,
 echo -n $stats_write_io,$stats_read_io,$stats_write_sectors,$stats_read_sectors,
 echo    $sctl_write_io,$sctl_read_io,$sctl_write_bytes,$sctl_read_bytes
