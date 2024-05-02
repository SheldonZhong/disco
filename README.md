```
# run micro-benchmark
$ make RCACHE_TRACE=y msstio.out && ./msstio.out -k /share/keys/emails-120788344.mmapkv -v 120 -r unizipf -m existing -q 100000 -n 2393134
# simulate cache replacement
$ sim.sh
$ sim_csv.sh
$ save_trace.sh <folder>
```

