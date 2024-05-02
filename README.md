# Dependencies

Dependencies for DiscoDB and RemixDB

Ubuntu 22.04

```
apt-get -y install git build-essential cmake clang python3-dev
```

Dependencies for building RocksDB

```
apt-get -y install libgflags-dev libsnappy-dev zlib1g-dev libbz2-dev liblz4-dev libzstd-dev
```

Clone the code

```
git clone https://github.com/SheldonZhong/disco.git
```

## Build RocksDB static library

```
cd ~
git clone https://github.com/facebook/rocksdb.git
cd ~/rocksdb
git checkout v8.10.0
make -j static_lib
cp ./librocksdb.a ~/disco
mkdir -p ~/disco/include/rocksdb
cp ~/rocksdb/include/rocksdb/c.h ~/disco/include/rocksdb
cd ~/disco
```

# Run micro-benchmark
```
make RCACHE_TRACE=y msstio.out && ./msstio.out -k <keyfile path> -120788344.mmapkv -v 120 -r unizipf -m existing -q 100000 -n 2393134
# simulate cache replacement
sim.sh
sim_csv.sh
save_trace.sh <folder>
```

# Run database experiments

```
./script/load_exp xdb-dbits 1010580539 16 120 624538773 <mount point>
./script/load_exp xdb-full 1010580539 16 120 624538773 <mount point>
./script/load_exp rdb-rw 1010580539 16 120 624538773 <mount point>

./script/load_exp <db name> 1010580539 16 120 624538773 <mount point>

./script/ycsb <db name> 1010580539 16 120 624538773 <mount point>
```

