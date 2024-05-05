# Disco
## Dependencies

Dependencies for DiscoDB and RemixDB

Supported on Ubuntu Jammy 22.04 (CloudLab default image)

```
apt-get -y install sudo git build-essential cmake clang python3 parallel python-is-python3 python3-pip
```

Dependencies for building RocksDB

```
apt-get -y install libgflags-dev libsnappy-dev zlib1g-dev libbz2-dev liblz4-dev libzstd-dev
```

Dependencies for building bcc

```
apt-get install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev libdebuginfod-dev arping netperf iperf
```

Build bcc from source

```
cd
git clone https://github.com/iovisor/bcc.git
cd bcc
git checkout v0.30.0
git submodule update
mkdir build; cd build
cmake ..
make -j
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make -j
sudo make install
popd
```

Clone the code

```
cd
git clone https://github.com/SheldonZhong/disco.git
```

Build RocksDB and setup the header file

```
cd
git clone https://github.com/facebook/rocksdb.git
cd ~/rocksdb
git checkout v8.10.0
make -j static_lib
cp ./librocksdb.a ~/disco
mkdir -p ~/disco/include/rocksdb
cp ~/rocksdb/include/rocksdb/c.h ~/disco/include/rocksdb
```

There is also a script `./scripts/setup_cloudlab` that does this all,
assuming you have this repo cloned in `~/disco`.

## Run micro-benchmark
We are still working on how to share our dataset files so people can access it anonymously.
For now, it should work with a plain text file with one key each line, if you have your own dataset.
`-n <number of keys>` specifies number of keys that the program considers.
There will eventually be about 75% of the keys actually inserted.
Table files have internal limitations of 256MB in size.
You will have to adjust the number of keys and value lengths accordingly.
```
./scripts/microbench -k <key file>
                     -n <number of keys>
                     -v <value length>
                     -q <number of queries>
                     -r <uniform/zipfian/unizipf>
                     -m <mixed/existing/non-existing>

./scripts/microbench -k <email address key> -n 2393134 -v 120 -r uniform -m mixed -q 100000
```

# Run database experiments

You need root / sudo to make `epbf`, `smartctl`, and some more tools work.

```
cd ~/disco
./scripts/load_exp xdb-dbits 1010580539 16 120 624538773 <mount point>
./scripts/load_exp xdb-full 1010580539 16 120 624538773 <mount point>
./scripts/load_exp rdb-rw 1010580539 16 120 624538773 <mount point>

./scripts/load_exp <db name> 1010580539 16 120 624538773 <mount point>

./scripts/ycsb <db name> 1010580539 16 120 624538773 <mount point>
```

