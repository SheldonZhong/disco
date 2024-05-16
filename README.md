# Disco
## Dependencies

Dependencies for DiscoDB and RemixDB

Supported on Ubuntu Jammy 22.04 (CloudLab default image)

```
apt-get -y install sudo git build-essential cmake clang python3 parallel python-is-python3 \
  python3-pip libcairo2-dev pkg-config python3-dev smartmontools
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

Install python package dependencies for plotting graphs
```
cd ~/disco
pip install -r ./requirements.txt
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

After that it should generate a folder `trace-<timestamp>` and a matching CSV file `trace-<timestamp>.csv`,
where `<timestamp>` has a format that looks like `trace-2024-05-05-18-32-17`.

You can generate the plots in the paper by
```
./scripts/plot_microbench.py trace-<timestamp>
```
This will generate `intro-exp.pdf`, `eval_seek_8.pdf`, and `eval_probe_8_mixed.pdf`
Do remember to install the python package dependencies for plotting.

## Run database experiments

You need root / sudo to make `epbf`, `smartctl`, and some more tools work.

All these experiments have a similar file output.
The output will have the format of `<prefix>-<suffix>.log`, where `<prefix>` has the format
```
<workload>-<timestamp>-<commit_hash>-<db_name>-<number_of_keys>-<key_length>-<value_length>
```
In this loading experiment, the `<workload>` is `load`.
The `<suffix>` could be
```
- start-smart: the smartctl output before the experiment
- end-smart: the smartctl output after the experiment
- out: the stdout during the experiment
- err: the stderr during the experiment
- bio: the I/O traces using from biosnoop
- <empty>: the log of the database
```
We will use some scripts to parse, extract, and plot the output.

### Loading experiments

`./scripts/load_exp` loads a database.
It will write the specified number of keys in shuffled order.
It loads the DB in 200 rounds, outputing one line of stat each round to both `stderr` and `stdout`.

To run a loading experiment
```
`./scripts/load_exp <db_name> <number_of_keys> <key_length> <value_length> <mount_point>`

# DiscoDB
./scripts/load_exp xdb-dbits 1010580539 16 120 <mount_point>
# RemixDB
./scripts/load_exp xdb-full 1010580539 16 120 <mount_point>
# RocksDB
./scripts/load_exp rdb-rw 1010580539 16 120 <mount_point>
```

### Read experiments

`./scripts/read_bench` runs the read experiments.
It will first warm up the page cache then perform the read experiments.
There are four sets of experiments: uniform range query (seek), uniform point queries (probe),
skewed range query, and skewed point query.

```
# DiscoDB
./scripts/read_bench xdb-dbits 1010580539 16 120 <mount_point>
# RemixDB
./scripts/read_bench xdb-full 1010580539 16 120 <mount_point>
# RocksDB
./scripts/read_bench rdb-ro  1010580539 16 120 <mount_point>
```

Note here that we open RocksDB in read-only mode to make sure all systems are evaluated equally.

### YCSB

`./scripts/ycsb` runs the YCSB experiments.
It will first warmup the page cache then run the YCSB workloads from A to F.

```
# DiscoDB
./scripts/ycsb xdb-dbits 1010580539 16 120 <mount_point>
# RemixDB
./scripts/ycsb xdb-full 1010580539 16 120 <mount_point>
# RocksDB
./scripts/ycsb rdb-rw  1010580539 16 120 <mount_point>
```

### Run experiments with different memory budgets

`./scripts/run_cgroups` could be used to run experiments under different memory budgets.
It will run whatever is given to the argument with 16G, 32G, and 64G memory budgets.
It then moves all `*.log` files into a directory.

For example
```
./scripts/run_cgroups ./scripts/read_bench xdb-dbits 1010580539 16 120 <mount_point>
./scripts/run_cgroups ./scripts/read_bench rdb-ro 1010580539 16 120 <mount_point>
```

*Note*: since the loading experiments and YCSB write to the database.
The results might be inconsistent if the script is used directly to run those experiments.

