# Makefile
# rules (always with .out)
# SRC-X.out += abc        # extra source: abc.c
# MOD-X.out += abc        # extra module: abc.c abc.h
# ASM-X.out += abc        # extra assembly: abc.S
# DEP-X.out += abc        # extra dependency: abc
# FLG-X.out += -finline   # extra flags
# LIB-X.out += abc        # extra -labc options

# X.out : xyz.h xyz.c # for extra dependences that are to be compiled/linked.

# X => X.out
TARGETS += libtest
# X => X.c only
SOURCES +=
SOURCES += $(EXTRASRC)
# X => X.S only
ASSMBLY +=
ASSMBLY += $(EXTRAASM)
# X => X.c X.h
MODULES += lib kv wh pkeys logger
MODULES += $(EXTRAMOD)
# X => X.h
HEADERS += ctypes
HEADERS += $(EXTRAHDR)

# EXTERNSRC/EXTERNDEP do not belong to this repo.
# extern-src will be linked
EXTERNSRC +=
# extern-dep will not be linked
EXTERNDEP +=

FLG +=
LIB += m

MOD-libtest.out += ord

#### all
# tools without external deps
TGT-all += $(TARGETS)
.PHONY : all
#all : $(addsuffix .out,$(TGT-all))
all : bin wh xdb bench


#### wh
TGT-wh += whdemo whdbg
.PHONY : wh
wh : $(addsuffix .out,$(TGT-wh))

FLG-msstio.out += -DRCACHE_TRACE

#### xdb
TGT-xdb += mssttest msstztest sstdump mbtytest
.PHONY : xdb
xdb : $(addsuffix .out,$(TGT-xdb))

MOD-REMIX = blkio sst xdb bt common msstv msstz fs
MOD-mssttest.out += $(MOD-REMIX)
MOD-mbtytest.out += $(MOD-REMIX)
MOD-rebuild_test.out += $(MOD-REMIX)
MOD-partial_test.out += $(MOD-REMIX)
MOD-msstio.out += $(MOD-REMIX)

#### bench
TGT-bench += dbtest1 ycsbtest
.PHONY : bench
bench : $(addsuffix .out,$(TGT-bench))

#### more
# collections

.PHONY : more
more : $(addsuffix .out,$(TGT-more))

# when $ make FORKER_PAPI=y
ifeq ($(FORKER_PAPI),y)
LIB += papi
FLG += -DFORKER_PAPI
else ifeq ($(PAPI),y) # just PAPI
LIB += papi
FLG += -DPAPI
endif
# DB
ifeq ($(REMIXDB),y)
MODULES += $(MOD-REMIX)
endif
ifeq ($(RCACHE_TRACE),y)
FLG += -DRCACHE_TRACE
endif
ifeq ($(LEVELDB),y)
MODULES += ord
FLG += -DLEVELDB
LIB += leveldb
endif
ifeq ($(ROCKSDB),y)
MODULES += ord
FLG += -DROCKSDB -L.
LIB += rocksdb stdc++ snappy zstd z lz4 bz2
endif

# append common rules (have to do it here)
include Makefile.common
