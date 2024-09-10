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
TARGETS +=
# X => X.c only
SOURCES +=
SOURCES += $(EXTRASRC)
# X => X.S only
ASSMBLY +=
ASSMBLY += $(EXTRAASM)
# X => X.c X.h
MODULES += lib kv wh pkeys logger blkio sst xdb bt common msstv msstz fs
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

#### all
# tools without external deps
TGT-all += $(TARGETS)
.PHONY : all
#all : $(addsuffix .out,$(TGT-all))
all : bin bench

FLG-msstio.out += -DRCACHE_TRACE

#### bench
TGT-bench += dbtest ycsbtest
.PHONY : bench
bench : $(addsuffix .out,$(TGT-bench))

# when $ make FORKER_PAPI=y
ifeq ($(FORKER_PAPI),y)
LIB += papi
FLG += -DFORKER_PAPI
else ifeq ($(PAPI),y) # just PAPI
LIB += papi
FLG += -DPAPI
endif
# DB
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
