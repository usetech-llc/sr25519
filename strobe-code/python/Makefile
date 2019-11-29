.PHONY: all test shavs shamont shakat clean
SHELL := /bin/bash
PYTHON ?= python

all:
	@echo "Not making test because that takes for fricken ever"
	@false

 
define def_monte
SHAMONT += test-sha3vs-$(1)-Monte
test-sha3vs-$(1)-Monte: kat/$(1)Monte.rsp Strobe/Test/Sha3vs.py Strobe/Keccak.py
	$(PYTHON) -B -m Strobe.Test.Sha3vs \
    	--test=Monte \
    	--hash=$(1) \
		--seed=$(shell perl -ne 'print $$1 if /(?:Seed|Msg) = ([a-f0-9]+)/i' kat/$(1)Monte.rsp) \
		--min-len=$(shell perl -ne 'print $$1 if /.Minimum Output Length .bits. = ([0-9]+)/i' kat/$(1)Monte.rsp) \
		--max-len=$(shell perl -ne 'print $$1 if /.Maximum Output Length .bits. = ([0-9]+)/i' kat/$(1)Monte.rsp) \
		| diff -u --strip-trailing-cr <(egrep -v '^\#' $$<) -
endef

define def_kat
SHAKAT += test-sha3vs-$(1)-$(2)
test-sha3vs-$(1)-$(2): kat/$(1)$(2).rsp Strobe/Test/Sha3vs.py Strobe/Keccak.py
	$(PYTHON) -B -m Strobe.Test.Sha3vs \
    	--test=Kat \
    	--hash=$(1) \
        --file=$$< \
		| diff -u --strip-trailing-cr <(egrep -v '^\#' $$<) -
endef
define def_common
$(eval $(call def_monte,$(1)))
$(eval $(call def_kat,$(1),ShortMsg))
$(eval $(call def_kat,$(1),LongMsg))
endef
ifneq ("$(wildcard kat)","")
$(eval $(call def_common,SHA3_224))
$(eval $(call def_common,SHA3_256))
$(eval $(call def_common,SHA3_384))
$(eval $(call def_common,SHA3_512))
$(eval $(call def_common,SHAKE128))
$(eval $(call def_common,SHAKE256))
$(eval $(call def_kat,SHAKE128,VariableOut))
$(eval $(call def_kat,SHAKE256,VariableOut))
endif

KAT1 = 'http://csrc.nist.gov/groups/STM/cavp/documents/sha3/sha-3bytetestvectors.zip'
KAT2 = 'http://csrc.nist.gov/groups/STM/cavp/documents/sha3/shakebytetestvectors.zip'
fetchkat:
	mkdir -p kat
	(cd kat && wget $(KAT1) && unzip `basename $(KAT1)`)
	(cd kat && wget $(KAT2) && unzip `basename $(KAT2)`)
    

shamont: $(SHAMONT)
shakat: $(SHAKAT)
shavs: shakat shamont
	@echo "All known-answer tests passed"
	
test: shavs

clean:
	find . -name '*.pyc' -delete
    