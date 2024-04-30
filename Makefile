.PHONY: help clean all test

VERSIONS := 2.23 2.24 2.27 2.31 2.32 2.33 2.34 2.35 2.36 2.37 2.38 2.39
TECH_BINS := $(patsubst %.c,%,$(wildcard glibc_*/*.c))
BASE_BINS := $(patsubst %.c,%,$(wildcard *.c))
BINS := $(TECH_BINS) $(BASE_BINS)

help:
	@echo 'make help                    - show this message'
	@echo 'make base                    - build all base binaries, namely `malloc_playground`, `first_fit`, `calc_tcache_idx`'
	@echo 'make <version>               - build all the techniques for the specific version. e.g. `make v2.39`'
	@echo 'make clean                   - remove all built binaries'
	@echo 'make all                     - build all binaries'
	@echo 'make test version=<version>  - test run all techniques for the specific version. e.g. `make test version=2.39`'

CFLAGS += -std=c99 -g -Wno-unused-result -Wno-free-nonheap-object
LDLIBS += -ldl

base: $(BASE_BINS)

$(foreach version,$(VERSIONS),$(eval v$(version): $(patsubst %.c,%,$(wildcard glibc_$(version)/*.c))))

all: $(BINS)

clean:
	@rm -f $(BINS)
	@echo "all the built binaries are removed."

define test_poc =
echo $(poc)
for i in $$(seq 0 20);\
do\
	LIBC_FATAL_STDERR_=1 $(poc) 1>/dev/null 2>&1 0>&1;\
	if [ "$$?" = "0" ]; then break; fi;\
	if [ "$$i" = "20" ]; then exit 1; fi;\
done
echo "success"
endef

test: v$(version)
	@$(foreach poc,$(patsubst %.c,%,$(wildcard glibc_$(version)/*.c)),$(call test_poc,$(poc));)
