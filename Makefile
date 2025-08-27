.PHONY: help clean distclean all test

VERSIONS := 2.23 2.24 2.27 2.31 2.32 2.33 2.34 2.35 2.36 2.37 2.38 2.39 2.40 2.41
TECH_BINS := $(patsubst %.c,%,$(wildcard glibc_*/*.c))
BASE_BINS := $(patsubst %.c,%,$(wildcard *.c))
DOWNLOADED := glibc-all-in-one/libs glibc-all-in-one/debs
BINS := $(TECH_BINS) $(BASE_BINS)
ARCH := amd64

ifeq ($(H2H_USE_SYSTEM_LIBC),)
H2H_USE_SYSTEM_LIBC := Y
endif

help:
	@echo 'make help                    - show this message'
	@echo 'make base                    - build all base binaries, namely `malloc_playground`, `first_fit`, `calc_tcache_idx`'
	@echo 'make <version>               - build all the techniques for a specific version. e.g. `make v2.39`'
	@echo 'make clean                   - remove all built binaries'
	@echo 'make distclean               - remove all built binaries and downloaded libcs'
	@echo 'make all                     - build all binaries'
	@echo 'make test version=<version>  - test run all techniques for a specific version. e.g. `make test version=2.39`'

CFLAGS += -std=c99 -g -Wno-unused-result -Wno-free-nonheap-object
LDLIBS += -ldl

base: $(BASE_BINS)

# initialize glibc-all-in-one
libc_ready:
	git submodule update --init --recursive
	cd glibc-all-in-one && ./update_list

# populate the download_glibc_<version> rules
$(addprefix download_glibc_, $(VERSIONS)): libc_ready
	@echo $@

	version=$(patsubst download_glibc_%,%,$@); \
	libc=$$(cat glibc-all-in-one/list | grep "$$version" | grep "$(ARCH)" | head -n 1); \
	old_libc=$$(cat glibc-all-in-one/old_list | grep "$$version" | grep "$(ARCH)" | head -n 1); \
	if [ -z $$libc ]; then libc=$$old_libc; script="download_old"; else libc=$$libc; script="download"; fi; \
	cd glibc-all-in-one; \
	rm -rf libs/$$libc; \
	./$$script $$libc

# populate the make <version> rules
ifeq ($(H2H_USE_SYSTEM_LIBC),Y)
$(foreach version,$(VERSIONS),$(eval v$(version): $(patsubst %.c,%,$(wildcard glibc_$(version)/*.c))))
else
$(foreach version,$(VERSIONS),$(eval v$(version): download_glibc_$(version) $(patsubst %.c,%,$(wildcard glibc_$(version)/*.c)) ))
endif

# the compilation rules
%: %.c
	version=$(word 1, $(subst /, ,$(patsubst glibc_%,%,$@))); \
	if [ "$(H2H_USE_SYSTEM_LIBC)" = "Y" ]; \
	then \
		$(CC) $(CFLAGS) $(DIR_CFLAGS_$(@D)) $^ -o $@ $(LDLIBS); \
	else \
		$(CC) $(CFLAGS) $(DIR_CFLAGS_$(@D)) $^ -o $@ $(LDLIBS) \
		-Xlinker -rpath=$$(realpath glibc-all-in-one/libs/$$version*) \
		-Xlinker -I$$(realpath glibc-all-in-one/libs/$$version*/ld-linux-x86-64.so.2) \
		-Xlinker $$(realpath glibc-all-in-one/libs/$$version*/libc.so.6) \
		-Xlinker $$(realpath glibc-all-in-one/libs/$$version*/libdl.so.2); \
	fi

all: $(BINS)

clean:
	@rm -f $(BINS)
	@echo "all the built binaries are removed."

distclean:
	@rm -f $(BINS)
	@rm -rf $(DOWNLOADED)
	@echo "all the built binaries and all downloaded libcs are removed."

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
