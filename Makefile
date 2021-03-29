BASE = malloc_playground first_fit calc_tcache_idx
V2.23 = glibc_2.23/fastbin_dup_into_stack glibc_2.23/fastbin_dup_consolidate glibc_2.23/unsafe_unlink glibc_2.23/house_of_spirit glibc_2.23/poison_null_byte glibc_2.23/house_of_lore glibc_2.23/overlapping_chunks glibc_2.23/overlapping_chunks_2 glibc_2.23/house_of_force glibc_2.23/large_bin_attack glibc_2.23/unsorted_bin_attack glibc_2.23/unsorted_bin_into_stack glibc_2.23/house_of_einherjar glibc_2.23/house_of_orange glibc_2.23/house_of_roman glibc_2.23/mmap_overlapping_chunks glibc_2.23/fastbin_dup glibc_2.23/house_of_mind_fastbin
V2.27 = glibc_2.27/unsafe_unlink glibc_2.27/house_of_lore glibc_2.27/overlapping_chunks glibc_2.27/large_bin_attack glibc_2.27/unsorted_bin_attack glibc_2.27/unsorted_bin_into_stack glibc_2.27/house_of_einherjar glibc_2.27/tcache_poisoning glibc_2.27/tcache_house_of_spirit glibc_2.27/house_of_botcake glibc_2.27/tcache_stashing_unlink_attack glibc_2.27/fastbin_reverse_into_tcache glibc_2.27/mmap_overlapping_chunks glibc_2.27/fastbin_dup glibc_2.27/house_of_force glibc_2.27/poison_null_byte glibc_2.27/house_of_mind_fastbin
V2.31 = glibc_2.31/unsafe_unlink glibc_2.31/overlapping_chunks glibc_2.31/house_of_einherjar glibc_2.31/tcache_poisoning glibc_2.31/tcache_house_of_spirit glibc_2.31/house_of_botcake glibc_2.31/tcache_stashing_unlink_attack glibc_2.31/fastbin_reverse_into_tcache glibc_2.31/mmap_overlapping_chunks glibc_2.31/fastbin_dup glibc_2.31/large_bin_attack glibc_2.31/house_of_mind_fastbin # glibc_2.31/house_of_lore
PROGRAMS = $(BASE) $(V2.23) $(V2.27) $(V2.31)
CFLAGS += -std=c99 -g
LDLIBS += -ldl

# Convenience to auto-call mcheck before the first malloc()
#CFLAGS += -lmcheck

all: $(PROGRAMS)
clean:
	rm -f $(PROGRAMS)

define test_poc =
echo $(poc)
for i in $$(seq 0 4);\
do\
	LIBC_FATAL_STDERR_=1 $(poc) 1>/dev/null 2>&1 0>&1;\
	if [ "$$?" = "0" ]; then break; fi;\
	if [ "$$i" = "4" ]; then exit 1; fi;\
done
echo "success"
endef

#if [ "$$i" == "5" ]; then exit 1; fi;\

test: $(PROGRAMS)
	@if [ -z "$(target)" ] || [ -z "$(V$(target))" ];\
	then echo "run 'make test target=<target_version>' to test existing techniques"; exit 1; fi;

	@$(foreach poc,$(V$(target)),$(call test_poc,$(poc));)
