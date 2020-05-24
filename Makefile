BASE = fastbin_dup malloc_playground first_fit calc_tcache_idx
V2.25 = glibc_2.25/fastbin_dup_into_stack glibc_2.25/fastbin_dup_consolidate glibc_2.25/unsafe_unlink glibc_2.25/house_of_spirit glibc_2.25/poison_null_byte glibc_2.25/house_of_lore glibc_2.25/overlapping_chunks glibc_2.25/overlapping_chunks_2 glibc_2.25/house_of_force glibc_2.25/large_bin_attack glibc_2.25/unsorted_bin_attack glibc_2.25/unsorted_bin_into_stack glibc_2.25/house_of_einherjar glibc_2.25/house_of_orange glibc_2.25/house_of_roman
V2.26 = glibc_2.26/unsafe_unlink glibc_2.26/house_of_lore glibc_2.26/overlapping_chunks glibc_2.26/large_bin_attack glibc_2.26/unsorted_bin_attack glibc_2.26/unsorted_bin_into_stack glibc_2.26/house_of_einherjar glibc_2.26/tcache_dup glibc_2.26/tcache_poisoning glibc_2.26/tcache_house_of_spirit glibc_2.26/house_of_botcake glibc_2.26/tcache_stashing_unlink_attack glibc_2.26/fastbin_reverse_into_tcache
PROGRAMS = $(BASE) $(V2.25) $(V2.26)
CFLAGS += -std=c99 -g

# Convenience to auto-call mcheck before the first malloc()
#CFLAGS += -lmcheck

all: $(PROGRAMS)
clean:
	rm -f $(PROGRAMS)
