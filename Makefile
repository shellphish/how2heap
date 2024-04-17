BASE = malloc_playground first_fit calc_tcache_idx
V2.23 = fastbin_dup fastbin_dup_consolidate fastbin_dup_into_stack house_of_einherjar house_of_force house_of_gods house_of_lore house_of_mind_fastbin house_of_orange house_of_roman house_of_spirit house_of_storm large_bin_attack mmap_overlapping_chunks overlapping_chunks overlapping_chunks_2 poison_null_byte unsafe_unlink unsorted_bin_attack unsorted_bin_into_stack sysmalloc_int_free
V2.24 = fastbin_dup fastbin_dup_consolidate fastbin_dup_into_stack house_of_einherjar house_of_force house_of_gods house_of_lore house_of_mind_fastbin house_of_roman house_of_spirit house_of_storm large_bin_attack mmap_overlapping_chunks overlapping_chunks overlapping_chunks_2 poison_null_byte unsafe_unlink unsorted_bin_attack unsorted_bin_into_stack sysmalloc_int_free
V2.27 = fastbin_dup fastbin_dup_consolidate fastbin_dup_into_stack fastbin_reverse_into_tcache house_of_botcake house_of_einherjar house_of_force house_of_lore house_of_mind_fastbin house_of_spirit house_of_storm large_bin_attack mmap_overlapping_chunks overlapping_chunks poison_null_byte tcache_house_of_spirit tcache_poisoning tcache_stashing_unlink_attack unsafe_unlink unsorted_bin_attack unsorted_bin_into_stack sysmalloc_int_free
V2.31 = fastbin_dup fastbin_dup_consolidate fastbin_dup_into_stack fastbin_reverse_into_tcache house_of_botcake house_of_einherjar house_of_lore house_of_mind_fastbin house_of_spirit large_bin_attack mmap_overlapping_chunks overlapping_chunks poison_null_byte tcache_house_of_spirit tcache_poisoning tcache_stashing_unlink_attack unsafe_unlink sysmalloc_int_free
V2.32 = decrypt_safe_linking fastbin_dup fastbin_dup_consolidate fastbin_dup_into_stack fastbin_reverse_into_tcache house_of_botcake house_of_einherjar house_of_lore house_of_mind_fastbin house_of_spirit large_bin_attack mmap_overlapping_chunks overlapping_chunks poison_null_byte tcache_house_of_spirit tcache_poisoning tcache_stashing_unlink_attack unsafe_unlink safe_link_double_protect house_of_water sysmalloc_int_free
V2.33 = decrypt_safe_linking fastbin_dup fastbin_dup_consolidate fastbin_dup_into_stack fastbin_reverse_into_tcache house_of_botcake house_of_einherjar house_of_lore house_of_mind_fastbin house_of_spirit large_bin_attack mmap_overlapping_chunks overlapping_chunks poison_null_byte tcache_house_of_spirit tcache_poisoning tcache_stashing_unlink_attack unsafe_unlink safe_link_double_protect house_of_water sysmalloc_int_free
V2.34 = decrypt_safe_linking fastbin_dup fastbin_dup_consolidate fastbin_dup_into_stack fastbin_reverse_into_tcache house_of_botcake house_of_einherjar house_of_lore house_of_mind_fastbin house_of_spirit large_bin_attack mmap_overlapping_chunks overlapping_chunks poison_null_byte tcache_house_of_spirit tcache_poisoning tcache_stashing_unlink_attack unsafe_unlink safe_link_double_protect house_of_water sysmalloc_int_free
V2.35 = decrypt_safe_linking fastbin_dup fastbin_dup_consolidate fastbin_dup_into_stack fastbin_reverse_into_tcache house_of_botcake house_of_einherjar house_of_lore house_of_mind_fastbin house_of_spirit large_bin_attack mmap_overlapping_chunks overlapping_chunks poison_null_byte tcache_house_of_spirit tcache_poisoning tcache_stashing_unlink_attack unsafe_unlink safe_link_double_protect house_of_water sysmalloc_int_free
V2.36 = decrypt_safe_linking fastbin_dup fastbin_dup_consolidate fastbin_dup_into_stack fastbin_reverse_into_tcache house_of_botcake house_of_einherjar house_of_lore house_of_mind_fastbin house_of_spirit large_bin_attack mmap_overlapping_chunks overlapping_chunks poison_null_byte tcache_house_of_spirit tcache_poisoning tcache_stashing_unlink_attack unsafe_unlink safe_link_double_protect house_of_water sysmalloc_int_free
V2.37 = decrypt_safe_linking fastbin_dup fastbin_dup_consolidate fastbin_dup_into_stack fastbin_reverse_into_tcache house_of_botcake house_of_einherjar house_of_lore house_of_mind_fastbin house_of_spirit large_bin_attack mmap_overlapping_chunks overlapping_chunks poison_null_byte tcache_house_of_spirit tcache_poisoning tcache_stashing_unlink_attack unsafe_unlink safe_link_double_protect house_of_water sysmalloc_int_free
V2.38 = decrypt_safe_linking fastbin_dup fastbin_dup_consolidate fastbin_dup_into_stack fastbin_reverse_into_tcache house_of_botcake house_of_einherjar house_of_lore house_of_mind_fastbin house_of_spirit large_bin_attack mmap_overlapping_chunks overlapping_chunks poison_null_byte tcache_house_of_spirit tcache_poisoning tcache_stashing_unlink_attack unsafe_unlink safe_link_double_protect house_of_water sysmalloc_int_free

# turn technique names into paths
VV2.23 = $(addprefix glibc_2.23/, $(V2.23))
VV2.24 = $(addprefix glibc_2.24/, $(V2.24))
VV2.27 = $(addprefix glibc_2.27/, $(V2.27))
VV2.31 = $(addprefix glibc_2.31/, $(V2.31))
VV2.32 = $(addprefix glibc_2.32/, $(V2.32))
VV2.33 = $(addprefix glibc_2.33/, $(V2.33))
VV2.34 = $(addprefix glibc_2.34/, $(V2.34))
VV2.35 = $(addprefix glibc_2.35/, $(V2.35))
VV2.36 = $(addprefix glibc_2.36/, $(V2.36))
VV2.37 = $(addprefix glibc_2.37/, $(V2.37))
VV2.38 = $(addprefix glibc_2.38/, $(V2.38))

PROGRAMS = $(BASE) $(VV2.23) $(VV2.24) $(VV2.27) $(VV2.31) $(VV2.32) $(VV2.33) $(VV2.34) $(VV2.35) $(VV2.36) $(VV2.37) $(VV2.38)
CFLAGS += -std=c99 -g -Wno-unused-result -Wno-free-nonheap-object
LDLIBS += -ldl

# Convenience to auto-call mcheck before the first malloc()
#CFLAGS += -lmcheck

all: $(PROGRAMS)
clean:
	rm -f $(PROGRAMS)

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

#if [ "$$i" == "5" ]; then exit 1; fi;\

test: $(PROGRAMS)
	@if [ -z "$(target)" ] || [ -z "$(VV$(target))" ];\
	then echo "run 'make test target=<target_version>' to test existing techniques"; exit 1; fi;

	@$(foreach poc,$(VV$(target)),$(call test_poc,$(poc));)
