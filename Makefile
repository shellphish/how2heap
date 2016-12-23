PROGRAMS = fastbin_dup fastbin_dup_into_stack unsafe_unlink house_of_spirit poison_null_byte malloc_playground first_fit house_of_lore overlapping_chunks house_of_force unsorted_bin_attack house_of_einherjar
CFLAGS += -std=c99 -g

# Convenience to auto-call mcheck before the first malloc()
#CFLAGS += -lmcheck

all: $(PROGRAMS)
clean:
	rm -f $(PROGRAMS)
