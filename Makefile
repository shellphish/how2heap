PROGRAMS = fastbin_dup fastbin_dup_into_stack unsafe_unlink house_of_spirit poison_null_byte malloc_playground
CFLAGS += -std=c99

# Convenience to auto-call mcheck before the first malloc()
#CFLAGS += -lmcheck

all: $(PROGRAMS)
clean:
	rm -f $(PROGRAMS)
