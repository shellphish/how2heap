// hook __libc_start_main
__asm__(".symver __libc_start_main_old,__libc_start_main@GLIBC_2.2.5");
int __libc_start_main_old(int (*main) (int, char **, char **),
                          int argc,
                          char **argv,
                          __typeof (main) init,
                          void (*fini) (void),
                          void (*rtld_fini) (void),
                          void *stack_end);

int __wrap___libc_start_main(int (*main) (int, char **, char **),
                             int argc,
                             char **argv,
                             __typeof (main) init,
                             void (*fini) (void),
                             void (*rtld_fini) (void),
                             void *stack_end)
{
  return __libc_start_main_old(main, argc, argv, init, fini, rtld_fini, stack_end);
}

// hook dlsym
__asm__(".symver dlsym_old,dlsym@GLIBC_2.2.5");
//__asm__(".symver dlsym_old,__libc_dlsym@GLIBC_PRIVATE");
void *dlsym_old(void *handle, const char *symbol);
void *__wrap_dlsym(void *handle, const char *symbol)
{
	return dlsym_old(handle, symbol);
}
