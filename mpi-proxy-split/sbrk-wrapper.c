// Usage:  To test, do:
//           gcc -DSTANDALONE sbrk-wrapper.c -ldl -lpthread && ./a.out
// Testing:  gdb a.out; ((gdb) break main && run && break mmap
//           This shows how GDB morecore can call sbrk or mmap.
// This works only with dynamically linked targets.
// This could be included in DMTCP.

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <linux/version.h>

#ifndef __USE_GNU
# define __USE_GNU
#endif
#include <dlfcn.h> 

#define ROUND_DOWN(x) ((unsigned long)(x) \
                       & ~(unsigned long)(0x1000-1))
#define ROUND_UP(x) ((unsigned long)(x + 0x1000-1) \
                     & ~(unsigned long)(0x1000-1))

pthread_mutex_t sbrk_mutex = PTHREAD_MUTEX_INITIALIZER;

#define HAS_MAP_FIXED_NOREPLACE LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)

static void patch_trampoline(void *from_addr, void *to_addr);
static void unpatch_trampoline(void *from_addr);

/* Due to split processes, during restart, the sbrk value (end-of-data)
 * reflects the lh_proxy code that was called first.  So, when the upper
 * half tries to call sbrk(), the end-of-data is too far away.
 *     A less robust workaround would be to use env MALLOC_MMAP_THRESHOLD_=8096
 * We prefer to intercept sbrk.
 */
void *sbrk(intptr_t increment) {
fprintf(stderr, "************* sbrk was called: %ld\n", increment);
  void *rc = 0;
  static int is_patched = 0;
  static char *cur_break = 0x0;
  static int cur_break_is_valid = 1;
  static void *(*this_sbrk)(intptr_t increment) = NULL;
  static void *(*next_sbrk)(intptr_t increment) = NULL;
  if (!is_patched) {
    // FIXME:  For consistency, compare dlsym(RTLD_DEFAULT, "sbrk") with $pc,
    //         to verify that it's this instance of sbrk that is selected.
    this_sbrk = dlsym(RTLD_DEFAULT, "sbrk");
    next_sbrk = dlsym(RTLD_NEXT, "sbrk"); // This should be libc.so:sbrk().
    patch_trampoline(next_sbrk, this_sbrk);
    is_patched = 1;
  }
  pthread_mutex_lock(&sbrk_mutex);
  if (cur_break_is_valid) {
    unpatch_trampoline(next_sbrk); // unpatch so that we can call the real sbrk
    rc = (*next_sbrk)(increment);
    patch_trampoline(next_sbrk, this_sbrk); // patch for when we reach again
    if (rc == (void *)-1) {
      cur_break_is_valid = 0;
    } else {
      cur_break = rc;
    }
  }

  if (!cur_break_is_valid) { // If cur_break not valid, fake it by using mmap.
    rc = cur_break; // sbrk returns previous break value
    cur_break += increment;
    long int page_delta = ROUND_UP(cur_break) - ROUND_UP(rc);
    if (page_delta == 0) {
      // No change in break value
    } else if (page_delta < 0) {
      munmap((void *)ROUND_UP(cur_break), -page_delta);
    } else { // else page_delta > 0
#if HAS_MAP_FIXED_NOREPLACE
      rc = mmap((void *)ROUND_UP(cur_break), page_delta, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
#else
      rc = mmap((void *)ROUND_UP(cur_break), page_delta, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (rc != MAP_FAILED && rc != cur_break) {
        // If kernel allocated at a different address than ROUND_UP(cur_break)
        munmap(rc, page_delta);
        rc = MAP_FAILED;
      }
#endif
    }
    if (rc == MAP_FAILED) {
      errno = ENOMEM;
    } else {
      cur_break += ROUND_UP(increment);
    }
  }
  pthread_mutex_unlock(&sbrk_mutex);
#ifdef STANDALONE
  fprintf(stderr, "rc = sbrk(%d) called; rc == %p\n", (int)increment, rc);
#endif
  return rc;
}


#if defined(__x86_64__)
static unsigned char asm_jump[] = {
  // mov    $0x1234567812345678,%rax
  0x48, 0xb8, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12,
  // jmpq   *%rax
  0xff, 0xe0
};
// Beginning of address in asm_jump:
static const int addr_offset = 2;
#elif defined(__i386__)
static unsigned char asm_jump[] = {
    0xb8, 0x78, 0x56, 0x34, 0x12, // mov    $0x12345678,%eax
    0xff, 0xe0                    // jmp    *%eax
};
// Beginning of address in asm_jump:
static const int addr_offset = 1;
#else
# error "architecture not supported"
#endif

static unsigned char orig_prefix[100];

static void get_page_params(void *from_addr,
                            void **page_base, int *page_length) {
  unsigned long pagesize = sysconf(_SC_PAGESIZE);
  *page_base = (void *)ROUND_DOWN((unsigned long)from_addr);
  *page_length = pagesize;
  if (from_addr + sizeof(asm_jump) - *page_base > pagesize) {
    // The patching instructions cross page boundary.  View page as double size.
    *page_length = 2 * pagesize;
  }
}

static void patch_trampoline(void *from_addr, void *to_addr) {
  void *page_base;
  int page_length;
  get_page_params(from_addr, &page_base, &page_length);
  int rc = mprotect(page_base, page_length, PROT_READ | PROT_WRITE | PROT_EXEC);
  if (rc == -1) { perror("patch_trampoline:mprotect"); exit(1); }
  assert(sizeof(asm_jump) < sizeof(orig_prefix));
  memcpy(orig_prefix, from_addr, sizeof(asm_jump));
  memcpy(from_addr, asm_jump, sizeof(asm_jump));
  memcpy(from_addr + addr_offset, &to_addr, sizeof(&to_addr));
  rc = mprotect(page_base, page_length, PROT_READ | PROT_EXEC);
  if (rc == -1) { perror("patch_trampoline:mprotect"); exit(1); }
}

static void unpatch_trampoline(void *from_addr) {
  void *page_base;
  int page_length;
  get_page_params(from_addr, &page_base, &page_length);
  int rc = mprotect(page_base, page_length, PROT_READ | PROT_WRITE | PROT_EXEC);
  if (rc == -1) { perror("unpatch_trampoline:mprotect"); exit(1); }
  memcpy(from_addr, orig_prefix, sizeof(asm_jump));
  rc = mprotect(page_base, page_length, PROT_READ | PROT_EXEC);
  if (rc == -1) { perror("unpatch_trampoline:mprotect"); exit(1); }
}


#ifdef STANDALONE
int main() {
  void *rc;
  printf("Patching libc with sbrk\n");
  sbrk(0); // To initialize it.
  printf("Calling: malloc(100);\n");
  rc = malloc(100);
  printf("Calling: malloc(1000);\n");
  rc = malloc(1000);
  printf("Calling: malloc(10000);\n");
  rc = malloc(10000);
  printf("Calling: malloc(100000);\n");
  rc = malloc(100000);
sbrk(100);
sbrk(-100);
sbrk(-10000);
sbrk(0);
sbrk(0);
  printf("Calling: malloc(1000000);\n");
  rc = malloc(1000000);
  printf("Done.\n");
  return 0;
}
#endif
