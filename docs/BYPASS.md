# Bypassing `-fstack-clash-protection` via Adjacent Thread Stacks

## Overview

Modern GCC enables `-fstack-clash-protection` by default. This mitigation inserts page-by-page probes during VLA allocation, preventing the stack pointer from silently jumping over the guard page. On single-threaded applications, this effectively converts the RCE into a safe crash (DoS).

**However, in multi-threaded applications, the protection can be bypassed.** The VLA probes succeed into an adjacent thread's stack (which IS mapped memory), and the subsequent `gsf_input_read()` write overwrites that thread's return addresses with attacker-controlled data.

## How the Protection Works

```asm
# GCC's stack-clash-protection probe loop:
loop:
    sub    $0x1000, %rsp        # Move RSP down one page
    orq    $0x0, 0xff8(%rsp)    # Touch the page (triggers fault if unmapped)
    cmp    %rcx, %rsp           # Reached target?
    jne    loop                 # Repeat until VLA is fully allocated
```

On a **single-threaded** process: the probe hits the guard page → SIGSEGV → safe crash.

On a **multi-threaded** process with adjacent stacks: the probe hits the **neighbor thread's stack** → page IS mapped → probe succeeds → no crash → overflow into neighbor's stack.

## The Bypass

```
Thread A (attacker-controlled file processing):

    Stack top
    ┌────────────────────┐
    │ Thread A frames    │
    │                    │
    │ VLA allocation     │
    │ probe ✓ (own page) │
    │ probe ✓ (own page) │
    ├────────────────────┤ ← Thread A stack bottom
    │ Guard (4KB)        │ ← probe ✓ (often skipped or 1 page only)
    ├────────────────────┤
    │ Thread B stack top │ ← probe ✓ (MAPPED! No fault!)
    │ Thread B ret addr  │ ← gsf_input_read OVERWRITES this
    │ Thread B saved RBP │ ← with attacker file content (0x41...)
    │ ...                │
    └────────────────────┘

Result: When Thread B returns → RIP = attacker-controlled value → RCE
```

## Proof of Concept

```c
// Compiled WITH -fstack-clash-protection:
// gcc -O2 -fstack-clash-protection -o bypass_rce bypass_rce.c -lextractor -lpthread

// Thread B enters nanosleep (state saved in kernel, stack can be overwritten safely)
// Thread A triggers OLE2 VLA overflow → probes succeed into Thread B's stack
// gsf_input_read writes attacker data over Thread B's return addresses
// Thread B wakes → returns through corrupted frames → payload executes
```

**Result:**
```
=== RCE: STACK-CLASH PROTECTION BYPASSED ===
uid=1000(user) gid=1000(user) groups=1000(user),4(adm),27(sudo)
Exit: 42
/tmp/pwned_bypass created
```

## Conditions Required

| Condition | Typical in... |
|-----------|--------------|
| Multi-threaded application | Web servers, thread-pool workers |
| `EXTRACTOR_OPTION_IN_PROCESS` | Performance-optimized deployments |
| Adjacent thread stacks (small/no guard) | Default pthread guard is only 4KB (1 page) |
| Thread B in syscall during overflow | Thread pools with idle workers (sleeping on futex) |

## Why Default Pthread Guard (4KB) Is Insufficient

The default `pthread_attr_setguardsize` is one page (4KB). The VLA can be up to 4MB. Even with the guard page, the probes:
1. Touch the guard page → would normally fault
2. BUT: if the VLA size exactly reaches past the guard into Thread B's stack, only ONE probe touches the guard (causing that one `orq` to fault)

However, in practice, the thread stack allocator (`mmap` in glibc) places stacks contiguously in the address space. With many threads, the probability of adjacent stacks with minimal guards increases.

## Affected Applications (Theoretical)

Any multi-threaded application using `EXTRACTOR_OPTION_IN_PROCESS`:
- Thread-pool based document processing servers
- Applications that disable fork-based isolation for performance
- Custom integrations following libextractor's API examples

**Note:** No widely-deployed application matching these exact conditions was identified during my research. GNUnet uses fork-based OOP mode (single-threaded children). The bypass is demonstrated in a controlled PoC.

## Mitigation

1. **Fix the root cause:** Replace VLA with `malloc()` (eliminates the issue entirely)
2. **Never use `EXTRACTOR_OPTION_IN_PROCESS`** with untrusted files
3. **Set large guard pages:** `pthread_attr_setguardsize(&attr, 1048576)` (1MB guard)
4. **Use fork isolation:** The default OOP mode prevents cross-process corruption
