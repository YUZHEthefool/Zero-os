/*
 * clone_test.c - Test clone syscall for Zero-OS
 *
 * This test verifies:
 * 1. clone() syscall with CLONE_VM | CLONE_THREAD flags
 * 2. Shared memory between parent and child
 * 3. Thread-like behavior (same address space)
 *
 * Compile: musl-gcc -static -o clone_test.elf clone_test.c
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

/* Clone flags */
#define CLONE_VM        0x00000100
#define CLONE_FS        0x00000200
#define CLONE_FILES     0x00000400
#define CLONE_SIGHAND   0x00000800
#define CLONE_THREAD    0x00010000

/* Shared counter - should be visible to both parent and child */
static volatile int shared_counter = 0;
static volatile int child_done = 0;

/* Child stack - 16KB */
static char child_stack[16 * 1024] __attribute__((aligned(16)));

/* Simple write wrapper using raw syscall to avoid any stack issues */
static void print_str(const char *s) {
    int len = 0;
    while (s[len]) len++;
    syscall(SYS_write, 1, s, len);
}

static void print_num(int n) {
    char buf[16];
    int i = 15;
    buf[i--] = '\0';
    if (n == 0) {
        buf[i--] = '0';
    } else {
        int neg = 0;
        if (n < 0) {
            neg = 1;
            n = -n;
        }
        while (n > 0) {
            buf[i--] = '0' + (n % 10);
            n /= 10;
        }
        if (neg) buf[i--] = '-';
    }
    print_str(&buf[i + 1]);
}

/* Child entry point - runs in the same address space as parent */
__attribute__((noreturn))
static void child_fn(void) {
    print_str("Child: started, setting shared_counter to 42\n");
    shared_counter = 42;
    child_done = 1;
    print_str("Child: done, exiting\n");

    /* Exit the thread - use inline asm to avoid any stack issues */
    __asm__ volatile (
        "mov $60, %%rax\n\t"   /* SYS_exit */
        "xor %%rdi, %%rdi\n\t" /* exit code 0 */
        "syscall\n\t"
        ::: "rax", "rdi"
    );
    __builtin_unreachable();
}

/*
 * my_clone - Custom clone wrapper using inline assembly
 *
 * This properly handles the child thread by:
 * 1. Pushing the child function pointer onto the child stack
 * 2. In child, popping and calling the function directly
 * 3. Never returning from child to avoid stack corruption
 *
 * Based on musl libc's __clone.s
 */
static long my_clone(unsigned long flags, void *stack, void (*fn)(void)) {
    long ret;

    /* Prepare child stack: push function pointer */
    uint64_t *sp = (uint64_t *)stack;
    sp -= 1;  /* Make room for function pointer */
    sp[0] = (uint64_t)fn;

    /* Align stack to 16 bytes */
    sp = (uint64_t *)((uint64_t)sp & ~0xFUL);

    __asm__ volatile (
        /* Save function pointer in r9 (will be available in child) */
        "mov %[fn], %%r9\n\t"

        /* Set up syscall arguments */
        "mov %[flags], %%rdi\n\t"  /* arg0: flags */
        "mov %[stack], %%rsi\n\t"  /* arg1: stack */
        "xor %%rdx, %%rdx\n\t"     /* arg2: parent_tid = NULL */
        "xor %%r10, %%r10\n\t"     /* arg3: child_tid = NULL */
        "xor %%r8, %%r8\n\t"       /* arg4: tls = 0 */
        "mov $56, %%rax\n\t"       /* SYS_clone */
        "syscall\n\t"

        /* Check if we're the child (rax == 0) */
        "test %%rax, %%rax\n\t"
        "jnz 1f\n\t"

        /* === Child path === */
        /* Clear frame pointer for clean stack trace */
        "xor %%rbp, %%rbp\n\t"

        /* Call the child function (stored in r9) */
        "call *%%r9\n\t"

        /* If child function returns (shouldn't happen), exit */
        "mov $60, %%rax\n\t"   /* SYS_exit */
        "mov $1, %%rdi\n\t"    /* exit code 1 */
        "syscall\n\t"

        /* === Parent path === */
        "1:\n\t"
        "mov %%rax, %[ret]\n\t"

        : [ret] "=r" (ret)
        : [flags] "r" (flags),
          [stack] "r" (sp),
          [fn] "r" (fn)
        : "rax", "rdi", "rsi", "rdx", "r8", "r9", "r10", "r11",
          "rcx", "memory", "cc"
    );

    return ret;
}

int main(void) {
    print_str("=== Clone Syscall Test ===\n");
    print_str("Initial shared_counter = ");
    print_num(shared_counter);
    print_str("\n");

    /* Setup clone flags for thread creation */
    unsigned long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;

    /* Stack grows downward, so pass the top of the stack */
    void *stack_top = child_stack + sizeof(child_stack);

    print_str("Calling clone() with flags=0x");
    /* Print hex */
    char hex[] = "00000000\n";
    unsigned long f = flags;
    for (int i = 7; i >= 0; i--) {
        int d = f & 0xf;
        hex[i] = d < 10 ? '0' + d : 'a' + d - 10;
        f >>= 4;
    }
    print_str(hex);

    /* Call our custom clone wrapper */
    long ret = my_clone(flags, stack_top, child_fn);

    if (ret < 0) {
        print_str("clone() failed with error: ");
        print_num((int)(-ret));
        print_str("\n");
        return 1;
    }

    /* Parent continues here */
    print_str("Parent: clone() returned child tid = ");
    print_num((int)ret);
    print_str("\n");

    /* Wait for child to finish (busy wait) */
    print_str("Parent: waiting for child...\n");
    int timeout = 10000000;
    while (!child_done && timeout > 0) {
        timeout--;
        /* Yield to let child run */
        __asm__ volatile (
            "mov $24, %%rax\n\t"  /* SYS_sched_yield */
            "syscall\n\t"
            ::: "rax", "rcx", "r11", "memory"
        );
    }

    if (child_done) {
        print_str("Parent: child completed\n");
        print_str("Final shared_counter = ");
        print_num(shared_counter);
        print_str("\n");

        if (shared_counter == 42) {
            print_str("TEST PASSED: shared memory works!\n");
        } else {
            print_str("TEST FAILED: expected 42\n");
            return 1;
        }
    } else {
        print_str("TEST FAILED: timeout waiting for child\n");
        return 1;
    }

    return 0;
}
