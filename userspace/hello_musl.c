// Simple musl test program for Zero-OS
// This tests basic musl libc initialization and I/O

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char *argv[]) {
    // Test 1: Simple write syscall
    const char *msg = "Hello from musl libc!\n";
    write(1, msg, 22);

    // Test 2: getpid
    pid_t pid = getpid();
    printf("My PID: %d\n", pid);

    // Test 3: Simple calculation
    int result = 42 * 2;
    printf("42 * 2 = %d\n", result);

    // Test 4: Success message
    puts("musl libc test passed!");

    return 0;
}
