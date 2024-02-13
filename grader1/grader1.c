/*
build in a ubuntu:22.04 docker container with:
$ apt update && apt install -y build-essential binutils
$ gcc /usr/src/grader.c -o /usr/bin/grader
$ strip /usr/bin/grader
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

void *load_shellcode(const char *filename) {
    void *addr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    assert(addr != MAP_FAILED);
    FILE *shellcode = fopen(filename, "r");
    fread(addr, 1, 0x1000, shellcode);
    assert(ferror(shellcode) == 0);
    fclose(shellcode);
    return addr;
}

int main(int argc, char **argv) {
    long long (*a_plus_b)(long long, long long) = load_shellcode(argv[1]);
    long long a, b;
    scanf("%lld%lld", &a, &b);
    long long c = a_plus_b(a, b);
    printf("%lld\n", c);
}