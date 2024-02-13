from pwn import *
from tqdm import trange
import random

context.arch = 'amd64'
context.log_level = 'error'

score = 0

for _ in trange(100, leave=False):
    r = process(['./grader1', './asm1.bin'])

    a, b = random.randint(0, (1 << 63) - 1), random.randint(0, (1 << 63) - 1)
    r.sendline(f'{a} {b}'.encode())

    ans = (a + b) & 0xffffffffffffffff
    num = int(r.recvline().strip()) & 0xffffffffffffffff

    if num == ans:
        score += 1

    r.close()

print(f'{score} / 100')