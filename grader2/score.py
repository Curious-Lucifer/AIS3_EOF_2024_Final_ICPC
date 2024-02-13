from pwn import *
from tqdm import trange
import random

context.arch = 'amd64'
context.log_level = 'error'

score = 0

for num in trange(1, 101, leave=False):
    r = process(['./grader2', './asm2.bin'])

    a = random.choices(range((1 << 63) - 1), k=num)

    r.sendline(str(num).encode())
    for a_i in a:
        r.sendline(str(a_i).encode())

    ans = max(a) - min(a)
    num = int(r.recvline().strip())

    if ans == num:
        score += 1

    r.close()

print(f'{score} / 100')