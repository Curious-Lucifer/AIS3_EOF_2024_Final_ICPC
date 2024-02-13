from pwn import *
from tqdm import trange
import random, string

context.arch = 'amd64'
context.log_level = 'error'

def gen_numstr():
    length = random.randint(1, 1000)
    return random.choice('123456789') + ''.join(random.choices(string.digits, k=length - 1))

score = 0

for _ in trange(100, leave=False):
    r = process(['./grader3', './asm3.bin'])

    a, b = gen_numstr(), gen_numstr()

    r.sendline(a.encode())
    r.sendline(b.encode())

    ans = str(int(a) + int(b))
    numstr = r.recvline().strip().decode()

    if ans == numstr:
        score += 1

    r.close()

print(f'{score} / 100')