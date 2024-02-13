from pwn import *
from tqdm import trange
import random, string

charset = string.ascii_lowercase

context.arch = 'amd64'
context.log_level = 'error'

score = 0

for num in trange(1, 101, leave=False):
    r = process(['./grader4', './asm4.bin'])

    str_list = [''.join(random.choices(charset, k=random.randint(1, 100))) for _ in range(num)]

    r.sendline(str(num).encode())
    for i in range(num):
        r.sendline(str_list[i].encode())

    ans_list = []
    for i in range(num):
        ans_list.append(r.recvline().strip().decode())

    r.close()

    str_list.sort()
    if str_list == ans_list:
        score += 1

print(f'{score} / 100')