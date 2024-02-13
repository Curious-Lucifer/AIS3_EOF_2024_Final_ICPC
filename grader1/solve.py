from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
import random, sys

context.arch = 'amd64'



def load_rip_shellcode1(disable_bytes, available_regs):
    available_bytes = [i for i in range(256) if not i in disable_bytes]
    shellcode_prototype = '''
        lea {reg}, [rip + {offset1}]
        sub {reg}, {offset2}
    '''

    # 0x8d : lea
    if 0x8d in disable_bytes:
        return False, None, None

    # 0x4c : prefix for r8, r9, r10, r11, r12, r13, r14, r15 in lea
    # 0x48 : prefix for rax, rbx, rcx, rdx, rdi, rsi in lea & sub
    if (0x4c in disable_bytes) and (0x48 in disable_bytes):
        return False, None, None

    # 0x81 : sub
    # 0x48 0x2d : sub rax, {offset2}
    if (0x81 in disable_bytes) and ((0x48 in disable_bytes) or (0x2d in disable_bytes)):
        return False, None, None

    # 0x49 : prefix for r8, r9, r10, r11, r12, r13, r14, r15 in sub
    if 0x49 in disable_bytes:
        return False, None, None

    for _ in range(100):
        offset1 = bytes_to_long(bytes(random.choices(available_bytes, k=4)))
        offset2 = offset1 + 7

        if offset1 >= 0x80000000:
            continue

        check = True
        for byte in long_to_bytes(offset2, 4):
            if byte in disable_bytes:
                check = False
        if check:
            break

        if (_ == 99) and (not check):
            return False, None, None

    for reg in available_regs:
        shellcode = shellcode_prototype.format(
            reg = reg, 
            offset1 = offset1, 
            offset2 = offset2,
        )

        shellcode_asm = asm(shellcode)

        check = True
        for byte in shellcode_asm:
            if byte in disable_bytes:
                check = False
        if check:
            return True, reg, shellcode

    return False, None, None



def load_rip_shellcode2(disable_bytes, available_regs, func_ptr_reg):
    shellcode_prototype = '''
        mov {reg1}, {reg2}
    '''

    # 0x89 : mov
    if 0x89 in disable_bytes:
        return False, None, None

    if func_ptr_reg in ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
        # 0x4c : prefix for rax, rbx, rcx, rdx, rdi, rsi in mov
        # 0x4d : prefix for r8, r9, r10, r11, r12, r13, r14, r15 in mov
        if (0x4c in disable_bytes) and (0x4d in disable_bytes):
            return False, None, None


    else:
        # 0x48 : prefix for rax, rbx, rcx, rdx, rdi, rsi in mov
        # 0x49 : prefix for r8, r9, r10, r11, r12, r13, r14, r15 in mov
        if (0x48 in disable_bytes) and (0x49 in disable_bytes):
            return False, None, None

    for reg in available_regs:
        shellcode = shellcode_prototype.format(
            reg1 = reg, 
            reg2 = func_ptr_reg
        )

        shellcode_asm = asm(shellcode)

        check = True
        for byte in shellcode_asm:
            if byte in disable_bytes:
                check = False
        if check:
            return True, reg, shellcode

    return False, None, None



def load_rip_shellcode3(disable_bytes, available_regs, func_ptr_reg):
    shellcode_prototype = '''
        push {reg1}
        pop {reg2}
    '''

    if func_ptr_reg in ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
        # 0x41 : push
        if 0x41 in disable_bytes:
            return False, None, None

    for reg in available_regs:
        shellcode = shellcode_prototype.format(
            reg1 = func_ptr_reg, 
            reg2 = reg
        )

        shellcode_asm = asm(shellcode)

        check = True
        for byte in shellcode_asm:
            if byte in disable_bytes:
                check = False
        if check:
            return True, reg, shellcode

    return False, None, None



def load_rip_shellcode4(disable_bytes, available_regs, func_ptr_reg):
    shellcode_prototype = '''
        vmovq {avx512_reg}, {reg1}
        vmovq {reg2}, {avx512_reg}
    '''

    avx512_regs = ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7', 'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15']

    for avx512_reg in avx512_regs:
        for reg in available_regs:
            shellcode = shellcode_prototype.format(
                avx512_reg = avx512_reg, 
                reg1 = func_ptr_reg, 
                reg2 = reg
            )

            shellcode_asm = asm(shellcode)

            check = True
            for byte in shellcode_asm:
                if byte in disable_bytes:
                    check = False
            if check:
                return True, reg, shellcode

    return False, None, None



def build_load_rip_shellcode(disable_bytes, available_regs, func_ptr_reg):
    check, reg, shellcode = load_rip_shellcode1(disable_bytes, available_regs)
    if check:
        return reg, shellcode
    
    check, reg, shellcode = load_rip_shellcode2(disable_bytes, available_regs, func_ptr_reg)
    if check:
        return reg, shellcode
    
    check, reg, shellcode = load_rip_shellcode3(disable_bytes, available_regs, func_ptr_reg)
    if check:
        return reg, shellcode
    
    check, reg, shellcode = load_rip_shellcode4(disable_bytes, available_regs, func_ptr_reg)
    if check:
        return reg, shellcode
    
    return '', ''



def build_xor_shellcode(disable_bytes, main_shellcode, rip_reg, load_rip_shellcode):
    offset = 0
    shellcode = ''

    for i in range(0x7f, -1, -1):
        if not i in disable_bytes:
            biggest_offset = i
            break

    main_shellcode_asm = bytearray(asm(main_shellcode))

    if 0x80 in disable_bytes:
        print('0x80 has been banned')
        sys.exit()

    for i in range(len(main_shellcode_asm)):
        if offset > 0x7f:
            shellcode += f'lea {rip_reg}, [{rip_reg} + {biggest_offset}]\n'
            offset -= 0x7f

        if not main_shellcode_asm[i] in disable_bytes:
            offset += 1
            continue

        if offset in disable_bytes:
            for j in range(-0x80, 0x80):
                if ((offset - j) < 0) or ((offset - j) > 0x7f):
                    continue

                if not (offset - j) in disable_bytes:
                    break

            offset -= j
            shellcode += f'lea {rip_reg}, [{rip_reg} + {j}]\n'

        for j in range(256):
            if (j in disable_bytes) or ((j ^ main_shellcode_asm[i]) in disable_bytes):
                continue
            break

        shellcode += f'xor byte ptr [{rip_reg} + {offset}], {j}\n'
        main_shellcode_asm[i] ^= j
        offset += 1

    shellcode_length = len(asm(load_rip_shellcode) + asm(shellcode))
    while True:
        if (shellcode_length + 4) < 0x80:
            break
        shellcode = f'lea {rip_reg}, [{rip_reg} + {biggest_offset}]\n' + shellcode
        shellcode_length -= biggest_offset
        shellcode_length += 4

    if shellcode_length != 0:
        shellcode_length += 4
        if shellcode_length in disable_bytes:
            shellcode_length += 4
            for i in range(1, shellcode_length):
                if (i in disable_bytes) or ((shellcode_length - i) in disable_bytes):
                    continue

                shellcode = f'lea {rip_reg}, [{rip_reg} + {i}]\n' + shellcode
                shellcode = f'lea {rip_reg}, [{rip_reg} + {shellcode_length - i}]\n' + shellcode

        else:
            shellcode = f'lea {rip_reg}, [{rip_reg} + {shellcode_length}]\n' + shellcode

    return shellcode, bytes(main_shellcode_asm)



# ===========================



main_shellcode = '''
    lea rax, [rdi + rsi]
    ret
'''



disable_bytes = list({73, 195, 72, 4, 0, 89, 194, 195})
available_regs = ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
func_ptr_reg = 'rcx'

rip_reg, load_rip_shellcode = build_load_rip_shellcode(disable_bytes, available_regs, func_ptr_reg)
xor_shellcode, main_shellcode_asm = build_xor_shellcode(disable_bytes, main_shellcode, rip_reg, load_rip_shellcode)

shellcode_asm = asm(load_rip_shellcode) + asm(xor_shellcode) + main_shellcode_asm


for byte in shellcode_asm:
    if byte in disable_bytes:
        print('Failed')


open('asm1.bin', 'wb').write(shellcode_asm)