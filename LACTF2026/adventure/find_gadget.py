from capstone import *
from elftools.elf.elffile import ELFFile

binary_path = "chall"
max_gap = 3    
context = 5  

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

with open(binary_path, "rb") as f:
    elf = ELFFile(f)
    text = elf.get_section_by_name(".text")
    base = text['sh_addr']
    code = text.data()

insns = list(md.disasm(code, base))

def print_block(start_idx):
    start = max(0, start_idx - context)
    end = min(len(insns), start_idx + context)
    for i in range(start, end):
        print(f"0x{insns[i].address:x}: {insns[i].mnemonic:8} {insns[i].op_str}")
    print("-" * 60)

for i, insn in enumerate(insns):
    if insn.mnemonic == "mov" and insn.op_str.startswith("rdi"):
        # check next few instructions
        for j in range(1, max_gap+1):
            if i + j >= len(insns):
                break
            next_insn = insns[i + j]
            # if next_insn.mnemonic == "puts" and "[" in next_insn.op_str:
            print(f"\n[*] Found match at 0x{insn.address:x} → call at 0x{next_insn.address:x}")
            print_block(i)
            # break