"""tiny safe x86-64 disassembler for a benign fixture."""

def disassemble_x86(code: bytes, base: int = 0x1000) -> list[dict]:
    output, index = [], 0
    while index < len(code):
        address = base + index
        if code[index] == 0x55: mnemonic, size = "push rbp", 1
        elif code[index:index + 3] == b"\x48\x89\xe5": mnemonic, size = "mov rbp, rsp", 3
        elif code[index] == 0xC3: mnemonic, size = "ret", 1
        elif code[index] == 0x90: mnemonic, size = "nop", 1
        elif code[index] == 0xB8 and index + 5 <= len(code): mnemonic, size = f"mov eax, 0x{int.from_bytes(code[index + 1:index + 5], 'little'):x}", 5
        else: mnemonic, size = f"db 0x{code[index]:02x}", 1
        output.append({"address": hex(address), "bytes": code[index:index + size].hex(), "mnemonic": mnemonic})
        index += size
    return output
