#! /usr/bin/python3

import sys
from dataclasses import dataclass

from typing import List, Callable

whitespaces = {'\n', ' ', '\t'}
TOKENS = {',', ';'}
DIRECTIVES = {'.ORIG', '.STRINGZ', '.FILL', '.END'}
OPCODES = {'ADD', 'AND', 'LD', 'ST', 'JSR', 'LDR', 'STR', 'RTI', 'NOT', 'LDI', 'STI', 'JMP', 'LEA', 'TRAP'}
INSTRUCTIONS = {'ADD', 'AND', 'LD', 'ST', 'JSR', 'LDR', 'STR', 'RTI', 'NOT', 'LDI', 'STI', 'JMP', 'LEA', 'TRAP',
                'BRnzp', 'BRp', 'BRz', 'BRn', 'BRnz', 'RET', 'BRnp', 'BRzp'}
TRAPS = {'GETC', 'PUTC', 'PUTS', 'IN', 'HALT', 'OUT'}
REGISTERS = {'R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7'}


class SymTable:
    def __init__(self):
        self.label_to_addr = {}
        self.addr_to_label = {}

    def insert(self, label, addr):
        if self.label_to_addr.get(label):
            raise Exception("Duplicated label %s" % label)
        if dup := self.addr_to_label.get(addr):
            raise Exception("Multiple labels pointing to same address: '%s', '%s'" % (dup, label))
        self.label_to_addr[label] = addr
        self.addr_to_label[addr] = label

    def get(self, label):
        if (addr := self.label_to_addr.get(label, -1)) == -1:
            raise Exception("unknown label: %s" % label)
        return addr

    def __repr__(self):
        string = ""
        for k, v in self.label_to_addr.items():
            string += f'{k}, {"x%04X" % v}\n'
        return string


@dataclass
class Token:
    value: str
    line: int
    column: int

    def __repr__(self):
        return f"{self.value}"


def tokenize(path):
    tokens = []

    with open(path, "r") as file:
        lines = file.readlines()
        for lineno, line in enumerate(lines):
            columno = 0
            l = []
            while columno < len(line):
                if line[columno] == ';':
                    break
                if line[columno] in whitespaces:
                    pass
                elif line[columno] == ',':
                    l.append(Token(value=',', line=lineno, column=columno))
                elif line[columno] == "\"":
                    string = ''
                    start = columno
                    columno += 1
                    while columno < len(line) and line[columno] != "\"":
                        if line[columno] == '\\':
                            columno += 1
                            if line[columno] == "n":
                                string += "\n"
                            else:
                                string += "e"
                            columno += 1
                        else:
                            string += line[columno]
                            columno += 1
                    assert columno < len(line) and line[columno] == "\"", "malformed string"
                    l.append(Token(value=string, line=lineno, column=start))
                else:
                    tok = ''
                    start = columno
                    while columno < len(line) and line[columno] not in TOKENS and line[columno] not in whitespaces:
                        tok += line[columno]
                        columno += 1
                    l.append(Token(value=tok, line=lineno, column=start))
                    continue

                columno += 1
            if l:
                tokens.append(l)
    return tokens


def is_instr(token: Token):
    return token.value in INSTRUCTIONS


def is_directive(token: Token):
    return token.value in DIRECTIVES


def is_trap(token: Token):
    return token.value in TRAPS


def is_valid_label(label: str):
    return True


def build_table(tokens, addr):
    instructions = []

    def process_line(line, labeled=False):
        nonlocal addr

        if not line:
            return

        first = line[0]

        if is_label(first):
            if not is_valid_label(first.value):
                raise Exception("invalid token: %s" % first.value)
            symtable.insert(first.value, addr)
            if not labeled:
                process_line(line[1:], True)

        elif is_directive(first):
            if first.value == ".STRINGZ":
                string = line[1].value
                instructions.append(STRINGZ(line, addr))
                addr += len(string) + 1
            elif first.value == '.END':
                return instructions
            else:
                handler = DIRECTIVE_HANDLERS.get(first.value)
                instr = handler(line, addr)
                if instr.is_valid():
                    instructions.append(instr)
                addr += 1
        elif is_trap(first):
            handler = TRAP_HANDLERS.get(first.value)
            instr = handler(line, addr)
            if instr.is_valid():
                instructions.append(instr)

            addr += 1
        elif is_instr(first):
            handler = INSTRUCTION_HANDLERS.get(first.value)
            instr = handler(line, addr)
            if instr.is_valid():
                instructions.append(instr)
            addr += 1
        else:
            raise Exception("unknown token: %s" % first.value)

    for line in tokens:
        process_line(line, False)

    return instructions


INSTRUCTION_TO_BINARY = {
    'LEA': 0xE,
    'LDR': 0x6,
    'TRAP': 0xF,
    'JSR': 0x4,
    'ADD': 0x1,
    'AND': 0x5,
    'LDI': 0xA,
    'STR': 0x7,
    'STI': 0xB,
    'BR': 0x0,
    'LD': 0x2,
    'ST': 0x3,
    'RET': 0xC,
    'JMP': 0xC,
    'NOT': 0x9
}

symtable = SymTable()


class BaseAsmInstruction:
    instruction: str = None
    validators: List[Callable[[List[Token]], bool]] = []

    def __init__(self, tokline: List[Token], addr: int):
        self.tokline = tokline
        self.addr = addr

    def parse_asm_number(self, tok: Token) -> int:
        if not is_asm_number(tok):
            return symtable.get(tok.value) - self.addr - 1
        numstr = tok.value
        if numstr.startswith("#"):
            return int(numstr[1:])
        return int("0" + numstr, 16)

    def is_valid(self):
        for validator in self.validators:
            if not validator(self.tokline):
                raise Exception
        return True

    def to_int(self) -> int:
        raise NotImplementedError

    def to_binary(self) -> bytes:
        return self.to_int().to_bytes(2, 'big')

    def opcode_binary(self):
        return INSTRUCTION_TO_BINARY[self.instruction]

    def __repr__(self):
        return f"<instruction '{self.instruction}' at {'x%04x' % self.addr}>"


def is_instruction_validator(tokline: List[Token]):
    return tokline[0].value in INSTRUCTIONS


def single_argument_validator(tokline: List[Token]):
    return len(tokline) == 2  # instruction + 1 operand


def double_argument_validator(tokline: List[Token]):
    return len(tokline) == 4 and tokline[2].value == ','


def triple_argument_validator(tokline: List[Token]):
    return len(tokline) == 6 and tokline[2].value == ',' and tokline[4].value == ','


def first_argument_register_validator(tokline: List[Token]):
    return tokline[1].value in REGISTERS


def first_argument_address_validator(tokline: List[Token]):
    return is_label(tokline[1]) or is_asm_number(tokline[1])


def second_argument_register_validator(tokline: List[Token]):
    return tokline[3].value in REGISTERS


def is_label(token: Token):
    return token.value not in DIRECTIVES and token.value not in INSTRUCTIONS and token.value not in TRAPS


def second_argument_address_validator(tokline: List[Token]):
    return is_label(tokline[3]) or is_asm_number(tokline[3])


REGISTER_CODES = {
    'R0': 0,
    'R1': 1,
    'R2': 2,
    'R3': 3,
    'R4': 4,
    'R5': 5,
    'R6': 6,
    'R7': 7,
}


def second_argument_number_validator(tokline: List[Token]):
    return is_asm_number(tokline[3]) or is_label(tokline[3])


def third_argument_numer_validator(tokline: List[Token]):
    return is_asm_number(tokline[5]) or is_label(tokline[5])


def is_asm_number(token: Token):
    num = token.value
    return num.startswith("x") or num.startswith("#")


def parse_asm_number(tok: Token) -> int:
    if not is_asm_number(tok):
        return symtable.get(tok.value)
    numstr = tok.value
    if numstr.startswith("#"):
        return int(numstr[1:])
    return int("0" + numstr, 16)


class DrSrPCoffset9(BaseAsmInstruction):
    validators = [
        double_argument_validator,
        first_argument_register_validator,
        second_argument_number_validator
    ]

    def to_int(self) -> int:
        dr = REGISTER_CODES[self.tokline[1].value]
        off = self.parse_asm_number(self.tokline[3]) & 0x1FF
        return self.opcode_binary() << 12 | dr << 9 | off


class LD(DrSrPCoffset9):
    instruction = 'LD'


class LEA(DrSrPCoffset9):
    instruction = 'LEA'


class LDI(DrSrPCoffset9):
    instruction = 'LDI'


class ST(DrSrPCoffset9):
    instruction = 'ST'


class STI(DrSrPCoffset9):
    instruction = 'STI'


class SrBaseROffset6(BaseAsmInstruction):
    validators = [
        triple_argument_validator,
        first_argument_register_validator,
        second_argument_register_validator,
        third_argument_numer_validator
    ]

    def to_int(self) -> int:
        sr = REGISTER_CODES[self.tokline[1].value]
        base_r = REGISTER_CODES[self.tokline[3].value]
        off = parse_asm_number(self.tokline[5])

        return self.opcode_binary() << 12 | sr << 9 | base_r << 6 | off & 0x3F


class LDR(SrBaseROffset6):
    instruction = 'LDR'


class STR(SrBaseROffset6):
    instruction = 'STR'


class DrSr1Imm5Sr2(BaseAsmInstruction):
    validators = [
        triple_argument_validator,
        first_argument_register_validator,
        second_argument_register_validator
    ]

    def to_int(self) -> int:
        dr = REGISTER_CODES[self.tokline[1].value]
        sr1 = REGISTER_CODES[self.tokline[3].value]
        num = self.opcode_binary() << 12 | dr << 9 | sr1 << 6
        dst = self.tokline[5]
        if is_asm_number(dst):
            # immediate
            num |= 1 << 5 | parse_asm_number(dst) & 0x1F
        else:
            num |= REGISTER_CODES[dst.value]
        return num


class ADD(DrSr1Imm5Sr2):
    instruction = 'ADD'


class AND(DrSr1Imm5Sr2):
    instruction = 'AND'


class BaseR(BaseAsmInstruction):
    validators = [
        single_argument_validator,
        first_argument_register_validator
    ]

    def to_int(self) -> int:
        base_r = REGISTER_CODES[self.tokline[1]]
        return self.opcode_binary() << 12 | base_r << 6


class JSRR(BaseR):
    instruction = 'JSRR'


class JMP(BaseR):
    instruction = 'JMP'


TRAP_CODES = {
    'PUTS': 0x22,
    'HALT': 0x25,
    'OUT': 0x21,
    'GETC': 0x20
}


class Trap(BaseAsmInstruction):
    instruction = 'TRAP'
    name = None

    def to_int(self) -> int:
        return self.opcode_binary() << 12 | TRAP_CODES[self.name]

    def __repr__(self):
        return f"<trap routine '{self.name}' at {'x%04x' % self.addr}>"


class PUTS(Trap):
    name = 'PUTS'


class HALT(Trap):
    name = 'HALT'


class Directive(BaseAsmInstruction):
    name = None

    def to_int(self) -> int:
        pass

    def __repr__(self):
        return f"<directive '{self.name}' at {'x%04x' % self.addr}>"


class STRINGZ(Directive):
    name = '.STRINGZ'
    validators = [
        single_argument_validator
    ]

    def to_binary(self) -> bytes:
        bstring = bytearray()
        for char in self.tokline[1].value:
            bstring += ord(char).to_bytes(2, 'big')
        return bstring + b'\0\0'


class JSR(BaseAsmInstruction):
    instruction = 'JSR'

    validators = [
        single_argument_validator
    ]

    def to_int(self) -> int:
        return self.opcode_binary() << 12 | 1 << 11 | self.parse_asm_number(self.tokline[1]) & 0x7FF


class FILL(Directive):
    name = '.FILL'

    def to_binary(self) -> bytes:
        value = parse_asm_number(self.tokline[1])
        return value.to_bytes(2, 'big')


class RET(BaseAsmInstruction):
    instruction = 'RET'

    def to_int(self) -> int:
        return self.opcode_binary() << 12 | REGISTER_CODES['R7'] << 6


class Branch(BaseAsmInstruction):
    validators = [
        single_argument_validator,
        first_argument_address_validator
    ]

    instruction = 'BR'
    pattern = 0

    def to_int(self) -> int:
        addr = self.parse_asm_number(self.tokline[1])
        return self.opcode_binary() << 12 | self.pattern << 9 | addr & 0x1FF

    def __repr__(self):
        conds = {1: 'p', 2: 'z', 4: 'n', 3: 'zp', 6: 'nz', 7: 'nzp', 5: 'np'}
        return f"<instruction 'BR{conds[self.pattern]}' at {'x%04x' % self.addr}"


class BR(Branch):
    instruction = 'BR'


class BRn(Branch):
    pattern = 4


class BRz(Branch):
    pattern = 2


class BRp(Branch):
    pattern = 1


class BRzp(Branch):
    pattern = BRz.pattern | BRp.pattern


class BRnp(Branch):
    pattern = BRn.pattern | BRp.pattern


class BRnz(Branch):
    pattern = BRn.pattern | BRz.pattern


class BRnzp(Branch):
    pattern = BRn.pattern | BRz.pattern | BRp.pattern


class NOT(BaseAsmInstruction):
    instruction = 'NOT'
    validators = [
        first_argument_register_validator,
        second_argument_register_validator
    ]

    def to_int(self) -> int:
        dr = REGISTER_CODES[self.tokline[1].value]
        sr = REGISTER_CODES[self.tokline[3].value]
        return self.opcode_binary() << 12 | dr << 9 | sr << 6 | 0x3F


class OUT(Trap):
    name = 'OUT'


class GETC(Trap):
    name = 'GETC'


INSTRUCTION_HANDLERS = {
    'NOT': NOT,
    'LEA': LEA,
    'JSR': JSR,
    'ADD': ADD,
    'AND': AND,
    'LDI': LDI,
    'LD': LD,
    'ST': ST,
    'STI': STI,
    'JMP': JMP,
    'JSRR': JSRR,
    'LDR': LDR,
    'STR': STR,
    'RET': RET,
    'BRp': BRp,
    'BRn': BRn,
    'BRz': BRz,
    'BRzp': BRzp,
    'BRnz': BRnz,
    'BRnp': BRnp,
    'BRnzp': BRnzp
}

TRAP_HANDLERS = {
    'PUTS': PUTS,
    'HALT': HALT,
    'OUT': OUT,
    'GETC': GETC
}

DIRECTIVE_HANDLERS = {
    '.STRINGZ': STRINGZ,
    '.FILL': FILL
}


def assemble(path):
    file = open("program.obj", "wb")
    tokens = tokenize(path)
    assert len(tokens) and tokens[0][0].value == '.ORIG', "no .ORIG found"
    addr = parse_asm_number(tokens[0][1])
    file.write(addr.to_bytes(2, 'big'))
    instructions = build_table(tokens[1:], addr)
    print(symtable)
    for instr in instructions:
        file.write(instr.to_binary())
    file.close()


if __name__ == '__main__':
    assemble(sys.argv[1])
