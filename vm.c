#include <stdio.h>
#include "stdlib.h"
#include <sys/mman.h>
#include <stdint.h>

#define AVAILABLE_MEMORY (1 << 16)

enum TrapCode {
    GETC,
    OUT,
    PUTS,
    IN,
    PUTSP,
    HALT
};

enum Register {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    COND,
    NUM_REGISTERS
};

enum ConditionCode {
    N,  /* negative */
    Z,  /* zero */
    P,  /* positive */
};

enum Opcode {
    BR,
    ADD,
    LD,
    ST,
    JSR,
    AND,
    LDR,
    STR,
    RTI,
    NOT,
    LDI,
    STI,
    JMP,
    _,
    LEA,
    TRAP
};

enum MmappedRegister{
    KBSR = 0xFE00,
    KBDR = 0xFE02
};

uint16_t registers[NUM_REGISTERS];
uint16_t memory[AVAILABLE_MEMORY] = {
        [0x20] = GETC,
        [0x21] = OUT,
        [0x22] = PUTS,
        [0x23] = IN,
        [0x24] = PUTSP,
        [0x25] = HALT
};

static inline uint16_t swap_bytes(uint16_t num)
{
    return (num >> 8) | (num << 8);
}

static inline uint16_t sext(uint16_t num, unsigned char bits)
{
    if (num & (1 <<  (bits - 1)))
        return num | (0xFFFF << bits);
    return num;
}

static inline void setcc(enum Register reg)
{
    if (registers[reg] == 0) registers[COND] = Z;
    else if (registers[reg] >> 15) registers[COND] = N;
    else registers[COND] = P;
}

static inline void memset(uint16_t idx, uint16_t data)
{
    memory[idx] = data;
}

static inline uint16_t memread(uint16_t addr)
{
    if (addr == KBSR)
    {
        memory[KBDR] = getchar();
        memory[KBSR] = 1 << 15;
    }
    else
    {
        memory[KBSR] = 0;
    }
    return memory[addr];
}

uint16_t read_img(char *path)
{
    uint16_t origin;
    FILE *fp = fopen(path, "rb");

    fread(&origin, sizeof(uint16_t), 1, fp);
    origin = swap_bytes(origin);

    size_t read = fread(memory+origin, sizeof(uint16_t), AVAILABLE_MEMORY - origin, fp);
    uint16_t *p = memory + origin;

    for (; read > 0; read--, p++)
        *p = swap_bytes(*p);

    return origin;
}

int main(int argc, char **argv)
{
    uint16_t PC = read_img(argv[1]);
    char run = 1;

    while (run)
    {
        uint16_t instr = memread(PC++);
        unsigned char opcode = (instr >> 12) & 0xF;

        switch (opcode)
        {
            case BR:
                {
                   if (
                           (((1 << 11) & instr) && registers[COND] == N)
                           || (((1 << 10) & instr) && registers[COND] == Z)
                           || (((1 << 9) & instr) && registers[COND] == P)
                           )
                   {
                       PC += sext(instr & 0x1FF, 9);
                   }
                }
                break;
            case JMP:
                {
                    uint16_t base_r = (instr >> 6) & 0x7;
                    PC = registers[base_r];
                }
                break;
            case LDI:
                {
                    uint16_t dr = (instr >> 9) & 0x7;
                    uint16_t pc_offset_9 = sext(instr & 0x1FF, 9);
                    registers[dr] = memread(memread(PC + pc_offset_9));
                    setcc(dr);
                }
                break;
            case LDR:
                {
                    uint16_t dr = (instr >> 9) & 0x7;
                    uint16_t base_r = (instr >> 6) & 0x7;
                    uint16_t offset6 = sext(instr & 0x3F, 6);
                    registers[dr] = memread(registers[base_r] + offset6);
                    setcc(dr);
                }
                break;
            case NOT:
                {
                    uint16_t dr = (instr >> 9) & 0x7;
                    uint16_t sr = (instr >> 6) & 0x7;
                    registers[dr] = ~registers[sr];
                    setcc(dr);
                }
                break;
            case ST:
                {
                    uint16_t sr = (instr >> 9) & 0x7;
                    uint16_t pc_offset9 = sext(instr & 0x1FF, 9);
                    memset(PC + pc_offset9, registers[sr]);
                }
                break;
            case STI:
                {
                    uint16_t sr = (instr >> 9) & 0x7;
                    uint16_t pc_offset9 = sext(instr & 0x1FF, 9);
                    memset(memread(PC + pc_offset9), registers[sr]);
                }
                break;
            case STR:
                {
                    uint16_t sr = (instr >> 9) & 0x7;
                    uint16_t base_r = (instr >> 6) & 0x7;
                    uint16_t offset6 = sext(instr & 0x3F, 6);
                    memset(registers[base_r] + offset6, registers[sr]);
                }
                break;
            case ADD:
                {
                    uint16_t dr = (instr >> 9) & 0x7;
                    uint16_t sr1 = (instr >> 6) & 0x7;
                    if ((1 << 5) & instr)
                        registers[dr] = registers[sr1] + sext(instr & 0x1F, 5);
                    else
                        registers[dr] = registers[sr1] + registers[instr & 0x7];
                    setcc(dr);
                }
                break;
            case AND:
                {
                    uint16_t dr = (instr >> 9) & 0x7;
                    uint16_t sr1 = (instr >> 6) & 0x7;
                    if ((1 << 5) & instr)
                        registers[dr] = registers[sr1] & sext(instr & 0x1F, 5);
                    else
                        registers[dr] = registers[sr1] & registers[instr & 0x7];
                    setcc(dr);
                }
                break;
            case LEA:
                {
                    uint16_t dr = (instr >> 9) & 0x7;
                    uint16_t pc_offset_9 = sext(instr & 0x1FF, 9);
                    registers[dr] = PC + pc_offset_9;
                    setcc(dr);
                }
                break;
            case LD:
                {
                    uint16_t dr = (instr >> 9) & 0x7;
                    uint16_t pc_offset_9 = sext(instr & 0x1FF, 9);
                    registers[dr] = memread(PC + pc_offset_9);
                    setcc(dr);
                }
                break;
            case TRAP:
                {
                    registers[R7] = PC;
                    uint16_t trapvect8 = instr & 0xFF;
                    PC = memread(trapvect8);

                    switch (PC)
                    {
                        case HALT:
                            {
                                run = 0;
                            }
                            break;
                        case PUTS:
                            {
                                uint16_t *ptr = memory + registers[R0];
                                while(*ptr != 0x0000)
                                    putc((char)*ptr++, stdout);
                            }
                            break;
                        case GETC:
                            {
                                registers[R0] = getchar() & 0xFF;
                            }
                        case OUT:
                            {
                                printf("%c", (char)registers[R0]);
                            }
                            break;
                        case IN:
                        case PUTSP:
                        default:
                            printf("Unknown trap routine %04x\n", PC);
                            exit(1);
                    }

                    PC = registers[R7];
                }
                break;
            case JSR:
                {
                    registers[R7] = PC;

                    if (instr & (1 << 11))
                        PC += sext(instr & 0x7FF, 11);
                    else
                    {
                        uint16_t base_r = (instr >> 6) & 0x7;
                        PC = registers[base_r];
                    }
                }
                break;
            default:
                printf("Unknown opcode %04x\n", opcode);
                exit(1);
        }

        fflush(stdout);
    }

    return 0;
}
