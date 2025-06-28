#ifndef X86_64_LENGTH_DISASSEMBLER_H
#define X86_64_LENGTH_DISASSEMBLER_H

#define INSTRUCTION_INVALID -1
int InstructionSize_x86_64(const uint8_t *const Bytes, size_t Length);

#endif
