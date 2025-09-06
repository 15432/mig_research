import os
from binascii import unhexlify as uhx, hexlify as hx
import re
import struct

host_calls_0 = {
    0x7BB8B585 : "host_spi_write",
    0x48B3DD8A : "host_aes_128_enc_init",
    0x13BE49F4 : "host_unk0",
    0x0CAB2405 : "host_unk1",
    0x056FFD32 : "host_unk2",
    0x0DF75FEC : "host_unk3",
    0x120F4645 : "host_spi_read",
    0x3F0CA432 : "host_fpga_write",
    0x1FFA884D : "host_led_blink",
    0x2E931656 : "host_aes_run",
    0x45571C27 : "host_unk4",
    0x479A273A : "host_get_random",
    0x6A891CDA : "host_load_xci",
    0x5B14BE2D : "host_unk5",
    0x52F924A0 : "host_unk6",
    0x5D23B296 : "host_unk7",
    0x5FB9543D : "host_unk8",
    0x6D496E0A : "host_unk9",
    0x6B988933 : "host_fpga_read",
    0x6BD8B7A3 : "host_memcpy",
    0x71BDFC29 : "host_memset",
    0x72519F98 : "host_unk10",
    0xBBC8993D : "host_decrypt_hwkey",
    0xA2D44440 : "host_unk11",
    0x9E665D6A : "host_aes_128_dec_init",
    0x963266B3 : "host_unk12",
    0x9ED00ECB : "host_unk13",
    0xA195DA89 : "host_unk14",
    0xB3214192 : "host_unk15",
    0xA4A413C4 : "host_set_vm_result",
    0xA929C445 : "host_file_open",
    0xB63779DA : "host_unk16",
    0xB9019911 : "host_parse_update",
    0xDEA4B7A4 : "host_unk17",
    0xD7EFFB7B : "host_unk18",
    0xD72017AD : "host_memcmp",
    0xD8E5ABB3 : "host_sha256_calc",
    0xDD351C3A : "host_unk19",
    0xF4BEA356 : "host_unk20",
    0xE3B309F2 : "host_unk21",
    0xF40B315B : "host_file_read",
    0xF8298D5C : "host_unk22",
    0xF97CC294 : "host_unk23",
}

xor_block = uhx(re.sub(r"\W", "", """
F0 A4 46 B0 C6 B1 9A E0 81 83 F8 0A 0A CE B3 4A 
56 57 BF 88 81 1E 7D 7A 0C D1 AE B4 C1 58 A3 B3 
64 BE 39 BC F1 72 2E 7E 66 12 6B D2 8C 69 04 3A 
CB 84 52 FB F1 AC 98 F0 94 92 6F E9 BD 83 E6 7E 
51 12 55 A5 4B B2 73 39 55 BB 96 A5 B8 0B FD 49 
42 33 5F 61 8D 16 2D B9 57 26 21 A0 23 C3 D0 B6 
59 51 6A 5E BD A8 3C 77 1B DB CE D2 C5 ED 36 C1 
2D B9 68 3F 44 BC FB 70 88 7D 74 F2 9E 70 4E FF 
F3 19 72 9E 32 06 91 BF D9 42 47 EE 1C 3B B8 D9 
BB CF 0C C7 29 EC F2 A3 E2 46 6B EC 68 41 4C DA 
2C 9D 05 02 F0 6D F8 24 41 7E 5E B6 78 37 18 95 
1D EB FB 27 8F 34 A1 B1 7D 3B C8 87 51 E7 D0 BB 
68 09 D2 8F 42 38 D1 01 81 93 CB 0E 7D 1B ED B8 
0A 0E 58 CF D9 FC 3E C6 0D 6A F5 41 DC 7D C7 11 
BD D5 B3 88 02 8D 74 87 A2 FD 2C 52 20 B5 8B D5 
D2 41 BF 36 5E 5F C4 85 90 37 9E 7F 67 CA 87 10
"""))

rnam = [
    "$zero", 
    "$at", 
    "$v0", "$v1", 
    "$a0", "$a1", "$a2", "$a3", 
    "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", 
    "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7", 
    "$t8", "$t9", 
    "$k0", "$k1", 
    "$gp", 
    "$sp", 
    "$fp", 
    "$ra", 
]

def vm_get_word(p, i):
    xi = (i & 0xFF)
    x = struct.unpack("I", xor_block[xi : xi + 4])[0]
    y = struct.unpack("I", p[i : i + 4])[0]
    return x ^ y

def str_simm16(imm):
    return "{0}0x{1:X}".format("-" if imm < 0 else "", -imm if imm < 0 else imm)

def decode_simm16(imm):
    return -(0xFFFF - imm + 1) if imm & 0x8000 else imm

def vm_dis(p, code_size, data_size, version):
    jal_targ = []
    b_targ = []
    lis_val = [-1] * 32
    lines = [[""] for i in range(0, len(p), 4)]
    for i in range(0, len(p), 4):
        if i < code_size:
            lines[i//4].append("{0:04X}\t\t".format(i))
            inst = vm_get_word(p, i)
            op = inst >> 26
            if ((version == 0) and (op == 0x19)):
                dst_reg = (inst >> 16) & 0x1F
                src_reg = (inst >> 21) & 0x1F
                off = decode_simm16(inst & 0xFFFF)
                lines[i//4].append("lbu {0}, [{1} + {2}]".format(rnam[dst_reg], rnam[src_reg], str_simm16(off)))
            elif ((version == 0) and (op == 0x2D)):
                dst_reg = (inst >> 16) & 0x1F
                src_reg = (inst >> 21) & 0x1F
                imm = inst & 0xFFFF
                lines[i//4].append("xori {0}, {1}, 0x{2:X}".format(rnam[dst_reg], rnam[src_reg], imm))
            elif ((version == 0) and (op == 0x23)):
                dst_reg = (inst >> 16) & 0x1F
                src_reg = (inst >> 21) & 0x1F
                off = decode_simm16(inst & 0xFFFF)
                lines[i//4].append("lh {0}, [{1} + {2}]".format(rnam[dst_reg], rnam[src_reg], str_simm16(off)))
            elif ((version == 0) and (op == 0x1E)):
                dst_reg = (inst >> 16) & 0x1F
                src_reg = (inst >> 21) & 0x1F
                off = decode_simm16(inst & 0xFFFF)
                lines[i//4].append("lw {0}, [{1} + {2}]".format(rnam[dst_reg], rnam[src_reg], str_simm16(off)))
            elif ((version == 0) and (op == 0x21)):
                dst_reg = (inst >> 21) & 0x1F
                src_reg = (inst >> 16) & 0x1F
                off = decode_simm16(inst & 0xFFFF)
                lines[i//4].append("sw [{0} + {1}], {2}".format(rnam[dst_reg], str_simm16(off), rnam[src_reg]))
            elif ((version == 0) and (op == 0x36)):
                dst_reg = (inst >> 16) & 0x1F
                src_reg = (inst >> 21) & 0x1F
                off = decode_simm16(inst & 0xFFFF)
                lines[i//4].append("lhu {0}, [{1} + {2}]".format(rnam[dst_reg], rnam[src_reg], str_simm16(off)))
            elif ((version == 0) and (op == 0x33)):
                imm = 4 * (inst & 0x3FFFFFF)
                lines[i//4].append("j loc_{0:X}".format(imm))
                b_targ.append(imm)
            elif ((version == 0) and (op == 0x35)):
                dst_reg = (inst >> 21) & 0x1F
                src_reg = (inst >> 16) & 0x1F
                off = decode_simm16(inst & 0xFFFF)
                lines[i//4].append("sh [{0} + {1}], {2}".format(rnam[dst_reg], str_simm16(off), rnam[src_reg]))
            elif ((version == 0) and (op == 0x30)):
                dst_reg = (inst >> 16) & 0x1F
                imm = (inst << 16) & 0xFFFF0000
                lines[i//4].append("lui {0}, 0x{1:X}".format(rnam[dst_reg], imm >> 16))
                lis_val[dst_reg] = imm
            elif ((version == 0) and (op == 0x3B)):
                reg1 = (inst >> 16) & 0x1F
                reg2 = (inst >> 21) & 0x1F
                off = decode_simm16(inst & 0xFFFF)
                lines[i//4].append("bnec {0}, {1}, loc_{2:X}".format(rnam[reg1], rnam[reg2], i + 4 * off))
                b_targ.append(i + 4 * off)
            elif ((version == 0) and ((op == 0x3C) or (op == 0x13))):
                dst_reg = (inst >> 16) & 0x1F
                src_reg = (inst >> 21) & 0x1F
                imm = inst & 0xFFFF
                lines[i//4].append("sltiu {0}, {1}, 0x{2:X}".format(rnam[dst_reg], rnam[src_reg], imm))
            elif ((version == 0) and (op == 0x38)):
                reg1 = (inst >> 16) & 0x1F
                reg2 = (inst >> 21) & 0x1F
                off = decode_simm16(inst & 0xFFFF)
                lines[i//4].append("beq {0}, {1}, loc_{2:X}".format(rnam[reg1], rnam[reg2], i + 4 * off))
                b_targ.append(i + 4 * off)
            elif ((version == 0) and (op == 0x29)):
                reg = (inst >> 21) & 0x1F
                off = inst & 0xFFFF
                lines[i//4].append("bgtz {0}, loc_{1:X}".format(rnam[reg], i + 4 * off))
                b_targ.append(i + 4 * off)
            elif ((version == 0) and (op == 0x2A)):
                imm = 4 * (inst & 0x3FFFFFF)
                lines[i//4].append("jal sub_{0:X}".format(imm))
                jal_targ.append(imm)
            elif ((version == 0) and (op == 0x25)):
                reg = (inst >> 21) & 0x1F
                off = inst & 0xFFFF
                lines[i//4].append("bgtzc {0}, loc_{1:X}".format(rnam[reg], i + 4 * off))
                b_targ.append(i + 4 * off)
            elif ((version == 0) and (op == 0xC)):
                reg1 = (inst >> 16) & 0x1F
                reg2 = (inst >> 21) & 0x1F
                off = decode_simm16(inst & 0xFFFF)
                lines[i//4].append("bne {0}, {1}, loc_{2:X}".format(rnam[reg1], rnam[reg2], i + 4 * off))
                b_targ.append(i + 4 * off)
            elif ((version == 0) and (op == 0x10)):
                reg = (inst >> 21) & 0x1F
                off = inst & 0xFFFF
                lines[i//4].append("blezc {0}, loc_{1:X}".format(rnam[reg], i + 4 * off))
                b_targ.append(i + 4 * off)
            elif ((version == 0) and (op == 0x12)):
                dst_reg = (inst >> 11) & 0x1F
                src1_reg = (inst >> 21) & 0x1F
                src2_reg = (inst >> 16) & 0x1F
                lines[i//4].append("mul {0}, {1}, {2}".format(rnam[dst_reg], rnam[src1_reg], rnam[src2_reg]))
            elif ((version == 0) and (op == 0xE)):
                lines[i//4].append("TODO op 0x{0:X}".format(op))
            elif ((version == 0) and (op == 0x16)):
                dst_reg = (inst >> 16) & 0x1F
                src_reg = (inst >> 21) & 0x1F
                imm = inst & 0xFFFF
                lines[i//4].append("ori {0}, {1}, 0x{2:X}".format(rnam[dst_reg], rnam[src_reg], imm))
                if dst_reg == src_reg and lis_val[dst_reg] != -1:
                    val = lis_val[dst_reg] | imm
                    lis_val[dst_reg] = -1
                    lines[i//4].append("; = 0x{0:X}".format(val))
                    if dst_reg == 2:
                        if ((version == 0) and (val in host_calls_0)):
                            lines[i//4].append(" - {0}".format(host_calls_0[val]))
                        else:
                            lines[i//4].append(" - UNK")
            elif ((version == 0) and (op == 0x15)):
                dst_reg = (inst >> 16) & 0x1F
                src_reg = (inst >> 21) & 0x1F
                imm = decode_simm16(inst & 0xFFFF)
                lines[i//4].append("addi {0}, {1}, {2}".format(rnam[dst_reg], rnam[src_reg], str_simm16(imm)))
            elif ((version == 0) and (op == 0x4)):
                reg = (inst >> 21) & 0x1F
                off = inst & 0xFFFF
                lines[i//4].append("blez {0}, loc_{1:X}".format(rnam[reg], i + 4 * off))
                b_targ.append(i + 4 * off)
            elif ((version == 0) and (op == 0x0)):
                dst_reg = (inst >> 21) & 0x1F
                src_reg = (inst >> 16) & 0x1F
                off = decode_simm16(inst & 0xFFFF)
                lines[i//4].append("sb [{0} + {1}], {2}".format(rnam[dst_reg], str_simm16(off), rnam[src_reg]))
            elif ((version == 0) and (op == 0x1)):
                reg1 = (inst >> 16) & 0x1F
                reg2 = (inst >> 21) & 0x1F
                off = decode_simm16(inst & 0xFFFF)
                lines[i//4].append("beqc {0}, {1}, loc_{2:X}".format(rnam[reg1], rnam[reg2], i + 4 * off))
                b_targ.append(i + 4 * off)
            elif ((version == 0) and (op == 0x7)):
                dst_reg = (inst >> 16) & 0x1F
                src_reg = (inst >> 21) & 0x1F
                off = decode_simm16(inst & 0xFFFF)
                lines[i//4].append("seb [{0} + {1}], {2}".format(rnam[dst_reg], str_simm16(off), rnam[src_reg]))
            elif ((version == 0) and (op == 0xA)):
                reg = (inst >> 21) & 0x1F
                off = inst & 0xFFFF
                lines[i//4].append("bnvc {0}, loc_{1:X}".format(rnam[reg], i + 4 * off))
                b_targ.append(i + 4 * off)
            elif ((version == 0) and (op == 0x6)):
                dst_reg = (inst >> 16) & 0x1F
                src_reg = (inst >> 21) & 0x1F
                imm = inst & 0xFFFF
                lines[i//4].append("andi {0}, {1}, 0x{2:X}".format(rnam[dst_reg], rnam[src_reg], imm))
            elif ((version == 0) and (op == 0x17)):
                sop = inst & 0x3F
                if ((version == 0) and (sop == 0x31)):
                    dst_reg = (inst >> 11) & 0x1F
                    src_reg = (inst >> 21) & 0x1F
                    lines[i//4].append("jalr {0}, {1}".format(rnam[dst_reg], rnam[src_reg]))            
                elif ((version == 0) and (sop == 0x27)):
                    lines[i//4].append("nop")
                elif ((version == 0) and (sop == 0x23)):
                    reg = (inst >> 21) & 0x1F
                    lines[i//4].append("jr {0}".format(rnam[reg]))    
                elif ((version == 0) and (sop == 0x26)):
                    dst_reg = (inst >> 11) & 0x1F
                    src_reg = (inst >> 16) & 0x1F
                    imm = (inst >> 6) & 0x1F
                    if (dst_reg == 0) and (src_reg == 0) and (imm == 0):
                        lines[i//4].append("nop")
                    else:
                        lines[i//4].append("sll {0}, {1}, 0x{2:X}".format(rnam[dst_reg], rnam[src_reg], imm))
                elif ((version == 0) and (sop == 0x37)):
                    dst_reg = (inst >> 11) & 0x1F
                    src1_reg = (inst >> 21) & 0x1F
                    src2_reg = (inst >> 16) & 0x1F
                    lines[i//4].append("add {0}, {1}, {2}".format(rnam[dst_reg], rnam[src1_reg], rnam[src2_reg]))
                elif ((version == 0) and (sop == 0x33)):
                    dst_reg = (inst >> 11) & 0x1F
                    src_reg = (inst >> 16) & 0x1F
                    imm = (inst >> 6) & 0x1F
                    lines[i//4].append("srl {0}, {1}, 0x{2:X}".format(rnam[dst_reg], rnam[src_reg], imm))    
                elif ((version == 0) and (sop == 0x34)):
                    dst_reg = (inst >> 11) & 0x1F
                    src1_reg = (inst >> 21) & 0x1F
                    src2_reg = (inst >> 16) & 0x1F
                    lines[i//4].append("srlv {0}, {1}, {2}".format(rnam[dst_reg], rnam[src1_reg], rnam[src2_reg]))    
                elif ((version == 0) and (sop == 0x3D)):
                    dst_reg = (inst >> 11) & 0x1F
                    src1_reg = (inst >> 21) & 0x1F
                    src2_reg = (inst >> 16) & 0x1F
                    lines[i//4].append("slt {0}, {1}, {2}".format(rnam[dst_reg], rnam[src1_reg], rnam[src2_reg]))    
                elif ((version == 0) and (sop == 0x3F)):
                    lines[i//4].append("TODO sop 0x{0:X}".format(sop))
                elif ((version == 0) and (sop == 0x29)):
                    dst_reg = (inst >> 11) & 0x1F
                    src1_reg = (inst >> 21) & 0x1F
                    src2_reg = (inst >> 16) & 0x1F
                    lines[i//4].append("sltu {0}, {1}, {2}".format(rnam[dst_reg], rnam[src1_reg], rnam[src2_reg]))    
                elif ((version == 0) and (sop == 0x38)):
                    dst_reg = (inst >> 11) & 0x1F
                    src1_reg = (inst >> 21) & 0x1F
                    src2_reg = (inst >> 16) & 0x1F
                    lines[i//4].append("sllv {0}, {1}, {2}".format(rnam[dst_reg], rnam[src1_reg], rnam[src2_reg]))    
                elif ((version == 0) and (sop == 0xE)):
                    dst_reg = (inst >> 11) & 0x1F
                    src1_reg = (inst >> 21) & 0x1F
                    src2_reg = (inst >> 16) & 0x1F
                    lines[i//4].append("and {0}, {1}, {2}".format(rnam[dst_reg], rnam[src1_reg], rnam[src2_reg]))    
                elif ((version == 0) and (sop == 0x15)):
                    dst_reg = (inst >> 11) & 0x1F
                    src1_reg = (inst >> 21) & 0x1F
                    src2_reg = (inst >> 16) & 0x1F
                    lines[i//4].append("srav {0}, {1}, {2}".format(rnam[dst_reg], rnam[src1_reg], rnam[src2_reg]))    
                elif ((version == 0) and (sop == 0xF)):
                    dst_reg = (inst >> 11) & 0x1F
                    src1_reg = (inst >> 21) & 0x1F
                    src2_reg = (inst >> 16) & 0x1F
                    lines[i//4].append("xor {0}, {1}, {2}".format(rnam[dst_reg], rnam[src1_reg], rnam[src2_reg]))    
                elif ((version == 0) and (sop == 0x14)):
                    dst_reg = (inst >> 11) & 0x1F
                    src1_reg = (inst >> 21) & 0x1F
                    src2_reg = (inst >> 16) & 0x1F
                    lines[i//4].append("nor {0}, ~{1}, {2}".format(rnam[dst_reg], rnam[src1_reg], rnam[src2_reg]))    
                elif ((version == 0) and (sop == 0x19)):
                    lines[i//4].append("TODO sop 0x{0:X}".format(sop)) 
                elif ((version == 0) and (sop == 0x1A)):
                    lines[i//4].append("TODO sop 0x{0:X}".format(sop))   
                elif ((version == 0) and (sop == 0x17)):
                    lines[i//4].append("TODO sop 0x{0:X}".format(sop))       
                elif ((version == 0) and (sop == 0x6)):
                    dst_reg = (inst >> 11) & 0x1F
                    src1_reg = (inst >> 21) & 0x1F
                    src2_reg = (inst >> 16) & 0x1F
                    lines[i//4].append("sub {0}, {1}, {2}".format(rnam[dst_reg], rnam[src1_reg], rnam[src2_reg]))
                elif ((version == 0) and (sop == 0x8)):
                    dst_reg = (inst >> 11) & 0x1F
                    src1_reg = (inst >> 21) & 0x1F
                    src2_reg = (inst >> 16) & 0x1F
                    lines[i//4].append("or {0}, {1}, {2}".format(rnam[dst_reg], rnam[src1_reg], rnam[src2_reg]))
                elif ((version == 0) and (sop == 0x9)):
                    lines[i//4].append("TODO sop 0x{0:X}".format(sop))
                elif ((version == 0) and (sop == 0x1)):
                    dst_reg = (inst >> 11) & 0x1F
                    src_reg = (inst >> 16) & 0x1F
                    imm = (inst >> 6) & 0x1F
                    lines[i//4].append("sra {0}, {1}, 0x{2:X}".format(rnam[dst_reg], rnam[src_reg], imm))
                elif ((version == 0) and (sop == 0x3)):
                    dst_reg = (inst >> 11) & 0x1F
                    src1_reg = (inst >> 21) & 0x1F
                    src2_reg = (inst >> 16) & 0x1F
                    lines[i//4].append("movn {0}, {1}, {2}".format(rnam[dst_reg], rnam[src1_reg], rnam[src2_reg]))
                elif ((version == 0) and (sop == 0x1D)):
                    lines[i//4].append("host_call")
                else:
                    lines[i//4].append("unknown extended op 0x{0:X}".format(sop))
            else:
                lines[i//4].append("unknown op 0x{0:X}".format(op))
        if i == code_size:
            lines[i//4].append("\n;------- data -------\n")
        if i >= code_size and i < code_size + data_size:
            lines[i//4].append("{0:04X}\t\t0x{1:08X}".format(i, vm_get_word(p, i)))
    for i in range(0, len(p), 4):
        if i in jal_targ:
            lines[i//4] = ["\n;------- subroutine -------\nsub_{0:X}:\n".format(i)] + lines[i//4]
        elif i in b_targ:
            lines[i//4] = ["\nloc_{0:X}:\n".format(i)] + lines[i//4]
    return lines

vm_offset = 0
vm_code_size = 0x69C
vm_data_size = 0x188
vm_size = vm_code_size + vm_data_size
vm_version = 0      # v1.1.4

with open("vm.bin", "rb") as in_file:
    with open("vm.asm", "w") as out_file:
        v = in_file.read()
        lines = vm_dis(v[vm_offset:vm_offset+vm_size], vm_code_size, vm_data_size, vm_version)
        for l in lines:
            out_file.write("%s\n" % "".join(l))
