/*
 * display_relocs.cpp - 重定位信息显示 (-r 选项)
 *
 * 重定位（Relocation）是链接器/动态链接器的核心工作之一：
 *   将代码/数据中的"符号引用"修补为实际地址。
 *
 * 重定位表项类型：
 *   REL  (Elf_Rel)  - 隐式加数，修补值 = 符号地址 + 目标位置当前值
 *   RELA (Elf_Rela) - 显式加数，修补值 = 符号地址 + r_addend
 *   x86_64通常使用RELA；i386通常使用REL。
 *
 * 常见重定位类型（以x86_64为例）：
 *   R_X86_64_64        - 绝对地址引用（64位）
 *   R_X86_64_PC32      - 相对PC的32位引用（用于函数调用指令）
 *   R_X86_64_PLT32     - 通过PLT的相对引用（动态函数调用）
 *   R_X86_64_GLOB_DAT  - GOT表项初始化（全局数据符号）
 *   R_X86_64_JUMP_SLOT - PLT延迟绑定的GOT槽（动态函数符号）
 *   R_X86_64_RELATIVE  - 无符号，值为基址+加数（位置无关代码）
 *   R_X86_64_COPY      - 将共享库中的符号值拷贝到可执行文件的BSS
 *
 * 操作系统中的作用：
 *   加载可执行文件时，动态链接器（ld-linux.so）扫描DYNAMIC段，
 *   找到所有重定位表，将各符号的真实运行时地址填入GOT/PLT中。
 */

#include "elf_parser.h"
#include "elf_strings.h"
#include <cstdio>

static void print_reloc_section(const ELFParser& elf, int sec_idx) {
    SecInfo sec = elf.getSection(sec_idx);
    bool isRela = (sec.type == SHT_RELA);

    auto relas = elf.getRelocations(sec_idx);
    if (relas.empty()) return;

    printf("\nRelocation section '%s' at offset 0x%lx contains %zu entries:\n",
           sec.name.c_str(),
           (unsigned long)sec.offset,
           relas.size());

    if (elf.is64bit()) {
        if (isRela)
            printf("  %-16s %-16s %-24s %-16s %s\n",
                   "Offset", "Info", "Type", "Sym. Value", "Sym. Name + Addend");
        else
            printf("  %-16s %-16s %-24s %-16s %s\n",
                   "Offset", "Info", "Type", "Sym. Value", "Sym. Name");
    } else {
        if (isRela)
            printf(" %-8s %-8s %-20s %-8s %s\n",
                   "Offset", "Info", "Type", "Sym.Value", "Sym. Name + Addend");
        else
            printf(" %-8s %-8s %-20s %-8s %s\n",
                   "Offset", "Info", "Type", "Sym.Value", "Sym. Name");
    }

    /* 关联的符号表 */
    int sym_sec = static_cast<int>(sec.link);
    auto syms = elf.getSymbols(sym_sec);

    uint16_t machine = elf.getMachine();

    for (const auto& r : relas) {
        /* 重定位类型字符串 */
        const char* type_name;
        if (machine == EM_X86_64)
            type_name = rela_type_str_x86_64(r.type);
        else if (machine == EM_386)
            type_name = rela_type_str_i386(r.type);
        else {
            static char buf[32];
            snprintf(buf, sizeof(buf), "%u", r.type);
            type_name = buf;
        }

        /* 符号值 */
        uint64_t sym_val = 0;
        if (r.sym_idx < syms.size())
            sym_val = syms[r.sym_idx].value;

        if (elf.is64bit()) {
            printf("%016lx  %016lx %-24s %016lx  %s",
                   (unsigned long)r.offset,
                   (unsigned long)r.info,
                   type_name,
                   (unsigned long)sym_val,
                   r.sym_name.c_str());
            if (isRela) {
                if (r.addend >= 0)
                    printf(" + %ld", r.addend);
                else
                    printf(" - %ld", -r.addend);
            }
            printf("\n");
        } else {
            printf("%08lx  %08lx %-20s %08lx   %s",
                   (unsigned long)r.offset,
                   (unsigned long)r.info,
                   type_name,
                   (unsigned long)sym_val,
                   r.sym_name.c_str());
            if (isRela) {
                if (r.addend >= 0)
                    printf(" + %ld", r.addend);
                else
                    printf(" - %ld", -r.addend);
            }
            printf("\n");
        }
    }
}

void display_relocations(const ELFParser& elf) {
    bool found = false;
    for (int i = 0; i < elf.sectionCount(); i++) {
        SecInfo s = elf.getSection(i);
        if (s.type == SHT_REL || s.type == SHT_RELA) {
            print_reloc_section(elf, i);
            found = true;
        }
    }
    if (!found)
        printf("\n此文件没有重定位节区。\n");
}
