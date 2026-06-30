/*
 * display_symbols.cpp - 符号表显示 (-s 选项)
 *
 * 符号表（Symbol Table）记录了程序中所有有意义的"名字"：
 *   - 函数名、变量名（全局符号，用于链接时符号解析）
 *   - 节区引用符号（STT_SECTION，用于重定位）
 *   - 文件名符号（STT_FILE，标记目标文件来源）
 *
 * 两种符号表：
 *   .symtab  - 完整符号表，包含调试信息，可被strip命令去除
 *   .dynsym  - 动态符号表，包含运行时动态链接所需的最小符号集，
 *              不可被strip去除（否则动态链接失败）
 *
 * 符号绑定（Binding）的操作系统含义：
 *   LOCAL   - 局部符号，仅在当前目标文件可见（C语言static函数/变量）
 *   GLOBAL  - 全局符号，对所有参与链接的文件可见
 *   WEAK    - 弱符号：若有同名GLOBAL符号则被覆盖；常用于提供可覆写的默认实现
 *
 * 符号值（Value）的含义随文件类型不同：
 *   可重定位文件：相对于节区起始的偏移
 *   可执行/共享文件：运行时虚拟地址
 */

#include "elf_parser.h"
#include "elf_strings.h"
#include "color.h"
#include <cstdio>
#include <vector>

static void print_symbol_table(const ELFParser& elf, int sec_idx,
                               const std::string& sec_name) {
    auto syms = elf.getSymbols(sec_idx);
    if (syms.empty()) return;

    printf("\nSymbol table '%s' contains %zu entries:\n",
           sec_name.c_str(), syms.size());

    if (elf.is64bit()) {
        printf("   Num:    Value          Size Type    Bind   "
               "Vis      Ndx Name\n");
    } else {
        printf("   Num:    Value  Size Type    Bind   "
               "Vis      Ndx Name\n");
    }

    for (size_t i = 0; i < syms.size(); i++) {
        const SymInfo& s = syms[i];
        uint8_t stype = ELF32_ST_TYPE(s.info);
        uint8_t sbind = ELF32_ST_BIND(s.info);
        uint8_t svis  = ELF32_ST_VISIBILITY(s.other);

        const char* bc = sym_bind_color(sbind);
        /* 函数符号名用绿色，对象用青色，其他用默认 */
        const char* nc = (stype == STT_FUNC)   ? C_BGREEN :
                         (stype == STT_OBJECT) ? C_CYAN   : "";
        if (elf.is64bit()) {
            printf("  %4zu: %s%016lx%s %5lu %s%-7s%s %s%-6s%s %-8s %3s %s%s%s\n",
                   i,
                   C_YELLOW, (unsigned long)s.value, C_RESET,
                   (unsigned long)s.size,
                   C_MAGENTA, sym_type_str(stype), C_RESET,
                   bc, sym_bind_str(sbind), C_RESET,
                   sym_vis_str(svis),
                   sym_shndx_str(s.shndx).c_str(),
                   nc, s.name.c_str(), C_RESET);
        } else {
            printf("  %4zu: %s%08lx%s %5lu %s%-7s%s %s%-6s%s %-8s %3s %s%s%s\n",
                   i,
                   C_YELLOW, (unsigned long)s.value, C_RESET,
                   (unsigned long)s.size,
                   C_MAGENTA, sym_type_str(stype), C_RESET,
                   bc, sym_bind_str(sbind), C_RESET,
                   sym_vis_str(svis),
                   sym_shndx_str(s.shndx).c_str(),
                   nc, s.name.c_str(), C_RESET);
        }
    }
}

void display_symbol_table(const ELFParser& elf, bool use_dynamic) {
    bool found = false;

    for (int i = 0; i < elf.sectionCount(); i++) {
        SecInfo s = elf.getSection(i);

        if (use_dynamic && s.type != SHT_DYNSYM) continue;
        if (!use_dynamic && s.type != SHT_SYMTAB && s.type != SHT_DYNSYM)
            continue;

        print_symbol_table(elf, i, s.name);
        found = true;
    }

    if (!found)
        printf("\n此文件不包含符号表。\n");
}
