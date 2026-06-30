/*
 * display_sections.cpp - 节区头部显示 (-S / -t 选项)
 *
 * 节区（Section）是链接视图中的基本单位：
 *   .text   - 机器指令（可执行代码）
 *   .data   - 已初始化全局/静态变量
 *   .bss    - 未初始化全局/静态变量（不占文件空间，加载后清零）
 *   .rodata - 只读数据（字符串字面量等）
 *   .symtab - 静态符号表（链接时使用）
 *   .dynsym - 动态符号表（运行时动态链接使用）
 *   .strtab - 字符串表（存储符号名）
 *   .plt    - 过程链接表（PLT，用于延迟绑定动态函数）
 *   .got    - 全局偏移表（GOT，运行时由动态链接器填写函数/数据地址）
 *
 * 节区标志（Flags）含义：
 *   W(rite)     - 进程运行时此节区可写
 *   A(lloc)     - 进程运行时需要在内存中分配此节区
 *   X(execute)  - 此节区包含可执行指令
 *   M(erge)     - 链接时可合并同类节区
 *   S(trings)   - 此节区包含以null结尾的字符串
 */

#include "elf_parser.h"
#include "elf_strings.h"
#include <cstdio>
#include <string>

/* ─── 辅助：打印Section Header表格行（32/64位通用） ─────── */
static void print_shdr_row(int idx, const SecInfo& s, bool is64) {
    std::string dname = s.name.size() > 17 ? s.name.substr(0, 17) : s.name;
    printf("  [%2d] %-17s %-15s ",
           idx,
           dname.c_str(),
           shtype_str(s.type));

    if (is64) {
        printf("%016lx  %08lx\n",
               (unsigned long)s.addr,
               (unsigned long)s.offset);
        printf("       %016lx  %016lx %3s  %5u %5u %5lu\n",
               (unsigned long)s.size,
               (unsigned long)s.entsize,
               shflags_str(s.flags).c_str(),
               s.link, s.info,
               (unsigned long)s.addralign);
    } else {
        printf("%08lx  %06lx\n",
               (unsigned long)s.addr,
               (unsigned long)s.offset);
        printf("       %08lx  %08lx %3s  %5u %5u %3lu\n",
               (unsigned long)s.size,
               (unsigned long)s.entsize,
               shflags_str(s.flags).c_str(),
               s.link, s.info,
               (unsigned long)s.addralign);
    }
}

/* ─── 主显示函数 ─────────────────────────────────────────── */
void display_section_headers(const ELFParser& elf, bool detailed) {
    int n = elf.sectionCount();
    if (n == 0) {
        printf("\n此文件没有节区。\n");
        return;
    }

    printf("\nThere are %d section headers, starting at offset 0x%lx:\n\n",
           n, (unsigned long)elf.getShoff());

    printf("Section Headers:\n");
    if (elf.is64bit()) {
        printf("  [Nr] Name              Type             Address"
               "           Offset\n");
        printf("       Size              EntSize          Flags"
               "  Link  Info  Align\n");
    } else {
        printf("  [Nr] Name              Type            Addr"
               "     Off    Size   ES Flg Lk Inf Al\n");
    }

    for (int i = 0; i < n; i++) {
        SecInfo s = elf.getSection(i);
        print_shdr_row(i, s, elf.is64bit());

        /* -t 选项：显示详细信息（节区类型的语义解释） */
        if (detailed && s.type != SHT_NULL) {
            printf("       [含义] 类型=%-10s | 对齐=%lu字节",
                   shtype_str(s.type),
                   (unsigned long)s.addralign);
            if (s.entsize > 0)
                printf(" | 表项大小=%lu字节", (unsigned long)s.entsize);
            printf("\n");
        }
    }

    /* 标志说明 */
    printf("Key to Flags:\n");
    printf("  W (write), A (alloc), X (execute), M (merge), "
           "S (strings), I (info),\n");
    printf("  L (link order), O (extra OS processing required), "
           "G (group), T (TLS),\n");
    printf("  C (compressed), x (unknown), o (OS specific), "
           "E (exclude),\n");
    printf("  l (large), p (processor specific)\n");
}
