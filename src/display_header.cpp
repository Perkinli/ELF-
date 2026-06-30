/*
 * display_header.cpp - ELF Header显示 (-h 选项)
 *
 * ELF头部（ELF Header）是ELF文件的起始结构，包含了整个文件的"元数据"：
 *   - 魔数（Magic Number）：标识文件格式
 *   - 文件类型、目标架构、版本
 *   - 程序入口地址（操作系统加载后第一条执行指令的虚拟地址）
 *   - 程序头表和节区头表的偏移
 *
 * 从操作系统视角：内核exec()系统调用首先读取ELF头，根据e_type决定如何加载。
 * 从编程语言视角：编译器/链接器生成此头部，确保二进制接口（ABI）兼容性。
 */

#include "elf_parser.h"
#include "elf_strings.h"
#include <cstdio>

void display_elf_header(const ELFParser& elf) {
    const unsigned char* ident = elf.e_ident();

    printf("ELF Header:\n");

    /* ── 魔数（16字节标识信息） ── */
    printf("  Magic:   ");
    for (int i = 0; i < EI_NIDENT; i++)
        printf("%02x ", ident[i]);
    printf("\n");

    printf("  %-34s %s\n", "Class:",
           elf_class_str(ident[EI_CLASS]));

    printf("  %-34s %s\n", "Data:",
           elf_data_str(ident[EI_DATA]));

    printf("  %-34s %u%s\n", "Version:",
           ident[EI_VERSION],
           ident[EI_VERSION] == EV_CURRENT ? " (current)" : "");

    printf("  %-34s %s\n", "OS/ABI:",
           elf_osabi_str(ident[EI_OSABI]));

    printf("  %-34s %u\n", "ABI Version:",
           ident[EI_ABIVERSION]);

    /* ── ELF头主体字段 ── */
    printf("  %-34s %s\n", "Type:",
           elf_type_str(elf.getType()));

    printf("  %-34s %s\n", "Machine:",
           elf_machine_str(elf.getMachine()));

    printf("  %-34s 0x%x\n", "Version:",
           elf.getVersion());

    printf("  %-34s 0x%lx\n", "Entry point address:",
           (unsigned long)elf.getEntry());

    printf("  %-34s %lu (bytes into file)\n",
           "Start of program headers:",
           (unsigned long)elf.getPhoff());

    printf("  %-34s %lu (bytes into file)\n",
           "Start of section headers:",
           (unsigned long)elf.getShoff());

    printf("  %-34s 0x%x\n", "Flags:",
           elf.getFlags());

    printf("  %-34s %u (bytes)\n", "Size of this header:",
           elf.getEhsize());

    printf("  %-34s %u (bytes)\n", "Size of program headers:",
           elf.getPhentsize());

    printf("  %-34s %u\n", "Number of program headers:",
           elf.getPhnum());

    printf("  %-34s %u (bytes)\n", "Size of section headers:",
           elf.getShentsize());

    printf("  %-34s %u\n", "Number of section headers:",
           elf.getShnum());

    printf("  %-34s %u\n", "Section header string table index:",
           elf.getShstrndx());
}
