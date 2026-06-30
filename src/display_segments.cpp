/*
 * display_segments.cpp - 程序头（段）显示 (-l 选项)
 *
 * 段（Segment）是执行视图中的基本单位：
 *   LOAD    - 需要从文件加载到内存的段
 *   DYNAMIC - 包含动态链接信息的段
 *   INTERP  - 程序解释器路径（动态链接器 ld-linux.so 的路径）
 *   NOTE    - 辅助信息（版本标记、构建ID等）
 *   GNU_STACK - 控制堆栈是否可执行（安全机制）
 *   GNU_RELRO - 只读重定位区域（安全机制，防止GOT覆写攻击）
 *
 * 段与节区的关系：
 *   一个段可包含多个节区。链接器将相同权限的节区合并为一个段。
 *   这是ELF的"两视图"设计：链接视图(节区)用于静态链接，
 *   执行视图(段)用于加载运行。
 */

#include "elf_parser.h"
#include "elf_strings.h"
#include <cstdio>
#include <cstring>

/* ─── 显示程序头表 ──────────────────────────────────────── */
void display_program_headers(const ELFParser& elf) {
    int phnum = elf.segmentCount();

    printf("\nElf file type is %s\n", elf_type_short(elf.getType()));
    printf("Entry point 0x%lx\n", (unsigned long)elf.getEntry());

    if (phnum == 0) {
        printf("There are no program headers in this file.\n");
        return;
    }

    printf("There are %d program headers, starting at offset %lu\n\n",
           phnum, (unsigned long)elf.getPhoff());

    printf("Program Headers:\n");
    if (elf.is64bit()) {
        printf("  %-14s %-8s %-18s %-18s %-8s %-8s %-3s %s\n",
               "Type", "Offset", "VirtAddr", "PhysAddr",
               "FileSiz", "MemSiz", "Flg", "Align");
    } else {
        printf("  %-14s %-8s %-10s %-10s %-8s %-8s %-3s %s\n",
               "Type", "Offset", "VirtAddr", "PhysAddr",
               "FileSiz", "MemSiz", "Flg", "Align");
    }

    for (int i = 0; i < phnum; i++) {
        if (elf.is64bit()) {
            const Elf64_Phdr* ph = elf.phdr64(i);
            uint32_t ptype   = elf.read32(&ph->p_type);
            uint32_t pflags  = elf.read32(&ph->p_flags);
            uint64_t poffset = elf.read64(&ph->p_offset);
            uint64_t pvaddr  = elf.read64(&ph->p_vaddr);
            uint64_t ppaddr  = elf.read64(&ph->p_paddr);
            uint64_t pfilesz = elf.read64(&ph->p_filesz);
            uint64_t pmemsz  = elf.read64(&ph->p_memsz);
            uint64_t palign  = elf.read64(&ph->p_align);

            printf("  %-14s 0x%06lx 0x%016lx 0x%016lx 0x%06lx 0x%06lx %-3s 0x%lx\n",
                   phtype_str(ptype),
                   (unsigned long)poffset,
                   (unsigned long)pvaddr,
                   (unsigned long)ppaddr,
                   (unsigned long)pfilesz,
                   (unsigned long)pmemsz,
                   phflags_str(pflags).c_str(),
                   (unsigned long)palign);

            /* 特殊：INTERP段显示动态链接器路径 */
            if (ptype == PT_INTERP && pfilesz > 0 &&
                poffset + pfilesz <= elf.rawSize()) {
                printf("      [Requesting program interpreter: %.*s]\n",
                       (int)(pfilesz - 1),
                       (const char*)elf.rawData() + poffset);
            }
        } else {
            const Elf32_Phdr* ph = elf.phdr32(i);
            uint32_t ptype   = elf.read32(&ph->p_type);
            uint32_t pflags  = elf.read32(&ph->p_flags);
            uint32_t poffset = elf.read32(&ph->p_offset);
            uint32_t pvaddr  = elf.read32(&ph->p_vaddr);
            uint32_t ppaddr  = elf.read32(&ph->p_paddr);
            uint32_t pfilesz = elf.read32(&ph->p_filesz);
            uint32_t pmemsz  = elf.read32(&ph->p_memsz);
            uint32_t palign  = elf.read32(&ph->p_align);

            printf("  %-14s 0x%06x 0x%08x 0x%08x 0x%05x 0x%05x %-3s 0x%x\n",
                   phtype_str(ptype),
                   poffset, pvaddr, ppaddr,
                   pfilesz, pmemsz,
                   phflags_str(pflags).c_str(),
                   palign);

            if (ptype == PT_INTERP && pfilesz > 0 &&
                poffset + pfilesz <= elf.rawSize()) {
                printf("      [Requesting program interpreter: %.*s]\n",
                       (int)(pfilesz - 1),
                       (const char*)elf.rawData() + poffset);
            }
        }
    }

    /* ── 节区到段的映射 ─────────────────────────────────── */
    printf("\n Section to Segment mapping:\n");
    printf("  Segment Sections...\n");

    int shnum = elf.sectionCount();
    for (int i = 0; i < phnum; i++) {
        printf("   %02d     ", i);

        uint64_t seg_off, seg_vaddr, seg_filesz, seg_memsz;
        uint32_t seg_type;

        if (elf.is64bit()) {
            const Elf64_Phdr* ph = elf.phdr64(i);
            seg_type   = elf.read32(&ph->p_type);
            seg_off    = elf.read64(&ph->p_offset);
            seg_vaddr  = elf.read64(&ph->p_vaddr);
            seg_filesz = elf.read64(&ph->p_filesz);
            seg_memsz  = elf.read64(&ph->p_memsz);
        } else {
            const Elf32_Phdr* ph = elf.phdr32(i);
            seg_type   = elf.read32(&ph->p_type);
            seg_off    = elf.read32(&ph->p_offset);
            seg_vaddr  = elf.read32(&ph->p_vaddr);
            seg_filesz = elf.read32(&ph->p_filesz);
            seg_memsz  = elf.read32(&ph->p_memsz);
        }
        (void)seg_type;

        /* 遍历所有节区，判断是否在此段的范围内 */
        for (int j = 1; j < shnum; j++) {
            SecInfo sec = elf.getSection(j);
            if (sec.type == SHT_NULL) continue;

            bool in_seg = false;
            if (sec.type == SHT_NOBITS) {
                /* .bss 等：按虚拟地址判断 */
                in_seg = (sec.addr >= seg_vaddr &&
                          sec.addr < seg_vaddr + seg_memsz);
            } else {
                in_seg = (sec.offset >= seg_off &&
                          sec.offset + sec.size <= seg_off + seg_filesz);
            }

            if (in_seg && !sec.name.empty())
                printf("%s ", sec.name.c_str());
        }
        printf("\n");
    }
}
