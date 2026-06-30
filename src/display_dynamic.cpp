/*
 * display_dynamic.cpp - 动态节区显示 (-d 选项)
 *
 * .dynamic节区（PT_DYNAMIC段）是动态链接的"路线图"，
 * 包含一系列(tag, value)对，告诉动态链接器如何加载此文件：
 *
 *   DT_NEEDED     - 依赖的共享库（like #include，但在运行时）
 *   DT_SONAME     - 本共享库的规范名称（lib*.so.N形式）
 *   DT_STRTAB     - 动态字符串表的虚拟地址
 *   DT_SYMTAB     - 动态符号表的虚拟地址
 *   DT_HASH       - ELF哈希表地址（用于O(1)符号查找）
 *   DT_GNU_HASH   - GNU改进哈希表（更快的符号查找）
 *   DT_PLTGOT     - GOT.PLT的地址（动态链接器填写PLT跳转目标）
 *   DT_JMPREL     - PLT重定位表地址
 *   DT_INIT/FINI  - 构造/析构函数地址（C++全局对象初始化）
 *   DT_FLAGS_1    - 扩展标志（NODELETE/GLOBAL/NOOPEN等加载控制）
 *
 * 这些信息是操作系统加载器（ld.so）找到各数据结构的唯一依据；
 * 去掉.dynamic节区，动态可执行文件将无法被加载。
 */

#include "elf_parser.h"
#include "elf_strings.h"
#include <cstdio>

void display_dynamic_section(const ELFParser& elf) {
    /* 找到.dynamic节区 */
    int dyn_idx = elf.findSection(".dynamic");
    if (dyn_idx < 0) {
        printf("\n此文件没有动态节区。\n");
        return;
    }

    SecInfo sec = elf.getSection(dyn_idx);
    const uint8_t* data = elf.getSectionData(dyn_idx);
    if (!data) {
        printf("\n无法读取.dynamic节区数据。\n");
        return;
    }

    /* 找到动态字符串表（.dynstr）的节区索引 */
    int dynstr_idx = static_cast<int>(sec.link);

    size_t entry_size = elf.is64bit() ? sizeof(Elf64_Dyn) : sizeof(Elf32_Dyn);
    size_t count = sec.size / entry_size;

    printf("\nDynamic section at offset 0x%lx contains %zu entries:\n",
           (unsigned long)sec.offset, count);

    printf("  %-18s %-20s %s\n", "Tag", "Type", "Name/Value");

    for (size_t i = 0; i < count; i++) {
        int64_t  tag;
        uint64_t val;

        if (elf.is64bit()) {
            const Elf64_Dyn* d = reinterpret_cast<const Elf64_Dyn*>(
                data + i * entry_size);
            tag = static_cast<int64_t>(elf.read64(&d->d_tag));
            val = elf.read64(&d->d_un.d_val);
        } else {
            const Elf32_Dyn* d = reinterpret_cast<const Elf32_Dyn*>(
                data + i * entry_size);
            tag = static_cast<int64_t>(static_cast<int32_t>(
                elf.read32(&d->d_tag)));
            val = static_cast<uint64_t>(elf.read32(&d->d_un.d_val));
        }

        printf(" 0x%016lx %-20s ",
               (unsigned long)tag,
               dyn_tag_str(tag));

        /* 根据tag类型格式化值 */
        switch (tag) {
        case DT_NEEDED:
        case DT_SONAME:
        case DT_RPATH:
        case DT_RUNPATH: {
            /* 字符串类型：从dynstr节区解析 */
            const char* str = elf.getString(dynstr_idx, static_cast<uint32_t>(val));
            if (str) {
                if (tag == DT_NEEDED)
                    printf("Shared library: [%s]", str);
                else if (tag == DT_SONAME)
                    printf("Library soname: [%s]", str);
                else if (tag == DT_RPATH || tag == DT_RUNPATH)
                    printf("Library runpath: [%s]", str);
                else
                    printf("[%s]", str);
            }
            break;
        }
        case DT_PLTRELSZ:
        case DT_RELASZ:
        case DT_RELAENT:
        case DT_STRSZ:
        case DT_SYMENT:
        case DT_RELSZ:
        case DT_RELENT:
        case DT_INIT_ARRAYSZ:
        case DT_FINI_ARRAYSZ:
        case DT_PREINIT_ARRAYSZ:
            printf("%lu (bytes)", (unsigned long)val);
            break;
        case DT_PLTREL:
            printf("%s", val == DT_RELA ? "RELA" : "REL");
            break;
        case DT_FLAGS_1:
            printf("Flags: ");
            if (val & 0x00000001) printf("NOW ");
            if (val & 0x00000002) printf("GLOBAL ");
            if (val & 0x00000004) printf("GROUP ");
            if (val & 0x00000008) printf("NODELETE ");
            if (val & 0x00000020) printf("NOOPEN ");
            if (val & 0x00000080) printf("ORIGIN ");
            if (val & 0x00000100) printf("DIRECT ");
            if (val & 0x00001000) printf("INITFIRST ");
            if (val & 0x00400000) printf("PIE ");
            break;
        case DT_FLAGS:
            printf("Flags: ");
            if (val & DF_ORIGIN)    printf("ORIGIN ");
            if (val & DF_SYMBOLIC)  printf("SYMBOLIC ");
            if (val & DF_TEXTREL)   printf("TEXTREL ");
            if (val & DF_BIND_NOW)  printf("BIND_NOW ");
            if (val & DF_STATIC_TLS) printf("STATIC_TLS ");
            break;
        case DT_NULL:
            break;
        default:
            printf("0x%lx", (unsigned long)val);
            break;
        }
        printf("\n");

        if (tag == DT_NULL) break;
    }
}
