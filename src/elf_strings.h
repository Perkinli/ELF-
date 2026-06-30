/*
 * elf_strings.h - ELF字段值到字符串的映射
 *
 * 将ELF头部的各种数值常量转换为可读的字符串，
 * 从操作系统和编程语言角度解释每个字段的含义。
 */
#pragma once
#include <elf.h>
#include <string>
#include <cstdint>

/* ── ELF文件类型 ───────────────────────────────────────── */
inline const char* elf_type_str(uint16_t type) {
    switch (type) {
    case ET_NONE:   return "NONE (无目标文件格式)";
    case ET_REL:    return "REL (可重定位文件)";
    case ET_EXEC:   return "EXEC (可执行文件)";
    case ET_DYN:    return "DYN (共享目标文件/位置无关可执行文件)";
    case ET_CORE:   return "CORE (转储文件)";
    default:
        if (type >= ET_LOPROC)
            return "PROC (处理器特定类型)";
        return "未知";
    }
}

/* 短类型名（用于段头显示） */
inline const char* elf_type_short(uint16_t type) {
    switch (type) {
    case ET_NONE: return "NONE";
    case ET_REL:  return "REL";
    case ET_EXEC: return "EXEC";
    case ET_DYN:  return "DYN";
    case ET_CORE: return "CORE";
    default:      return "?";
    }
}

/* ── 目标机器架构 ───────────────────────────────────────── */
inline const char* elf_machine_str(uint16_t mach) {
    switch (mach) {
    case EM_NONE:    return "无架构";
    case EM_M32:     return "AT&T WE 32100";
    case EM_SPARC:   return "SPARC";
    case EM_386:     return "Intel 80386";
    case EM_68K:     return "Motorola 68000";
    case EM_88K:     return "Motorola 88000";
    case EM_860:     return "Intel 80860";
    case EM_MIPS:    return "MIPS RS3000 (big-endian)";
    case EM_PPC:     return "PowerPC";
    case EM_PPC64:   return "PowerPC 64位";
    case EM_ARM:     return "ARM";
    case EM_SH:      return "Hitachi SuperH";
    case EM_SPARCV9: return "SPARC V9 (64位)";
    case EM_IA_64:   return "Intel Itanium IA-64";
    case EM_X86_64:  return "Advanced Micro Devices X86-64";
    case EM_AARCH64: return "AArch64 (ARM 64位)";
    case EM_RISCV:   return "RISC-V";
    default:         return "未知架构";
    }
}

/* ── ELF数据编码（字节序） ─────────────────────────────── */
inline const char* elf_data_str(uint8_t data) {
    switch (data) {
    case ELFDATA2LSB: return "2's complement, little endian";
    case ELFDATA2MSB: return "2's complement, big endian";
    default:          return "无效数据编码";
    }
}

/* ── ELF文件类别（32/64位） ────────────────────────────── */
inline const char* elf_class_str(uint8_t cls) {
    switch (cls) {
    case ELFCLASS32: return "ELF32";
    case ELFCLASS64: return "ELF64";
    default:         return "无效类别";
    }
}

/* ── OS/ABI ────────────────────────────────────────────── */
inline const char* elf_osabi_str(uint8_t abi) {
    switch (abi) {
    case ELFOSABI_NONE:    return "UNIX - System V";
    case ELFOSABI_HPUX:    return "UNIX - HP-UX";
    case ELFOSABI_NETBSD:  return "UNIX - NetBSD";
    case ELFOSABI_GNU:     return "UNIX - GNU/Linux";
    case ELFOSABI_SOLARIS: return "UNIX - Solaris";
    case ELFOSABI_AIX:     return "UNIX - AIX";
    case ELFOSABI_IRIX:    return "UNIX - IRIX";
    case ELFOSABI_FREEBSD: return "UNIX - FreeBSD";
    case ELFOSABI_TRU64:   return "UNIX - TRU64";
    case ELFOSABI_OPENBSD: return "UNIX - OpenBSD";
    case ELFOSABI_ARM:     return "ARM";
    case ELFOSABI_STANDALONE: return "独立嵌入式应用";
    default:               return "未知ABI";
    }
}

/* ── 节区类型 ──────────────────────────────────────────── */
inline const char* shtype_str(uint32_t type) {
    switch (type) {
    case SHT_NULL:          return "NULL";
    case SHT_PROGBITS:      return "PROGBITS";
    case SHT_SYMTAB:        return "SYMTAB";
    case SHT_STRTAB:        return "STRTAB";
    case SHT_RELA:          return "RELA";
    case SHT_HASH:          return "HASH";
    case SHT_DYNAMIC:       return "DYNAMIC";
    case SHT_NOTE:          return "NOTE";
    case SHT_NOBITS:        return "NOBITS";
    case SHT_REL:           return "REL";
    case SHT_SHLIB:         return "SHLIB";
    case SHT_DYNSYM:        return "DYNSYM";
    case SHT_INIT_ARRAY:    return "INIT_ARRAY";
    case SHT_FINI_ARRAY:    return "FINI_ARRAY";
    case SHT_PREINIT_ARRAY: return "PREINIT_ARRAY";
    case SHT_GROUP:         return "GROUP";
    case SHT_SYMTAB_SHNDX:  return "SYMTAB SECTION INDICES";
    case 0x6ffffff6:        return "GNU_HASH";
    case 0x6ffffffd:        return "VERDEF";
    case 0x6ffffffe:        return "VERNEED";
    case 0x6fffffff:        return "VERSYM";
    case 0x6ffffff0:        return "GNU_LIBLIST";
    default:
        if (type >= SHT_LOPROC && type <= SHT_HIPROC) return "LOPROC..HIPROC";
        if (type >= SHT_LOUSER && type <= SHT_HIUSER) return "LOUSER..HIUSER";
        return "UNKNOWN";
    }
}

/* ── 节区标志（返回flags字符串，如"WAX"） ──────────────── */
inline std::string shflags_str(uint64_t flags) {
    std::string s;
    if (flags & SHF_WRITE)            s += 'W';
    if (flags & SHF_ALLOC)            s += 'A';
    if (flags & SHF_EXECINSTR)        s += 'X';
    if (flags & SHF_MERGE)            s += 'M';
    if (flags & SHF_STRINGS)          s += 'S';
    if (flags & SHF_INFO_LINK)        s += 'I';
    if (flags & SHF_LINK_ORDER)       s += 'L';
    if (flags & SHF_OS_NONCONFORMING) s += 'O';
    if (flags & SHF_GROUP)            s += 'G';
    if (flags & SHF_TLS)              s += 'T';
    if (flags & SHF_COMPRESSED)       s += 'C';
    if (flags & SHF_EXECINSTR && flags & SHF_ALLOC && flags & SHF_WRITE)
        {} /* already captured */
    return s;
}

/* ── 程序头类型 ────────────────────────────────────────── */
inline const char* phtype_str(uint32_t type) {
    switch (type) {
    case PT_NULL:    return "NULL";
    case PT_LOAD:    return "LOAD";
    case PT_DYNAMIC: return "DYNAMIC";
    case PT_INTERP:  return "INTERP";
    case PT_NOTE:    return "NOTE";
    case PT_SHLIB:   return "SHLIB";
    case PT_PHDR:    return "PHDR";
    case PT_TLS:     return "TLS";
    case 0x6474e550: return "GNU_EH_FRAME";
    case 0x6474e551: return "GNU_STACK";
    case 0x6474e552: return "GNU_RELRO";
    case 0x6474e553: return "GNU_PROPERTY";
    default:
        if (type >= PT_LOPROC && type <= PT_HIPROC) return "LOPROC..HIPROC";
        return "UNKNOWN";
    }
}

/* ── 程序头标志 ────────────────────────────────────────── */
inline std::string phflags_str(uint32_t flags) {
    std::string s;
    s += (flags & PF_R) ? 'R' : ' ';
    s += (flags & PF_W) ? 'W' : ' ';
    s += (flags & PF_X) ? 'E' : ' ';
    return s;
}

/* ── 符号绑定类型 ──────────────────────────────────────── */
inline const char* sym_bind_str(uint8_t bind) {
    switch (bind) {
    case STB_LOCAL:  return "LOCAL";
    case STB_GLOBAL: return "GLOBAL";
    case STB_WEAK:   return "WEAK";
    default:         return "??";
    }
}

/* ── 符号类型 ──────────────────────────────────────────── */
inline const char* sym_type_str(uint8_t type) {
    switch (type) {
    case STT_NOTYPE:  return "NOTYPE";
    case STT_OBJECT:  return "OBJECT";
    case STT_FUNC:    return "FUNC";
    case STT_SECTION: return "SECTION";
    case STT_FILE:    return "FILE";
    case STT_COMMON:  return "COMMON";
    case STT_TLS:     return "TLS";
    default:          return "??";
    }
}

/* ── 符号可见性 ────────────────────────────────────────── */
inline const char* sym_vis_str(uint8_t vis) {
    switch (vis & 0x3) {
    case STV_DEFAULT:   return "DEFAULT";
    case STV_INTERNAL:  return "INTERNAL";
    case STV_HIDDEN:    return "HIDDEN";
    case STV_PROTECTED: return "PROTECTED";
    default:            return "??";
    }
}

/* ── 符号所在节区索引 ──────────────────────────────────── */
inline std::string sym_shndx_str(uint16_t shndx) {
    switch (shndx) {
    case SHN_UNDEF:  return "UND";
    case SHN_ABS:    return "ABS";
    case SHN_COMMON: return "COM";
    default: {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d", shndx);
        return buf;
    }
    }
}

/* ── x86_64重定位类型 ──────────────────────────────────── */
inline const char* rela_type_str_x86_64(uint32_t type) {
    switch (type) {
    case R_X86_64_NONE:      return "R_X86_64_NONE";
    case R_X86_64_64:        return "R_X86_64_64";
    case R_X86_64_PC32:      return "R_X86_64_PC32";
    case R_X86_64_GOT32:     return "R_X86_64_GOT32";
    case R_X86_64_PLT32:     return "R_X86_64_PLT32";
    case R_X86_64_COPY:      return "R_X86_64_COPY";
    case R_X86_64_GLOB_DAT:  return "R_X86_64_GLOB_DAT";
    case R_X86_64_JUMP_SLOT: return "R_X86_64_JUMP_SLOT";
    case R_X86_64_RELATIVE:  return "R_X86_64_RELATIVE";
    case R_X86_64_GOTPCREL:  return "R_X86_64_GOTPCREL";
    case R_X86_64_32:        return "R_X86_64_32";
    case R_X86_64_32S:       return "R_X86_64_32S";
    case R_X86_64_16:        return "R_X86_64_16";
    case R_X86_64_PC16:      return "R_X86_64_PC16";
    case R_X86_64_8:         return "R_X86_64_8";
    case R_X86_64_PC8:       return "R_X86_64_PC8";
    case R_X86_64_TLSGD:     return "R_X86_64_TLSGD";
    case R_X86_64_TLSLD:     return "R_X86_64_TLSLD";
    case R_X86_64_TPOFF64:   return "R_X86_64_TPOFF64";
    case R_X86_64_IRELATIVE: return "R_X86_64_IRELATIVE";
    case R_X86_64_GOTPCRELX: return "R_X86_64_GOTPCRELX";
    default: {
        static char buf[32];
        snprintf(buf, sizeof(buf), "<type %u>", type);
        return buf;
    }
    }
}

/* ── i386重定位类型 ────────────────────────────────────── */
inline const char* rela_type_str_i386(uint32_t type) {
    switch (type) {
    case R_386_NONE:      return "R_386_NONE";
    case R_386_32:        return "R_386_32";
    case R_386_PC32:      return "R_386_PC32";
    case R_386_GOT32:     return "R_386_GOT32";
    case R_386_PLT32:     return "R_386_PLT32";
    case R_386_COPY:      return "R_386_COPY";
    case R_386_GLOB_DAT:  return "R_386_GLOB_DAT";
    case R_386_JMP_SLOT:  return "R_386_JMP_SLOT";
    case R_386_RELATIVE:  return "R_386_RELATIVE";
    case R_386_GOTOFF:    return "R_386_GOTOFF";
    case R_386_GOTPC:     return "R_386_GOTPC";
    default: {
        static char buf[32];
        snprintf(buf, sizeof(buf), "<type %u>", type);
        return buf;
    }
    }
}

/* ── 动态节区tag名称 ───────────────────────────────────── */
inline const char* dyn_tag_str(int64_t tag) {
    switch (tag) {
    case DT_NULL:         return "(NULL)";
    case DT_NEEDED:       return "(NEEDED)";
    case DT_PLTRELSZ:     return "(PLTRELSZ)";
    case DT_PLTGOT:       return "(PLTGOT)";
    case DT_HASH:         return "(HASH)";
    case DT_STRTAB:       return "(STRTAB)";
    case DT_SYMTAB:       return "(SYMTAB)";
    case DT_RELA:         return "(RELA)";
    case DT_RELASZ:       return "(RELASZ)";
    case DT_RELAENT:      return "(RELAENT)";
    case DT_STRSZ:        return "(STRSZ)";
    case DT_SYMENT:       return "(SYMENT)";
    case DT_INIT:         return "(INIT)";
    case DT_FINI:         return "(FINI)";
    case DT_SONAME:       return "(SONAME)";
    case DT_RPATH:        return "(RPATH)";
    case DT_SYMBOLIC:     return "(SYMBOLIC)";
    case DT_REL:          return "(REL)";
    case DT_RELSZ:        return "(RELSZ)";
    case DT_RELENT:       return "(RELENT)";
    case DT_PLTREL:       return "(PLTREL)";
    case DT_DEBUG:        return "(DEBUG)";
    case DT_TEXTREL:      return "(TEXTREL)";
    case DT_JMPREL:       return "(JMPREL)";
    case DT_BIND_NOW:     return "(BIND_NOW)";
    case DT_INIT_ARRAY:   return "(INIT_ARRAY)";
    case DT_FINI_ARRAY:   return "(FINI_ARRAY)";
    case DT_INIT_ARRAYSZ: return "(INIT_ARRAYSZ)";
    case DT_FINI_ARRAYSZ: return "(FINI_ARRAYSZ)";
    case DT_RUNPATH:      return "(RUNPATH)";
    case DT_FLAGS:        return "(FLAGS)";
    case DT_PREINIT_ARRAY:   return "(PREINIT_ARRAY)";
    case DT_PREINIT_ARRAYSZ: return "(PREINIT_ARRAYSZ)";
    case 0x6ffffef5:      return "(GNU_HASH)";
    case 0x6ffffff0:      return "(VERSYM)";
    case 0x6ffffffc:      return "(VERDEF)";
    case 0x6ffffffd:      return "(VERDEFNUM)";
    case 0x6ffffffe:      return "(VERNEED)";
    case 0x6fffffff:      return "(VERNEEDNUM)";
    case 0x6ffffff9:      return "(RELACOUNT)";
    case 0x6ffffffb:      return "(FLAGS_1)";
    default: {
        static char buf[32];
        snprintf(buf, sizeof(buf), "(0x%lx)", (unsigned long)tag);
        return buf;
    }
    }
}
