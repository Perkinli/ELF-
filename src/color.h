/*
 * color.h - ANSI终端彩色输出支持
 *
 * 用法：
 *   g_color = true;           // 开启（由 --color/-C 控制）
 *   printf("%s", C_RED);      // 直接输出转义码
 *   printf("%s", C_RESET);    // 还原
 *   col(C_GREEN, "text")      // 返回着色字符串（用于printf %s）
 */
#pragma once
#include <cstring>

/* 全局开关，由 main.cpp 在解析 --color 后设置 */
extern bool g_color;

/* ── ANSI转义码 ─────────────────────────────────────────── */
#define C_RESET   (g_color ? "\033[0m"  : "")
#define C_BOLD    (g_color ? "\033[1m"  : "")
#define C_DIM     (g_color ? "\033[2m"  : "")

#define C_RED     (g_color ? "\033[31m" : "")
#define C_GREEN   (g_color ? "\033[32m" : "")
#define C_YELLOW  (g_color ? "\033[33m" : "")
#define C_BLUE    (g_color ? "\033[34m" : "")
#define C_MAGENTA (g_color ? "\033[35m" : "")
#define C_CYAN    (g_color ? "\033[36m" : "")
#define C_WHITE   (g_color ? "\033[37m" : "")

#define C_BRED    (g_color ? "\033[1;31m" : "")
#define C_BGREEN  (g_color ? "\033[1;32m" : "")
#define C_BYELLOW (g_color ? "\033[1;33m" : "")
#define C_BCYAN   (g_color ? "\033[1;36m" : "")
#define C_BWHITE  (g_color ? "\033[1;37m" : "")

/* ── 节区类型着色 ────────────────────────────────────────── */
inline const char* shtype_color(uint32_t type) {
    if (!g_color) return "";
    switch (type) {
    case SHT_PROGBITS:  return "\033[36m";   /* 青色：代码/数据 */
    case SHT_SYMTAB:
    case SHT_DYNSYM:    return "\033[33m";   /* 黄色：符号表 */
    case SHT_STRTAB:    return "\033[32m";   /* 绿色：字符串表 */
    case SHT_RELA:
    case SHT_REL:       return "\033[35m";   /* 紫色：重定位 */
    case SHT_DYNAMIC:   return "\033[1;34m"; /* 亮蓝：动态段 */
    case SHT_NOTE:      return "\033[2;37m"; /* 灰色：note */
    case SHT_NOBITS:    return "\033[2;36m"; /* 暗青：.bss */
    case SHT_NULL:      return "\033[2m";    /* 暗色：null */
    default:            return "\033[37m";
    }
}

/* ── 节区标志着色（W/A/X各一色） ────────────────────────── */
inline void print_flags_colored(uint64_t flags) {
    /* W 可写 → 红 */
    if (flags & SHF_WRITE)     printf("%sW%s", C_RED,   C_RESET);
    /* A 分配 → 蓝 */
    if (flags & SHF_ALLOC)     printf("%sA%s", C_BLUE,  C_RESET);
    /* X 可执行 → 绿 */
    if (flags & SHF_EXECINSTR) printf("%sX%s", C_GREEN, C_RESET);
    if (flags & SHF_MERGE)     printf("M");
    if (flags & SHF_STRINGS)   printf("S");
    if (flags & SHF_INFO_LINK) printf("I");
}

/* ── 符号绑定着色 ────────────────────────────────────────── */
inline const char* sym_bind_color(uint8_t bind) {
    if (!g_color) return "";
    switch (bind) {
    case STB_GLOBAL: return "\033[1;37m"; /* 亮白：全局 */
    case STB_WEAK:   return "\033[33m";   /* 黄色：弱符号 */
    case STB_LOCAL:  return "\033[2m";    /* 暗色：局部 */
    default:         return "";
    }
}

/* ── 程序头类型着色 ──────────────────────────────────────── */
inline const char* phtype_color(uint32_t type) {
    if (!g_color) return "";
    switch (type) {
    case PT_LOAD:    return "\033[1;36m"; /* 亮青：可加载段 */
    case PT_DYNAMIC: return "\033[1;34m"; /* 亮蓝：动态段 */
    case PT_INTERP:  return "\033[32m";   /* 绿色：解释器 */
    case 0x6474e552: return "\033[33m";   /* 黄色：RELRO */
    case 0x6474e551: return "\033[35m";   /* 紫色：STACK */
    default:         return "\033[37m";
    }
}
