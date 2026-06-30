/*
 * display_checksec.cpp - ELF安全属性全面扫描 (--checksec)
 *
 * 检测项目（从操作系统和安全角度解释）：
 *
 *  PIE    - Position Independent Executable（位置无关可执行文件）
 *           文件类型为ET_DYN表示PIE，配合内核ASLR可使每次加载基址随机，
 *           攻击者无法预测代码地址，防御ROP/ret2libc攻击。
 *
 *  NX     - No-eXecute（不可执行栈/堆）
 *           GNU_STACK段的PF_X标志为0表示启用，阻止攻击者在栈上注入并执行shellcode。
 *           对应CPU的NX/XD/XN特性，由内核通过页表设置。
 *
 *  RELRO  - RELocation Read-Only（重定位只读）
 *           Partial RELRO：存在GNU_RELRO段，将.got等节区在初始化后设为只读。
 *           Full RELRO：还需BIND_NOW（DT_BIND_NOW或DF_BIND_NOW），
 *           程序启动时立即解析所有符号，之后GOT全部只读，防止GOT覆写攻击。
 *
 *  Canary - 栈金丝雀（Stack Smashing Protector）
 *           动态符号表中存在__stack_chk_fail表示编译时开启了-fstack-protector，
 *           在函数返回前检查栈帧是否被破坏（金丝雀值是否改变）。
 *
 *  FORTIFY - FORTIFY_SOURCE缓冲区溢出检测
 *            存在__*_chk形式符号（如__memcpy_chk）表示编译时使用了-D_FORTIFY_SOURCE，
 *            对strlen/strcpy等不安全函数替换为带边界检查版本。
 *
 *  RPATH/RUNPATH - 运行时库搜索路径
 *            存在DT_RPATH/DT_RUNPATH表示可能存在库劫持风险（尤其是相对路径）。
 */

#include "elf_parser.h"
#include "elf_strings.h"
#include "color.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

/* ── 检测结果结构 ─────────────────────────────────────────── */
struct CheckResult {
    const char* name;
    const char* status;   /* 状态字符串 */
    const char* color;    /* 状态颜色 */
    const char* detail;   /* 解释说明 */
};

static void print_check(const char* name, bool good, const char* good_str,
                        const char* bad_str, const char* detail) {
    const char* color  = good ? C_BGREEN : C_BRED;
    const char* status = good ? good_str : bad_str;
    const char* mark   = good ? " ✓" : " ✗";
    printf("  %-16s %s%-20s%s%s  %s%s%s\n",
           name,
           color, status, C_RESET,
           good ? C_BGREEN : C_RED, mark, C_RESET,
           detail);
}

static void print_check_warn(const char* name, bool good, const char* good_str,
                              const char* bad_str, const char* detail) {
    const char* color  = good ? C_BGREEN : C_BYELLOW;
    const char* status = good ? good_str : bad_str;
    const char* mark   = good ? " ✓" : " ⚠";
    printf("  %-16s %s%-20s%s%s  %s%s%s\n",
           name,
           color, status, C_RESET,
           good ? C_BGREEN : C_YELLOW, mark, C_RESET,
           detail);
}

void display_checksec(const ELFParser& elf) {
    printf("\n%s════════ 安全属性检查 (Security Hardening) ════════%s\n",
           C_BOLD, C_RESET);
    printf("  文件: %s%s%s\n\n",
           C_CYAN, elf.filename().c_str(), C_RESET);
    printf("  %-16s %-20s   %s\n", "属性", "状态", "说明");
    printf("  %s\n", std::string(72, '-').c_str());

    /* ──────────────────────────────────────────────────────── */
    /* 1. PIE                                                   */
    /* ──────────────────────────────────────────────────────── */
    bool pie = (elf.getType() == ET_DYN);
    print_check("PIE",
                pie, "PIE enabled", "No PIE",
                pie ? "地址随机化（ASLR）有效，防ROP攻击"
                    : "固定加载地址，ASLR无效");

    /* ──────────────────────────────────────────────────────── */
    /* 2. NX (Non-eXecutable stack)                             */
    /* ──────────────────────────────────────────────────────── */
    bool nx = true;   /* 默认有NX（找到GNU_STACK且无X标志） */
    bool found_stack = false;
    for (int i = 0; i < elf.segmentCount(); i++) {
        uint32_t ptype, pflags;
        if (elf.is64bit()) {
            const Elf64_Phdr* ph = elf.phdr64(i);
            ptype  = elf.read32(&ph->p_type);
            pflags = elf.read32(&ph->p_flags);
        } else {
            const Elf32_Phdr* ph = elf.phdr32(i);
            ptype  = elf.read32(&ph->p_type);
            pflags = elf.read32(&ph->p_flags);
        }
        if (ptype == 0x6474e551u) {   /* PT_GNU_STACK */
            found_stack = true;
            nx = !(pflags & PF_X);
            break;
        }
    }
    if (!found_stack) nx = false;   /* 没有GNU_STACK段视为不安全 */
    print_check("NX",
                nx, "Enabled", "Disabled",
                nx ? "栈不可执行，阻止shellcode注入"
                   : "栈可执行，存在shellcode风险");

    /* ──────────────────────────────────────────────────────── */
    /* 3. RELRO                                                  */
    /* ──────────────────────────────────────────────────────── */
    bool has_relro = false;
    for (int i = 0; i < elf.segmentCount(); i++) {
        uint32_t ptype;
        if (elf.is64bit())
            ptype = elf.read32(&elf.phdr64(i)->p_type);
        else
            ptype = elf.read32(&elf.phdr32(i)->p_type);
        if (ptype == 0x6474e552u) { has_relro = true; break; }
    }

    /* BIND_NOW：DT_BIND_NOW 或 DT_FLAGS 含 DF_BIND_NOW */
    bool bind_now = false;
    int dyn_idx = elf.findSection(".dynamic");
    if (dyn_idx >= 0) {
        SecInfo dsec = elf.getSection(dyn_idx);
        const uint8_t* ddata = elf.getSectionData(dyn_idx);
        if (ddata) {
            size_t esz = elf.is64bit() ? sizeof(Elf64_Dyn) : sizeof(Elf32_Dyn);
            size_t cnt = dsec.size / esz;
            for (size_t i = 0; i < cnt; i++) {
                int64_t tag;
                uint64_t val;
                if (elf.is64bit()) {
                    const Elf64_Dyn* d = reinterpret_cast<const Elf64_Dyn*>(
                        ddata + i * esz);
                    tag = static_cast<int64_t>(elf.read64(
                        reinterpret_cast<const uint64_t*>(&d->d_tag)));
                    val = elf.read64(&d->d_un.d_val);
                } else {
                    const Elf32_Dyn* d = reinterpret_cast<const Elf32_Dyn*>(
                        ddata + i * esz);
                    tag = static_cast<int64_t>(
                        static_cast<int32_t>(elf.read32(
                            reinterpret_cast<const uint32_t*>(&d->d_tag))));
                    val = elf.read32(&d->d_un.d_val);
                }
                if (tag == DT_NULL) break;
                if (tag == DT_BIND_NOW) { bind_now = true; break; }
                if (tag == DT_FLAGS && (val & DF_BIND_NOW)) { bind_now = true; }
                if (tag == DT_FLAGS_1 && (val & 0x1)) { bind_now = true; } /* DF_1_NOW */
            }
        }
    }

    bool full_relro = has_relro && bind_now;
    if (full_relro) {
        print_check("RELRO",
                    true, "Full RELRO",
                    "",
                    "GOT完全只读，防止GOT覆写攻击");
    } else if (has_relro) {
        print_check_warn("RELRO",
                    false, "Partial RELRO",
                    "Partial RELRO",
                    "GOT.PLT仍可写，存在GOT覆写风险");
    } else {
        print_check("RELRO",
                    false, "", "No RELRO",
                    "无保护，GOT可任意写");
    }

    /* ──────────────────────────────────────────────────────── */
    /* 4. Stack Canary                                           */
    /* ──────────────────────────────────────────────────────── */
    bool canary = false;
    int dynsym_idx = elf.findSection(".dynsym");
    if (dynsym_idx >= 0) {
        auto syms = elf.getSymbols(dynsym_idx);
        for (auto& s : syms) {
            if (s.name == "__stack_chk_fail") { canary = true; break; }
        }
    }
    if (!canary) {
        int symtab_idx = elf.findSection(".symtab");
        if (symtab_idx >= 0) {
            auto syms = elf.getSymbols(symtab_idx);
            for (auto& s : syms) {
                if (s.name == "__stack_chk_fail") { canary = true; break; }
            }
        }
    }
    print_check("Stack Canary",
                canary, "Found", "Not found",
                canary ? "编译时启用-fstack-protector，检测栈溢出"
                       : "无栈溢出检测");

    /* ──────────────────────────────────────────────────────── */
    /* 5. FORTIFY_SOURCE                                         */
    /* ──────────────────────────────────────────────────────── */
    bool fortify = false;
    if (dynsym_idx >= 0) {
        auto syms = elf.getSymbols(dynsym_idx);
        for (auto& s : syms) {
            if (s.name.size() > 2 &&
                s.name[0] == '_' && s.name[1] == '_' &&
                s.name.find("_chk") != std::string::npos) {
                fortify = true; break;
            }
        }
    }
    print_check("FORTIFY",
                fortify, "Enabled", "Not found",
                fortify ? "不安全函数已替换为带检查版本"
                        : "未使用-D_FORTIFY_SOURCE");

    /* ──────────────────────────────────────────────────────── */
    /* 6. RPATH / RUNPATH                                        */
    /* ──────────────────────────────────────────────────────── */
    bool has_rpath    = false;
    bool has_runpath  = false;
    std::string rpath_val, runpath_val;

    if (dyn_idx >= 0) {
        SecInfo dsec = elf.getSection(dyn_idx);
        const uint8_t* ddata = elf.getSectionData(dyn_idx);
        int dynstr_idx = static_cast<int>(dsec.link);
        if (ddata) {
            size_t esz = elf.is64bit() ? sizeof(Elf64_Dyn) : sizeof(Elf32_Dyn);
            size_t cnt = dsec.size / esz;
            for (size_t i = 0; i < cnt; i++) {
                int64_t tag; uint32_t val32 = 0; uint64_t val64 = 0;
                if (elf.is64bit()) {
                    const Elf64_Dyn* d = reinterpret_cast<const Elf64_Dyn*>(
                        ddata + i * esz);
                    tag   = static_cast<int64_t>(elf.read64(
                        reinterpret_cast<const uint64_t*>(&d->d_tag)));
                    val64 = elf.read64(&d->d_un.d_val);
                } else {
                    const Elf32_Dyn* d = reinterpret_cast<const Elf32_Dyn*>(
                        ddata + i * esz);
                    tag   = static_cast<int64_t>(static_cast<int32_t>(
                        elf.read32(reinterpret_cast<const uint32_t*>(&d->d_tag))));
                    val32 = elf.read32(&d->d_un.d_val);
                }
                uint64_t val = elf.is64bit() ? val64 : val32;
                if (tag == DT_NULL) break;
                if (tag == DT_RPATH) {
                    has_rpath = true;
                    const char* s = elf.getString(dynstr_idx, (uint32_t)val);
                    if (s) rpath_val = s;
                }
                if (tag == DT_RUNPATH) {
                    has_runpath = true;
                    const char* s = elf.getString(dynstr_idx, (uint32_t)val);
                    if (s) runpath_val = s;
                }
            }
        }
    }
    print_check_warn("RPATH",
                     !has_rpath, "Not set", "Set",
                     has_rpath ? ("路径: " + rpath_val + " (库劫持风险)").c_str()
                               : "无运行时库路径注入风险");
    print_check_warn("RUNPATH",
                     !has_runpath, "Not set", "Set",
                     has_runpath ? ("路径: " + runpath_val).c_str()
                                 : "无运行时库路径注入风险");

    /* ──────────────────────────────────────────────────────── */
    /* 总结                                                      */
    /* ──────────────────────────────────────────────────────── */
    int score = (pie ? 1:0) + (nx ? 1:0) + (has_relro ? 1:0) +
                (bind_now ? 1:0) + (canary ? 1:0) + (fortify ? 1:0);
    int total = 6;

    printf("  %s\n", std::string(72, '-').c_str());
    const char* rating;
    const char* rating_color;
    if (score == total)       { rating = "优秀 (Excellent)"; rating_color = C_BGREEN; }
    else if (score >= total-2){ rating = "良好 (Good)";      rating_color = C_BYELLOW;}
    else if (score >= total/2){ rating = "一般 (Fair)";      rating_color = C_YELLOW; }
    else                      { rating = "危险 (Dangerous)"; rating_color = C_BRED;   }

    printf("  安全评分: %s%d/%d%s  总体评级: %s%s%s\n",
           C_BOLD, score, total, C_RESET,
           rating_color, rating, C_RESET);
}
