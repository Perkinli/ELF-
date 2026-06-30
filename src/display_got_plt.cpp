/*
 * display_got_plt.cpp - GOT/PLT表深度分析 (--got-plt 选项)
 *
 * ═══════════════════════════════════════════════════════════════
 *  GOT（Global Offset Table，全局偏移表）的作用：
 * ═══════════════════════════════════════════════════════════════
 *  GOT将代码中的"符号引用"与其运行时地址解耦，实现位置无关代码（PIC）。
 *
 *  .got        - 存放全局数据符号的地址（GLOB_DAT类型重定位填写）
 *  .got.plt    - 存放函数符号的地址（PLT机制使用）
 *
 *  GOT[0] = .dynamic段的地址
 *  GOT[1] = 动态链接器link_map结构的地址（运行时由ld.so填写）
 *  GOT[2] = 动态链接器的符号解析入口（_dl_runtime_resolve）
 *  GOT[3..N] = 各个动态符号的实际地址（初始时指向对应的PLT stub）
 *
 * ═══════════════════════════════════════════════════════════════
 *  PLT（Procedure Linkage Table，过程链接表）的作用：
 * ═══════════════════════════════════════════════════════════════
 *  PLT实现动态函数的"延迟绑定"（Lazy Binding）：
 *    第一次调用某函数 → PLT stub → 触发ld.so解析真实地址 → 填入GOT
 *    后续调用同一函数 → PLT stub → 直接从GOT读取地址 → 跳转（O(1)）
 *
 *  x86_64的PLT stub（每项16字节）：
 *    PLT[0]（解析器stub）：
 *      pushq  *GOT[1](%rip)   ; 压入link_map
 *      jmpq   *GOT[2](%rip)   ; 跳入 _dl_runtime_resolve
 *
 *    PLT[N]（普通函数stub）：
 *      jmpq   *GOT[N+2](%rip) ; 直接跳到已解析地址（或进入下一条）
 *      pushq  $index           ; 压入PLT表项索引（重定位表偏移）
 *      jmpq   PLT[0]           ; 跳到解析器stub
 *
 * ═══════════════════════════════════════════════════════════════
 *  安全含义：
 * ═══════════════════════════════════════════════════════════════
 *  GNU_RELRO + FULL RELRO：将.got.plt标记为只读，防止攻击者覆写
 *  GOT表项以劫持程序控制流（GOT Overwrite Attack）。
 *  检测方式：查看PT_GNU_RELRO段的范围是否覆盖了.got.plt。
 */

#include "elf_parser.h"
#include "elf_strings.h"
#include <cstdio>
#include <vector>
#include <string>

/* ─── 辅助：检查是否启用了RELRO保护 ────────────────────── */
static bool check_relro(const ELFParser& elf) {
    for (int i = 0; i < elf.segmentCount(); i++) {
        uint32_t ptype;
        if (elf.is64bit())
            ptype = elf.read32(&elf.phdr64(i)->p_type);
        else
            ptype = elf.read32(&elf.phdr32(i)->p_type);
        if (ptype == 0x6474e552) /* PT_GNU_RELRO */
            return true;
    }
    return false;
}

/* ─── 辅助：打印GOT表内容 ───────────────────────────────── */
static void print_got_section(const ELFParser& elf, int got_idx,
                              const std::vector<SymInfo>& dynsyms,
                              const std::vector<RelaInfo>& rela_dyn) {
    (void)dynsyms;
    SecInfo sec = elf.getSection(got_idx);
    const uint8_t* data = elf.getSectionData(got_idx);
    if (!data || sec.size == 0) return;

    size_t ptrSize = elf.is64bit() ? 8 : 4;
    size_t count   = sec.size / ptrSize;

    printf("\n节区 '%s' 内容（起始地址 0x%lx，共 %zu 项）：\n",
           sec.name.c_str(),
           (unsigned long)sec.addr,
           count);
    printf("  %-4s  %-18s  %-18s  %s\n",
           "IDX", "地址(VirtAddr)", "当前值", "对应符号");
    printf("  %s\n", std::string(70, '-').c_str());

    for (size_t i = 0; i < count; i++) {
        uint64_t entry_addr = sec.addr + i * ptrSize;
        uint64_t entry_val  = 0;
        if (elf.is64bit())
            entry_val = elf.read64(data + i * ptrSize);
        else
            entry_val = elf.read32(data + i * ptrSize);

        /* 找对应的重定位项 */
        std::string sym_name = "-";
        for (const auto& rela : rela_dyn) {
            if (rela.offset == entry_addr && !rela.sym_name.empty()) {
                sym_name = rela.sym_name;
                break;
            }
        }

        if (elf.is64bit())
            printf("  [%2zu]  0x%016lx  0x%016lx  %s\n",
                   i, (unsigned long)entry_addr,
                   (unsigned long)entry_val, sym_name.c_str());
        else
            printf("  [%2zu]  0x%08lx          0x%08lx          %s\n",
                   i, (unsigned long)entry_addr,
                   (unsigned long)entry_val, sym_name.c_str());
    }
}

/* ─── 辅助：打印PLT表和对应符号 ────────────────────────── */
static void print_plt_section(const ELFParser& elf,
                              int plt_idx,
                              const std::vector<SymInfo>& dynsyms,
                              const std::vector<RelaInfo>& rela_plt) {
    (void)dynsyms;
    SecInfo plt_sec = elf.getSection(plt_idx);
    if (plt_sec.size == 0) return;

    /* PLT表项大小：x86_64=16B, i386=16B */
    size_t plt_entry_size = 16;
    size_t num_entries = plt_sec.size / plt_entry_size;

    printf("\n节区 '%s' 内容（起始地址 0x%lx，共 %zu 项，每项 %zu 字节）：\n",
           plt_sec.name.c_str(),
           (unsigned long)plt_sec.addr,
           num_entries,
           plt_entry_size);

    printf("  PLT[0] = 公共解析入口（调用 _dl_runtime_resolve）\n\n");

    printf("  %-5s  %-18s  %-18s  %s\n",
           "IDX", "PLT地址", "GOT.PLT地址", "符号名称");
    printf("  %s\n", std::string(70, '-').c_str());

    /* PLT[0]是公共解析入口，跳过 */
    for (size_t i = 1; i < num_entries && (i - 1) < rela_plt.size(); i++) {
        uint64_t plt_addr = plt_sec.addr + i * plt_entry_size;
        const RelaInfo& rela = rela_plt[i - 1];

        if (elf.is64bit())
            printf("  [%3zu]  0x%016lx  0x%016lx  %s\n",
                   i, (unsigned long)plt_addr,
                   (unsigned long)rela.offset,
                   rela.sym_name.c_str());
        else
            printf("  [%3zu]  0x%08lx          0x%08lx          %s\n",
                   i, (unsigned long)plt_addr,
                   (unsigned long)rela.offset,
                   rela.sym_name.c_str());
    }
}

/* ─── 主函数 ─────────────────────────────────────────────── */
void display_got_plt(const ELFParser& elf) {
    printf("\n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("  GOT/PLT 深度分析报告\n");
    printf("═══════════════════════════════════════════════════════\n");

    /* ── 安全属性检测 ── */
    bool has_relro = check_relro(elf);
    printf("\n[安全属性]\n");
    printf("  GNU_RELRO保护: %s\n", has_relro ? "已启用" : "未启用");

    /* 检测BIND_NOW（立即绑定，意味着Full RELRO） */
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
                if (elf.is64bit()) {
                    const Elf64_Dyn* d = reinterpret_cast<const Elf64_Dyn*>(
                        ddata + i * esz);
                    tag = static_cast<int64_t>(elf.read64(&d->d_tag));
                } else {
                    const Elf32_Dyn* d = reinterpret_cast<const Elf32_Dyn*>(
                        ddata + i * esz);
                    tag = static_cast<int32_t>(elf.read32(&d->d_tag));
                }
                if (tag == DT_BIND_NOW || tag == 0x6ffffffb) {
                    /* FLAGS_1 with NOW flag */
                    bind_now = true;
                }
                if (tag == DT_NULL) break;
            }
        }
    }
    printf("  BIND_NOW（立即绑定）: %s\n", bind_now ? "已启用（Full RELRO）" : "未启用（Lazy Binding）");
    printf("  延迟绑定（Lazy Binding）: %s\n",
           bind_now ? "已禁用" : "已启用（首次调用时解析符号）");

    /* ── 收集动态符号表 ── */
    int dynsym_idx = elf.findSection(".dynsym");
    std::vector<SymInfo> dynsyms;
    if (dynsym_idx >= 0)
        dynsyms = elf.getSymbols(dynsym_idx);

    /* ── .rela.dyn重定位 ── */
    std::vector<RelaInfo> rela_dyn;
    for (int i = 0; i < elf.sectionCount(); i++) {
        SecInfo s = elf.getSection(i);
        if ((s.type == SHT_RELA || s.type == SHT_REL) &&
            s.name.find(".dyn") != std::string::npos) {
            auto v = elf.getRelocations(i);
            rela_dyn.insert(rela_dyn.end(), v.begin(), v.end());
        }
    }

    /* ── .rela.plt重定位 ── */
    std::vector<RelaInfo> rela_plt;
    int rela_plt_idx = elf.findSection(".rela.plt");
    if (rela_plt_idx < 0) rela_plt_idx = elf.findSection(".rel.plt");
    if (rela_plt_idx >= 0)
        rela_plt = elf.getRelocations(rela_plt_idx);

    /* ── 显示 .got 节区 ── */
    printf("\n");
    printf("─── .got 节区（全局数据符号地址表）────────────────────\n");
    printf("  作用：存放全局数据对象的运行时地址（GLOB_DAT重定位填写）\n");
    int got_idx = elf.findSection(".got");
    if (got_idx >= 0) {
        print_got_section(elf, got_idx, dynsyms, rela_dyn);
    } else {
        printf("  （未找到 .got 节区）\n");
    }

    /* ── 显示 .got.plt 节区 ── */
    printf("\n");
    printf("─── .got.plt 节区（函数指针表，PLT延迟绑定使用）──────\n");
    printf("  作用：PLT存根通过此表间接跳转到动态函数\n");
    printf("  GOT.PLT[0] = .dynamic地址（运行时填写）\n");
    printf("  GOT.PLT[1] = link_map地址（ld.so填写）\n");
    printf("  GOT.PLT[2] = _dl_runtime_resolve入口（ld.so填写）\n");
    printf("  GOT.PLT[3..N] = 各动态函数地址（首次调用前指向PLT+6）\n");

    int got_plt_idx = elf.findSection(".got.plt");
    if (got_plt_idx >= 0) {
        print_got_section(elf, got_plt_idx, dynsyms, rela_plt);
    } else {
        printf("  （未找到 .got.plt 节区）\n");
    }

    /* ── 显示 .plt 节区 ── */
    printf("\n");
    printf("─── .plt 节区（过程链接表）────────────────────────────\n");
    printf("  作用：每个动态函数对应一个PLT存根，实现延迟绑定跳转\n");
    printf("  调用流程：call func@plt → PLT存根 → GOT.PLT[N]\n");
    printf("           首次：GOT[N]→下一条指令→压索引→PLT[0]→ld.so解析→填写GOT[N]\n");
    printf("           后续：GOT[N]→真实函数地址（直接跳转）\n");

    int plt_idx = elf.findSection(".plt");
    if (plt_idx >= 0 && !rela_plt.empty()) {
        print_plt_section(elf, plt_idx, dynsyms, rela_plt);
    } else if (plt_idx < 0) {
        printf("  （未找到 .plt 节区）\n");
    } else {
        printf("  （未找到 .rela.plt 重定位表，PLT符号无法解析）\n");
    }

    /* ── 总结：动态符号解析链 ── */
    printf("\n");
    printf("─── 动态函数调用链总结 ──────────────────────────────────\n");
    if (!rela_plt.empty()) {
        printf("  共 %zu 个动态函数通过PLT调用：\n", rela_plt.size());
        for (size_t i = 0; i < rela_plt.size(); i++) {
            printf("    [%2zu] %-30s  GOT.PLT @ 0x%lx\n",
                   i + 1,
                   rela_plt[i].sym_name.c_str(),
                   (unsigned long)rela_plt[i].offset);
        }
    } else {
        printf("  （无PLT动态函数）\n");
    }

    printf("\n═══════════════════════════════════════════════════════\n");
}
