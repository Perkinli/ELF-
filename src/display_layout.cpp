/*
 * display_layout.cpp - ELF文件物理布局可视化 (--layout)
 *
 * 以ASCII地图的形式展示ELF文件中各部分在文件内的物理位置，
 * 直观揭示"链接视图"与文件字节的对应关系：
 *
 *   偏移      大小     类型        名称
 *   0x00000  [  64B]  ELF Header
 *   0x00040  [ 728B]  PHDRs        (13 entries)
 *   0x00318  [  28B]  Section      .interp
 *   ...
 *
 * 同时绘制比例尺条形图，让文件布局一目了然。
 */

#include "elf_parser.h"
#include "elf_strings.h"
#include "color.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

struct LayoutEntry {
    uint64_t    offset;
    uint64_t    size;
    std::string type;    /* ELF Header / PHDRs / SHDRs / Section / Gap */
    std::string name;
    const char* color;
};

static std::string human_size(uint64_t sz) {
    char buf[32];
    if      (sz >= 1024*1024) snprintf(buf, sizeof(buf), "%.1f MB", sz/1048576.0);
    else if (sz >= 1024)      snprintf(buf, sizeof(buf), "%.1f KB", sz/1024.0);
    else                      snprintf(buf, sizeof(buf), "%lu B",   (unsigned long)sz);
    return buf;
}

void display_layout(const ELFParser& elf) {
    std::vector<LayoutEntry> entries;

    uint64_t fileSize = static_cast<uint64_t>(elf.rawSize());

    /* ── ELF Header ─────────────────────────────────────── */
    {
        LayoutEntry e;
        e.offset = 0;
        e.size   = elf.getEhsize();
        e.type   = "ELF Header";
        e.name   = "";
        e.color  = C_BWHITE;
        entries.push_back(e);
    }

    /* ── Program Headers ────────────────────────────────── */
    if (elf.getPhoff() > 0 && elf.getPhnum() > 0) {
        LayoutEntry e;
        e.offset = elf.getPhoff();
        e.size   = static_cast<uint64_t>(elf.getPhnum()) * elf.getPhentsize();
        e.type   = "PHDRs";
        char buf[32];
        snprintf(buf, sizeof(buf), "(%d entries)", elf.getPhnum());
        e.name  = buf;
        e.color = C_BCYAN;
        entries.push_back(e);
    }

    /* ── 各节区 ──────────────────────────────────────────── */
    for (int i = 0; i < elf.sectionCount(); i++) {
        SecInfo s = elf.getSection(i);
        if (s.type == SHT_NULL || s.type == SHT_NOBITS) continue;
        if (s.size == 0) continue;

        LayoutEntry e;
        e.offset = s.offset;
        e.size   = s.size;
        e.type   = "Section";
        e.name   = s.name;
        /* 按节区类型着色 */
        e.color  = shtype_color(s.type);
        entries.push_back(e);
    }

    /* ── Section Header Table ────────────────────────────── */
    if (elf.getShoff() > 0 && elf.sectionCount() > 0) {
        LayoutEntry e;
        e.offset = elf.getShoff();
        e.size   = static_cast<uint64_t>(elf.sectionCount()) * elf.getShentsize();
        e.type   = "SHDRs";
        char buf[32];
        snprintf(buf, sizeof(buf), "(%d entries)", elf.sectionCount());
        e.name  = buf;
        e.color = C_BYELLOW;
        entries.push_back(e);
    }

    /* ── 按偏移排序 ──────────────────────────────────────── */
    std::sort(entries.begin(), entries.end(),
              [](const LayoutEntry& a, const LayoutEntry& b){
                  return a.offset < b.offset;
              });

    /* ── 输出头部 ────────────────────────────────────────── */
    printf("\n%s═══ ELF 文件布局地图 (File Layout Map) ══════════════════════════════%s\n",
           C_BOLD, C_RESET);
    printf("  文件: %s%s%s  大小: %s%s%s (%s%lu%s bytes)\n\n",
           C_CYAN, elf.filename().c_str(), C_RESET,
           C_YELLOW, human_size(fileSize).c_str(), C_RESET,
           C_DIM, (unsigned long)fileSize, C_RESET);

    /* 列标题 */
    printf("  %s%-10s  %-8s  %-10s  %-18s  %s%s\n",
           C_BOLD,
           "Offset", "Size", "Type", "Name", "Bar (比例)", C_RESET);
    printf("  %s\n", std::string(74, '-').c_str());

    /* ── 逐行打印 + ASCII 比例条 ─────────────────────────── */
    const int BAR_WIDTH = 16;
    uint64_t prev_end = 0;

    for (auto& e : entries) {
        /* 检测间隙 */
        if (e.offset > prev_end) {
            uint64_t gap = e.offset - prev_end;
            printf("  %s0x%08lx  %8s  %-10s  %-18s%s\n",
                   C_DIM,
                   (unsigned long)prev_end,
                   human_size(gap).c_str(),
                   "(gap)",
                   "",
                   C_RESET);
        }

        /* 比例条：按占文件比例填充 */
        int filled = (fileSize > 0)
            ? static_cast<int>((double)e.size / fileSize * BAR_WIDTH + 0.5)
            : 0;
        if (filled < 1 && e.size > 0) filled = 1;
        if (filled > BAR_WIDTH) filled = BAR_WIDTH;

        char bar[BAR_WIDTH + 3];
        bar[0] = '[';
        for (int j = 1; j <= BAR_WIDTH; j++)
            bar[j] = (j <= filled) ? '#' : '.';
        bar[BAR_WIDTH + 1] = ']';
        bar[BAR_WIDTH + 2] = '\0';

        std::string dname = e.name.size() > 18 ? e.name.substr(0, 17) + ">" : e.name;

        printf("  0x%08lx  %s%8s%s  %s%-10s%s  %s%-18s%s  %s%s%s\n",
               (unsigned long)e.offset,
               C_DIM, human_size(e.size).c_str(), C_RESET,
               C_MAGENTA, e.type.c_str(), C_RESET,
               e.color, dname.c_str(), C_RESET,
               C_GREEN, bar, C_RESET);

        prev_end = e.offset + e.size;
    }

    /* 文件尾部间隙 */
    if (prev_end < fileSize) {
        uint64_t tail = fileSize - prev_end;
        printf("  %s0x%08lx  %8s  %-10s%s\n",
               C_DIM,
               (unsigned long)prev_end,
               human_size(tail).c_str(),
               "(tail gap)",
               C_RESET);
    }

    printf("  %s\n", std::string(74, '-').c_str());

    /* ── 统计摘要 ────────────────────────────────────────── */
    uint64_t code_sz = 0, data_sz = 0, meta_sz = 0;
    for (int i = 0; i < elf.sectionCount(); i++) {
        SecInfo s = elf.getSection(i);
        if (s.type == SHT_NULL || s.size == 0) continue;
        if (s.flags & SHF_EXECINSTR)       code_sz += s.size;
        else if (s.flags & SHF_ALLOC)      data_sz += s.size;
        else                               meta_sz  += s.size;
    }

    printf("  代码段: %s%-8s%s  数据段: %s%-8s%s  元数据: %s%-8s%s\n",
           C_BGREEN, human_size(code_sz).c_str(), C_RESET,
           C_YELLOW, human_size(data_sz).c_str(), C_RESET,
           C_DIM,    human_size(meta_sz).c_str(), C_RESET);
}
