/*
 * display_misc.cpp - 辅助显示功能
 *   - Notes段显示 (-n)
 *   - 十六进制转储 (-x)
 *   - 版本信息 (-V)
 *   - 哈希桶柱状图 (-I)
 */

#include "elf_parser.h"
#include "elf_strings.h"
#include <cstdio>
#include <cctype>
#include <cstring>
#include <algorithm>
#include <vector>

/* ─── Notes段显示 ──────────────────────────────────────────── */
/*
 * Note段用于在ELF文件中嵌入额外信息（不影响程序执行）：
 *   .note.gnu.build-id     - 文件的唯一构建ID（SHA1/MD5哈希）
 *   .note.ABI-tag          - 最低支持的内核版本
 *   .note.gnu.property     - 硬件/ABI属性（如控制流完整性CET支持）
 */
void display_notes(const ELFParser& elf) {
    bool found = false;

    for (int i = 0; i < elf.sectionCount(); i++) {
        SecInfo s = elf.getSection(i);
        if (s.type != SHT_NOTE) continue;

        const uint8_t* data = elf.getSectionData(i);
        if (!data) continue;

        printf("\nDisplaying notes found in: %s\n", s.name.c_str());
        printf("  %-20s %-8s %-12s Description\n",
               "Owner", "Data size", "Type");

        size_t pos = 0;
        while (pos + 12 <= s.size) {
            uint32_t namesz = elf.read32(data + pos);
            uint32_t descsz = elf.read32(data + pos + 4);
            uint32_t type   = elf.read32(data + pos + 8);
            pos += 12;

            /* name字段（4字节对齐） */
            size_t name_padded = (namesz + 3) & ~3u;
            const char* name = (namesz > 0) ?
                reinterpret_cast<const char*>(data + pos) : "";

            /* 打印行 */
            printf("  %-20s 0x%06x  0x%08x  ", name, descsz, type);

            /* 识别常见Note类型 */
            if (strcmp(name, "GNU") == 0) {
                switch (type) {
                case 1: printf("NT_GNU_ABI_TAG (ABI version tag)"); break;
                case 3: printf("NT_GNU_BUILD_ID (unique build ID bitstring)"); break;
                case 4: printf("NT_GNU_GOLD_VERSION (gold version)"); break;
                case 5: printf("NT_GNU_PROPERTY_TYPE_0"); break;
                default: printf("Unknown note type"); break;
                }
            } else if (strcmp(name, "Linux") == 0) {
                printf("NT_VERSION");
            } else {
                printf("Unknown note type");
            }
            printf("\n");

            /* 打印desc内容（以十六进制） */
            if (descsz > 0 && pos + name_padded + descsz <= s.size) {
                const uint8_t* desc = data + pos + name_padded;
                /* 特殊：GNU_BUILD_ID显示为十六进制字符串 */
                if (strcmp(name, "GNU") == 0 && type == 3) {
                    printf("    Build ID: ");
                    for (uint32_t j = 0; j < descsz; j++)
                        printf("%02x", desc[j]);
                    printf("\n");
                } else if (strcmp(name, "GNU") == 0 && type == 1) {
                    /* ABI tag：显示系统和最低内核版本 */
                    if (descsz >= 16) {
                        uint32_t os   = elf.read32(desc);
                        uint32_t vmaj = elf.read32(desc + 4);
                        uint32_t vmin = elf.read32(desc + 8);
                        uint32_t vsub = elf.read32(desc + 12);
                        const char* os_str = (os == 0) ? "Linux" :
                                             (os == 1) ? "Hurd" :
                                             (os == 2) ? "Solaris" : "Unknown";
                        printf("    OS: %s, ABI: %u.%u.%u\n",
                               os_str, vmaj, vmin, vsub);
                    }
                }
            }

            size_t desc_padded = (descsz + 3) & ~3u;
            pos += name_padded + desc_padded;
        }
        found = true;
    }

    if (!found)
        printf("\n此文件没有note段。\n");
}

/* ─── 十六进制转储 ─────────────────────────────────────────── */
void display_hex_dump(const ELFParser& elf, int sec_num,
                     const std::string& sec_name) {
    int idx = -1;

    if (sec_num >= 0) {
        /* 按编号查找 */
        if (sec_num < elf.sectionCount())
            idx = sec_num;
    } else if (!sec_name.empty()) {
        /* 按名称查找 */
        idx = elf.findSection(sec_name);
    }

    if (idx < 0) {
        if (sec_num >= 0)
            printf("没有编号为 %d 的节区。\n", sec_num);
        else
            printf("没有名为 '%s' 的节区。\n", sec_name.c_str());
        return;
    }

    SecInfo s = elf.getSection(idx);
    const uint8_t* data = elf.getSectionData(idx);

    if (!data || s.size == 0) {
        printf("节区 '%s' 为空或不包含文件数据。\n", s.name.c_str());
        return;
    }

    printf("\nHex dump of section '%s':\n", s.name.c_str());

    for (size_t off = 0; off < s.size; off += 16) {
        /* 地址 */
        printf("  0x%08lx ", (unsigned long)(s.addr + off));

        /* 十六进制 */
        for (int j = 0; j < 16; j++) {
            if (off + j < s.size)
                printf("%02x ", data[off + j]);
            else
                printf("   ");
            if (j == 7) printf(" ");
        }

        /* ASCII */
        printf(" ");
        for (int j = 0; j < 16 && off + j < s.size; j++) {
            uint8_t c = data[off + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("\n");
    }
}

/* ─── 版本信息显示 ─────────────────────────────────────────── */
/*
 * GNU版本信息节区（.gnu.version, .gnu.version_r, .gnu.version_d）
 * 记录了：
 *   - 每个动态符号需要的库版本（如 puts@GLIBC_2.2.5）
 *   - 此文件对其他库版本的需求（VERNEED）
 *   - 此文件导出符号的版本定义（VERDEF）
 */
void display_version_info(const ELFParser& elf) {
    bool found = false;

    /* .gnu.version_r（VERNEED：本文件需要的外部版本） */
    int vr_idx = elf.findSection(".gnu.version_r");
    if (vr_idx >= 0) {
        SecInfo sec = elf.getSection(vr_idx);
        const uint8_t* data = elf.getSectionData(vr_idx);
        int dynstr_idx = static_cast<int>(sec.link);

        if (data) {
            printf("\nVersion needs section '%s' contains:\n", sec.name.c_str());
            printf("  Address: 0x%016lx  Offset: 0x%06lx  Link: %d (%s)\n\n",
                   (unsigned long)sec.addr,
                   (unsigned long)sec.offset,
                   dynstr_idx,
                   dynstr_idx >= 0 ? elf.getSectionName(dynstr_idx) : "?");

            size_t pos = 0;
            int entry = 0;
            while (pos + sizeof(Elf64_Verneed) <= sec.size) {
                const Elf64_Verneed* vn = reinterpret_cast<const Elf64_Verneed*>(
                    data + pos);
                uint16_t cnt  = elf.read16(&vn->vn_cnt);
                uint32_t file = elf.read32(&vn->vn_file);
                uint32_t aux_off = elf.read32(&vn->vn_aux);
                uint32_t next_off = elf.read32(&vn->vn_next);

                const char* filename = elf.getString(dynstr_idx, file);
                printf("  %04d: Version: %u  File: %-20s  Cnt: %u\n",
                       entry++,
                       elf.read16(&vn->vn_version),
                       filename ? filename : "?",
                       cnt);

                /* 遍历aux条目 */
                size_t aux_pos = pos + aux_off;
                for (uint16_t j = 0; j < cnt; j++) {
                    if (aux_pos + sizeof(Elf64_Vernaux) > sec.size) break;
                    const Elf64_Vernaux* va = reinterpret_cast<const Elf64_Vernaux*>(
                        data + aux_pos);
                    uint32_t vname = elf.read32(&va->vna_name);
                    uint16_t other = elf.read16(&va->vna_other);
                    const char* vn_str = elf.getString(dynstr_idx, vname);
                    printf("    0x%08x:   Name: %-20s  Flags: 0x%x  Version: %u\n",
                           elf.read32(&va->vna_hash),
                           vn_str ? vn_str : "?",
                           elf.read16(&va->vna_flags),
                           other);
                    uint32_t next_aux = elf.read32(&va->vna_next);
                    if (!next_aux) break;
                    aux_pos += next_aux;
                }

                if (!next_off) break;
                pos += next_off;
            }
            found = true;
        }
    }

    if (!found)
        printf("\n此文件没有版本信息节区。\n");
}

/* ─── GNU哈希桶柱状图 ──────────────────────────────────────── */
/*
 * .gnu.hash和.hash节区包含符号哈希表，用于动态链接时快速查找符号。
 * 柱状图展示哈希桶的利用率分布，理想情况下每个桶含1个符号（均匀分布）。
 */
void display_histogram(const ELFParser& elf) {
    int hash_idx = elf.findSection(".gnu.hash");
    bool is_gnu = (hash_idx >= 0);
    if (!is_gnu) hash_idx = elf.findSection(".hash");

    if (hash_idx < 0) {
        printf("\n此文件没有哈希表节区。\n");
        return;
    }

    SecInfo sec = elf.getSection(hash_idx);
    const uint8_t* data = elf.getSectionData(hash_idx);
    if (!data) return;

    if (is_gnu) {
        /* GNU哈希表格式 */
        uint32_t nbuckets  = elf.read32(data);
        uint32_t symoffset = elf.read32(data + 4);
        uint32_t bloom_sz  = elf.read32(data + 8);
        /* uint32_t bloom_shift = elf.read32(data + 12); */

        printf("\nHistogram for bucket list length (GNU Hash):\n");
        printf("  nbuckets = %u, symndx = %u, bloom_size = %u\n",
               nbuckets, symoffset, bloom_sz);
        (void)symoffset; (void)bloom_sz;
    } else {
        /* ELF哈希表格式 */
        uint32_t nbuckets = elf.read32(data);
        uint32_t nchains  = elf.read32(data + 4);

        printf("\nHistogram for bucket list length (ELF Hash):\n");
        printf("  nbuckets = %u, nchains = %u\n", nbuckets, nchains);

        /* 统计桶长度分布 */
        const uint8_t* buckets = data + 8;
        const uint8_t* chains  = buckets + nbuckets * 4;
        std::vector<int> lengths(nbuckets, 0);

        for (uint32_t i = 0; i < nbuckets; i++) {
            uint32_t sym = elf.read32(buckets + i * 4);
            int len = 0;
            while (sym != STN_UNDEF && len < 1000) {
                if (sym >= nchains) break;
                sym = elf.read32(chains + sym * 4);
                len++;
            }
            lengths[i] = len;
        }

        /* 输出分布 */
        int maxlen = *std::max_element(lengths.begin(), lengths.end());
        std::vector<int> count(maxlen + 1, 0);
        for (int l : lengths) count[l]++;

        printf("  Length  Number     %%  Cumulative\n");
        int cumulative = 0;
        for (int l = 0; l <= maxlen; l++) {
            cumulative += count[l];
            printf("  %6d  %6d  %5.1f%%  %6.1f%%\n",
                   l, count[l],
                   100.0 * count[l] / nbuckets,
                   100.0 * cumulative / nbuckets);
        }
    }
}

/* ─── 节组显示 -g ───────────────────────────────────────────── */
/*
 * SHT_GROUP 节区用于 C++ 模板实例化的 COMDAT 去重：
 *   - 多个编译单元可能各自实例化同一模板，产生同名节区
 *   - 链接器通过 COMDAT 标记只保留其中一份，避免重复
 * 格式：第一个 uint32_t 是 flags（GRP_COMDAT=1），
 *       后续每个 uint32_t 是该组包含的节区索引
 * sh_link → 符号表节区，sh_info → 组签名符号的索引
 */
void display_section_groups(const ELFParser& elf) {
    bool found = false;

    for (int i = 0; i < elf.sectionCount(); i++) {
        SecInfo s = elf.getSection(i);
        if (s.type != SHT_GROUP) continue;

        const uint8_t* data = elf.getSectionData(i);
        if (!data || s.size < 4) continue;

        /* 取组签名符号的名称 */
        std::string sig_name;
        int sym_sec = static_cast<int>(s.link);
        uint32_t sig_idx = s.info;
        if (sym_sec >= 0 && sym_sec < elf.sectionCount()) {
            auto syms = elf.getSymbols(sym_sec);
            if (sig_idx < syms.size())
                sig_name = syms[sig_idx].name;
        }

        uint32_t flags      = elf.read32(data);
        size_t   n_sections = (s.size - 4) / 4;
        const char* flag_str = (flags & GRP_COMDAT) ? "COMDAT " : "";

        printf("\n%sgroup section [%5d] `%s' [%s] contains %zu sections:\n",
               flag_str, i, s.name.c_str(), sig_name.c_str(), n_sections);
        printf("   [Index]    Name\n");

        for (size_t j = 0; j < n_sections; j++) {
            uint32_t    sec_idx  = elf.read32(data + 4 + j * 4);
            const char* sec_name = elf.getSectionName(static_cast<int>(sec_idx));
            printf("   [%5u]   %s\n", sec_idx, sec_name ? sec_name : "?");
        }
        found = true;
    }

    if (!found)
        printf("\nThere are no section groups in this file.\n");
}

/* ─── 架构相关信息 -A ───────────────────────────────────────── */
/*
 * 对于 x86/x86-64：解析 .note.gnu.property 中的 GNU_PROPERTY_X86_*
 *   - GNU_PROPERTY_X86_FEATURE_1_IBT   : 间接分支跟踪（CET IBT）
 *   - GNU_PROPERTY_X86_FEATURE_1_SHSTK : 影子栈（CET SHSTK）
 * 对于其他架构（ARM/AARCH64）暂不展开，仅报告无附加信息。
 */
void display_arch_specific(const ELFParser& elf) {
    uint16_t mach = elf.getMachine();

    if (mach != EM_X86_64 && mach != EM_386) {
        /* 非 x86 平台：读取 ARM 等属性节区（本工具暂未实现） */
        printf("\n此架构（machine=0x%x）无处理器特定附加信息。\n", mach);
        return;
    }

    /* x86/x86-64：扫描 .note.gnu.property */
    int prop_idx = elf.findSection(".note.gnu.property");
    if (prop_idx < 0) {
        /* readelf -A 在没有该节区时静默，此处同样不输出 */
        return;
    }

    SecInfo    sec  = elf.getSection(prop_idx);
    const uint8_t* data = elf.getSectionData(prop_idx);
    if (!data) return;

    printf("\nGNU property notes for segment/section .note.gnu.property:\n");

    size_t pos = 0;
    while (pos + 12 <= sec.size) {
        uint32_t namesz  = elf.read32(data + pos);
        uint32_t descsz  = elf.read32(data + pos + 4);
        /* uint32_t type  = elf.read32(data + pos + 8); */
        pos += 12;

        size_t name_padded = (namesz + 3) & ~3u;
        if (pos + name_padded > sec.size) break;
        const char* name = reinterpret_cast<const char*>(data + pos);
        pos += name_padded;

        if (strcmp(name, "GNU") != 0 || pos + descsz > sec.size) {
            pos += (descsz + 3) & ~3u;
            continue;
        }

        /* 遍历 GNU 属性列表（每条：pr_type u32 + pr_datasz u32 + data） */
        size_t dpos = 0;
        while (dpos + 8 <= descsz) {
            uint32_t pr_type   = elf.read32(data + pos + dpos);
            uint32_t pr_datasz = elf.read32(data + pos + dpos + 4);
            dpos += 8;
            if (dpos + pr_datasz > descsz) break;

            /* GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002 */
            if (pr_type == 0xc0000002u && pr_datasz >= 4) {
                uint32_t feat = elf.read32(data + pos + dpos);
                printf("  x86 ISA used: ");
                if (feat & 0x1) printf("IBT ");
                if (feat & 0x2) printf("SHSTK ");
                if (!(feat & 0x3)) printf("(none)");
                printf("\n");
                printf("  x86 feature: ");
                if (feat & 0x1) printf("CET IBT (间接分支跟踪) ");
                if (feat & 0x2) printf("CET SHSTK (影子栈) ");
                if (!(feat & 0x3)) printf("无");
                printf("\n");
            }
            dpos += (pr_datasz + 3) & ~3u;
        }
        pos += (descsz + 3) & ~3u;
    }
}
