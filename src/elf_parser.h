/*
 * elf_parser.h - ELF文件解析器核心接口
 *
 * ELF (Executable and Linkable Format) 是Linux/Unix系统上的标准二进制格式。
 * 本模块提供统一的接口，支持32位和64位ELF文件的解析。
 *
 * 设计思路：
 *   - 使用系统提供的 <elf.h> 定义标准结构体（避免手工定义，减少错误）
 *   - 将文件整体读入内存，通过指针直接访问各结构体
 *   - 对外提供统一的64位接口，内部根据文件类别分派到32/64位代码路径
 */
#pragma once

#include <elf.h>
#include <string>
#include <vector>
#include <cstdint>

/* ─── 命令行选项 ─────────────────────────────────────────────── */
struct ELFOptions {
    bool file_header      = false;  // -h  ELF文件头
    bool program_headers  = false;  // -l  程序头（段头）
    bool section_headers  = false;  // -S  节区头部
    bool section_details  = false;  // -t  节区详细信息
    bool symbols          = false;  // -s  符号表
    bool use_dynamic_syms = false;  // -D  仅使用动态符号表
    bool relocs           = false;  // -r  重定位信息
    bool unwind           = false;  // -u  unwind信息
    bool dynamic          = false;  // -d  动态段
    bool notes            = false;  // -n  note段
    bool version_info     = false;  // -V  版本信息
    bool arch_specific    = false;  // -A  架构相关信息
    bool histogram        = false;  // -I  哈希桶柱状图
    bool section_groups   = false;  // -g       节组信息
    bool checksec         = false;  // --checksec 安全属性扫描
    bool layout           = false;  // --layout   文件布局可视化
    bool all_headers      = false;  // -e       = -h + -l + -S
    bool got_plt          = false;  // --got-plt GOT/PLT分析（扩展功能）
    bool wide             = false;  // -W       宽输出
    int  hex_section_num  = -1;     // -x <number>
    std::string hex_section_name;   // -x <name>
};

/* ─── 统一的符号表项（内部表示，屏蔽32/64位差异） ─────────── */
struct SymInfo {
    uint32_t    name_idx;   // 在字符串表中的偏移
    uint64_t    value;
    uint64_t    size;
    uint8_t     info;       // STB_* | STT_*
    uint8_t     other;      // 可见性
    uint16_t    shndx;      // 所在节区索引
    std::string name;       // 已解析的名称字符串
};

/* ─── 统一的节区描述符 ────────────────────────────────────────── */
struct SecInfo {
    uint32_t    name_idx;
    uint32_t    type;
    uint64_t    flags;
    uint64_t    addr;
    uint64_t    offset;
    uint64_t    size;
    uint32_t    link;
    uint32_t    info;
    uint64_t    addralign;
    uint64_t    entsize;
    std::string name;
};

/* ─── 统一的重定位表项 ────────────────────────────────────────── */
struct RelaInfo {
    uint64_t    offset;
    uint64_t    info;
    int64_t     addend;
    bool        has_addend;  // true = RELA, false = REL
    uint32_t    sym_idx;
    uint32_t    type;
    std::string sym_name;
};

/* ─── ELF解析器主类 ──────────────────────────────────────────── */
class ELFParser {
public:
    ELFParser();
    ~ELFParser();

    /* 加载文件，返回false表示失败 */
    bool load(const std::string& filename);
    void unload();

    bool isValid()  const { return valid_;  }
    bool is64bit()  const { return is64_;   }
    bool isLE()     const { return isLE_;   }

    const std::string& filename() const { return filename_; }
    const uint8_t*     rawData()  const { return data_;     }
    size_t             rawSize()  const { return fileSize_;  }

    /* ── ELF头字段（统一以uint64_t返回，32位情况下自动零扩展） ── */
    const unsigned char* e_ident()  const;
    uint16_t  getType()        const;
    uint16_t  getMachine()     const;
    uint32_t  getVersion()     const;
    uint64_t  getEntry()       const;
    uint64_t  getPhoff()       const;
    uint64_t  getShoff()       const;
    uint32_t  getFlags()       const;
    uint16_t  getEhsize()      const;
    uint16_t  getPhentsize()   const;
    uint16_t  getPhnum()       const;
    uint16_t  getShentsize()   const;
    uint16_t  getShnum()       const;
    uint16_t  getShstrndx()    const;

    /* ── 节区访问 ─────────────────────────────────────────────── */
    int          sectionCount()          const;
    SecInfo      getSection(int idx)     const;
    const char*  getSectionName(int idx) const;
    const uint8_t* getSectionData(int idx) const;
    int          findSection(const std::string& name) const;

    /* ── 程序头（段）访问 ─────────────────────────────────────── */
    int          segmentCount() const;

    /* ── 符号表 ───────────────────────────────────────────────── */
    std::vector<SymInfo> getSymbols(int sec_idx) const;

    /* ── 重定位表 ─────────────────────────────────────────────── */
    std::vector<RelaInfo> getRelocations(int sec_idx) const;

    /* ── 字符串表 ─────────────────────────────────────────────── */
    const char* getString(int sec_idx, uint32_t offset) const;

    /* ── 字节序读取辅助（按需做大小端转换） ─────────────────── */
    uint16_t read16(const void* p) const;
    uint32_t read32(const void* p) const;
    uint64_t read64(const void* p) const;

    /* ── 访问原始Elf32/Elf64结构（供显示层直接使用） ──────── */
    const Elf32_Ehdr* ehdr32() const;
    const Elf64_Ehdr* ehdr64() const;
    const Elf32_Shdr* shdr32(int idx) const;
    const Elf64_Shdr* shdr64(int idx) const;
    const Elf32_Phdr* phdr32(int idx) const;
    const Elf64_Phdr* phdr64(int idx) const;

private:
    uint8_t*    data_     = nullptr;
    size_t      fileSize_ = 0;
    bool        valid_    = false;
    bool        is64_     = false;
    bool        isLE_     = true;
    std::string filename_;

    bool parseHeader();

    /* 边界检查 */
    bool inBounds(const void* p, size_t sz) const;
};
