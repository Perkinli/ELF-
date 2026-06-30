/*
 * elf_parser.cpp - ELF解析器核心实现
 *
 * 实现思路：
 *   将整个文件读入堆内存，通过reinterpret_cast直接将偏移处的字节
 *   解释为ELF结构体指针，避免反复的字节拷贝。
 *   所有read16/read32/read64函数统一处理字节序（大端/小端）。
 */

#include "elf_parser.h"
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/* ─── 构造/析构 ─────────────────────────────────────────────── */
ELFParser::ELFParser() = default;

ELFParser::~ELFParser() {
    unload();
}

void ELFParser::unload() {
    delete[] data_;
    data_     = nullptr;
    fileSize_ = 0;
    valid_    = false;
}

/* ─── 文件加载 ──────────────────────────────────────────────── */
bool ELFParser::load(const std::string& filename) {
    unload();
    filename_ = filename;

    int fd = open(filename.c_str(), O_RDONLY);
    if (fd < 0) {
        perror(("myreadelf: " + filename).c_str());
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return false;
    }
    fileSize_ = static_cast<size_t>(st.st_size);

    if (fileSize_ < EI_NIDENT) {
        fprintf(stderr, "myreadelf: %s: 文件太小，不是有效的ELF文件\n",
                filename.c_str());
        close(fd);
        return false;
    }

    data_ = new uint8_t[fileSize_];
    ssize_t rd = read(fd, data_, fileSize_);
    close(fd);

    if (rd < 0 || static_cast<size_t>(rd) != fileSize_) {
        fprintf(stderr, "myreadelf: %s: 读取文件失败\n", filename.c_str());
        delete[] data_;
        data_ = nullptr;
        return false;
    }

    return parseHeader();
}

/* ─── 解析ELF头，验证魔数和基本字段 ─────────────────────────── */
bool ELFParser::parseHeader() {
    /* 检查ELF魔数：0x7f 'E' 'L' 'F' */
    if (data_[EI_MAG0] != ELFMAG0 || data_[EI_MAG1] != ELFMAG1 ||
        data_[EI_MAG2] != ELFMAG2 || data_[EI_MAG3] != ELFMAG3) {
        fprintf(stderr, "myreadelf: %s: 不是ELF文件（魔数错误）\n",
                filename_.c_str());
        return false;
    }

    /* EI_CLASS: 文件位数 */
    switch (data_[EI_CLASS]) {
    case ELFCLASS32: is64_ = false; break;
    case ELFCLASS64: is64_ = true;  break;
    default:
        fprintf(stderr, "myreadelf: %s: 不支持的ELF类别 %d\n",
                filename_.c_str(), data_[EI_CLASS]);
        return false;
    }

    /* EI_DATA: 字节序 */
    switch (data_[EI_DATA]) {
    case ELFDATA2LSB: isLE_ = true;  break;  /* little-endian */
    case ELFDATA2MSB: isLE_ = false; break;  /* big-endian    */
    default:
        fprintf(stderr, "myreadelf: %s: 不支持的数据编码 %d\n",
                filename_.c_str(), data_[EI_DATA]);
        return false;
    }

    /* 最小长度检查 */
    size_t minHdr = is64_ ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr);
    if (fileSize_ < minHdr) {
        fprintf(stderr, "myreadelf: %s: 文件过短，ELF头不完整\n",
                filename_.c_str());
        return false;
    }

    valid_ = true;
    return true;
}

/* ─── 边界检查 ──────────────────────────────────────────────── */
bool ELFParser::inBounds(const void* p, size_t sz) const {
    auto base = reinterpret_cast<const uint8_t*>(p);
    return base >= data_ && (base + sz) <= (data_ + fileSize_);
}

/* ─── 字节序读取 ─────────────────────────────────────────────── */
uint16_t ELFParser::read16(const void* p) const {
    uint16_t v;
    memcpy(&v, p, 2);
    if (!isLE_) v = __builtin_bswap16(v);
    return v;
}

uint32_t ELFParser::read32(const void* p) const {
    uint32_t v;
    memcpy(&v, p, 4);
    if (!isLE_) v = __builtin_bswap32(v);
    return v;
}

uint64_t ELFParser::read64(const void* p) const {
    uint64_t v;
    memcpy(&v, p, 8);
    if (!isLE_) v = __builtin_bswap64(v);
    return v;
}

/* ─── 原始结构体访问 ─────────────────────────────────────────── */
const Elf32_Ehdr* ELFParser::ehdr32() const {
    return reinterpret_cast<const Elf32_Ehdr*>(data_);
}
const Elf64_Ehdr* ELFParser::ehdr64() const {
    return reinterpret_cast<const Elf64_Ehdr*>(data_);
}
const Elf32_Shdr* ELFParser::shdr32(int idx) const {
    auto hdr = ehdr32();
    uint32_t off = read32(&hdr->e_shoff);
    uint16_t esz = read16(&hdr->e_shentsize);
    return reinterpret_cast<const Elf32_Shdr*>(data_ + off + idx * esz);
}
const Elf64_Shdr* ELFParser::shdr64(int idx) const {
    auto hdr = ehdr64();
    uint64_t off = read64(&hdr->e_shoff);
    uint16_t esz = read16(&hdr->e_shentsize);
    return reinterpret_cast<const Elf64_Shdr*>(data_ + off + idx * esz);
}
const Elf32_Phdr* ELFParser::phdr32(int idx) const {
    auto hdr = ehdr32();
    uint32_t off = read32(&hdr->e_phoff);
    uint16_t esz = read16(&hdr->e_phentsize);
    return reinterpret_cast<const Elf32_Phdr*>(data_ + off + idx * esz);
}
const Elf64_Phdr* ELFParser::phdr64(int idx) const {
    auto hdr = ehdr64();
    uint64_t off = read64(&hdr->e_phoff);
    uint16_t esz = read16(&hdr->e_phentsize);
    return reinterpret_cast<const Elf64_Phdr*>(data_ + off + idx * esz);
}

/* ─── ELF头字段访问（统一接口） ─────────────────────────────── */
const unsigned char* ELFParser::e_ident() const { return data_; }

uint16_t ELFParser::getType() const {
    return is64_ ? read16(&ehdr64()->e_type) : read16(&ehdr32()->e_type);
}
uint16_t ELFParser::getMachine() const {
    return is64_ ? read16(&ehdr64()->e_machine) : read16(&ehdr32()->e_machine);
}
uint32_t ELFParser::getVersion() const {
    return is64_ ? read32(&ehdr64()->e_version) : read32(&ehdr32()->e_version);
}
uint64_t ELFParser::getEntry() const {
    return is64_ ? read64(&ehdr64()->e_entry)
                 : static_cast<uint64_t>(read32(&ehdr32()->e_entry));
}
uint64_t ELFParser::getPhoff() const {
    return is64_ ? read64(&ehdr64()->e_phoff)
                 : static_cast<uint64_t>(read32(&ehdr32()->e_phoff));
}
uint64_t ELFParser::getShoff() const {
    return is64_ ? read64(&ehdr64()->e_shoff)
                 : static_cast<uint64_t>(read32(&ehdr32()->e_shoff));
}
uint32_t ELFParser::getFlags() const {
    return is64_ ? read32(&ehdr64()->e_flags) : read32(&ehdr32()->e_flags);
}
uint16_t ELFParser::getEhsize() const {
    return is64_ ? read16(&ehdr64()->e_ehsize) : read16(&ehdr32()->e_ehsize);
}
uint16_t ELFParser::getPhentsize() const {
    return is64_ ? read16(&ehdr64()->e_phentsize) : read16(&ehdr32()->e_phentsize);
}
uint16_t ELFParser::getPhnum() const {
    return is64_ ? read16(&ehdr64()->e_phnum) : read16(&ehdr32()->e_phnum);
}
uint16_t ELFParser::getShentsize() const {
    return is64_ ? read16(&ehdr64()->e_shentsize) : read16(&ehdr32()->e_shentsize);
}
uint16_t ELFParser::getShnum() const {
    return is64_ ? read16(&ehdr64()->e_shnum) : read16(&ehdr32()->e_shnum);
}
uint16_t ELFParser::getShstrndx() const {
    return is64_ ? read16(&ehdr64()->e_shstrndx) : read16(&ehdr32()->e_shstrndx);
}

/* ─── 节区计数 ──────────────────────────────────────────────── */
int ELFParser::sectionCount() const {
    if (!valid_) return 0;
    return static_cast<int>(getShnum());
}

/* ─── 程序头（段）计数 ──────────────────────────────────────── */
int ELFParser::segmentCount() const {
    if (!valid_) return 0;
    return static_cast<int>(getPhnum());
}

/* ─── 获取节区描述（统一接口，屏蔽32/64差异） ──────────────── */
SecInfo ELFParser::getSection(int idx) const {
    SecInfo s{};
    if (!valid_ || idx < 0 || idx >= sectionCount()) return s;

    if (is64_) {
        const Elf64_Shdr* sh = shdr64(idx);
        s.name_idx  = read32(&sh->sh_name);
        s.type      = read32(&sh->sh_type);
        s.flags     = read64(&sh->sh_flags);
        s.addr      = read64(&sh->sh_addr);
        s.offset    = read64(&sh->sh_offset);
        s.size      = read64(&sh->sh_size);
        s.link      = read32(&sh->sh_link);
        s.info      = read32(&sh->sh_info);
        s.addralign = read64(&sh->sh_addralign);
        s.entsize   = read64(&sh->sh_entsize);
    } else {
        const Elf32_Shdr* sh = shdr32(idx);
        s.name_idx  = read32(&sh->sh_name);
        s.type      = read32(&sh->sh_type);
        s.flags     = read32(&sh->sh_flags);
        s.addr      = read32(&sh->sh_addr);
        s.offset    = read32(&sh->sh_offset);
        s.size      = read32(&sh->sh_size);
        s.link      = read32(&sh->sh_link);
        s.info      = read32(&sh->sh_info);
        s.addralign = read32(&sh->sh_addralign);
        s.entsize   = read32(&sh->sh_entsize);
    }

    /* 通过shstrndx节区的字符串表解析名称 */
    const char* nm = getSectionName(idx);
    s.name = nm ? nm : "";
    return s;
}

/* ─── 获取节区名称（直接访问原始结构，不通过getSection避免递归） ── */
const char* ELFParser::getSectionName(int idx) const {
    if (!valid_ || idx < 0 || idx >= sectionCount()) return nullptr;
    uint32_t name_idx;
    if (is64_) name_idx = read32(&shdr64(idx)->sh_name);
    else       name_idx = read32(&shdr32(idx)->sh_name);
    uint16_t strndx = getShstrndx();
    if (strndx == SHN_UNDEF || strndx >= static_cast<uint16_t>(sectionCount()))
        return nullptr;
    return getString(static_cast<int>(strndx), name_idx);
}

/* ─── 获取节区原始数据指针（直接访问，不调用getSection避免递归） ── */
const uint8_t* ELFParser::getSectionData(int idx) const {
    if (!valid_ || idx < 0 || idx >= sectionCount()) return nullptr;
    uint32_t stype;
    uint64_t soff, ssz;
    if (is64_) {
        const Elf64_Shdr* sh = shdr64(idx);
        stype = read32(&sh->sh_type);
        soff  = read64(&sh->sh_offset);
        ssz   = read64(&sh->sh_size);
    } else {
        const Elf32_Shdr* sh = shdr32(idx);
        stype = read32(&sh->sh_type);
        soff  = read32(&sh->sh_offset);
        ssz   = read32(&sh->sh_size);
    }
    if (stype == SHT_NOBITS) return nullptr;
    if (soff + ssz > fileSize_) return nullptr;
    return data_ + soff;
}

/* ─── 在字符串表节区中查找字符串（直接访问，不调用getSection） ── */
const char* ELFParser::getString(int sec_idx, uint32_t offset) const {
    if (!valid_ || sec_idx < 0 || sec_idx >= sectionCount()) return nullptr;
    uint32_t stype;
    uint64_t soff, ssz;
    if (is64_) {
        const Elf64_Shdr* sh = shdr64(sec_idx);
        stype = read32(&sh->sh_type);
        soff  = read64(&sh->sh_offset);
        ssz   = read64(&sh->sh_size);
    } else {
        const Elf32_Shdr* sh = shdr32(sec_idx);
        stype = read32(&sh->sh_type);
        soff  = read32(&sh->sh_offset);
        ssz   = read32(&sh->sh_size);
    }
    if (stype != SHT_STRTAB) return nullptr;
    if (offset >= ssz || soff + offset >= fileSize_) return nullptr;
    return reinterpret_cast<const char*>(data_ + soff + offset);
}

/* ─── 按名称查找节区 ────────────────────────────────────────── */
int ELFParser::findSection(const std::string& name) const {
    for (int i = 0; i < sectionCount(); i++) {
        const char* n = getSectionName(i);
        if (n && name == n) return i;
    }
    return -1;
}

/* ─── 读取符号表 ────────────────────────────────────────────── */
std::vector<SymInfo> ELFParser::getSymbols(int sec_idx) const {
    std::vector<SymInfo> result;
    if (!valid_ || sec_idx < 0 || sec_idx >= sectionCount()) return result;

    SecInfo sec = getSection(sec_idx);
    if (sec.type != SHT_SYMTAB && sec.type != SHT_DYNSYM) return result;

    const uint8_t* secData = getSectionData(sec_idx);
    if (!secData) return result;

    int strtab_idx = static_cast<int>(sec.link);

    if (is64_) {
        if (sec.entsize < sizeof(Elf64_Sym)) return result;
        size_t count = sec.size / sec.entsize;
        for (size_t i = 0; i < count; i++) {
            const Elf64_Sym* sym = reinterpret_cast<const Elf64_Sym*>(
                secData + i * sec.entsize);
            SymInfo info;
            info.name_idx = read32(&sym->st_name);
            info.value    = read64(&sym->st_value);
            info.size     = read64(&sym->st_size);
            info.info     = sym->st_info;
            info.other    = sym->st_other;
            info.shndx    = read16(&sym->st_shndx);
            const char* nm = getString(strtab_idx, info.name_idx);
            info.name     = nm ? nm : "";
            result.push_back(info);
        }
    } else {
        if (sec.entsize < sizeof(Elf32_Sym)) return result;
        size_t count = sec.size / sec.entsize;
        for (size_t i = 0; i < count; i++) {
            const Elf32_Sym* sym = reinterpret_cast<const Elf32_Sym*>(
                secData + i * sec.entsize);
            SymInfo info;
            info.name_idx = read32(&sym->st_name);
            info.value    = static_cast<uint64_t>(read32(&sym->st_value));
            info.size     = static_cast<uint64_t>(read32(&sym->st_size));
            info.info     = sym->st_info;
            info.other    = sym->st_other;
            info.shndx    = read16(&sym->st_shndx);
            const char* nm = getString(strtab_idx, info.name_idx);
            info.name     = nm ? nm : "";
            result.push_back(info);
        }
    }
    return result;
}

/* ─── 读取重定位表 ──────────────────────────────────────────── */
std::vector<RelaInfo> ELFParser::getRelocations(int sec_idx) const {
    std::vector<RelaInfo> result;
    if (!valid_ || sec_idx < 0 || sec_idx >= sectionCount()) return result;

    SecInfo sec = getSection(sec_idx);
    bool isRela = (sec.type == SHT_RELA);
    bool isRel  = (sec.type == SHT_REL);
    if (!isRela && !isRel) return result;

    const uint8_t* secData = getSectionData(sec_idx);
    if (!secData) return result;

    /* 关联的符号表节区 */
    int sym_sec = static_cast<int>(sec.link);

    if (is64_) {
        size_t entrySz = isRela ? sizeof(Elf64_Rela) : sizeof(Elf64_Rel);
        if (sec.entsize < entrySz) return result;
        size_t count = sec.size / sec.entsize;
        for (size_t i = 0; i < count; i++) {
            RelaInfo ri;
            ri.has_addend = isRela;
            if (isRela) {
                const Elf64_Rela* r = reinterpret_cast<const Elf64_Rela*>(
                    secData + i * sec.entsize);
                ri.offset  = read64(&r->r_offset);
                ri.info    = read64(&r->r_info);
                ri.addend  = static_cast<int64_t>(read64(
                    reinterpret_cast<const uint64_t*>(&r->r_addend)));
            } else {
                const Elf64_Rel* r = reinterpret_cast<const Elf64_Rel*>(
                    secData + i * sec.entsize);
                ri.offset  = read64(&r->r_offset);
                ri.info    = read64(&r->r_info);
                ri.addend  = 0;
            }
            ri.sym_idx = static_cast<uint32_t>(ELF64_R_SYM(ri.info));
            ri.type    = static_cast<uint32_t>(ELF64_R_TYPE(ri.info));

            /* 解析符号名 */
            if (sym_sec >= 0) {
                auto syms = getSymbols(sym_sec);
                if (ri.sym_idx < syms.size())
                    ri.sym_name = syms[ri.sym_idx].name;
            }
            result.push_back(ri);
        }
    } else {
        size_t entrySz = isRela ? sizeof(Elf32_Rela) : sizeof(Elf32_Rel);
        if (sec.entsize < entrySz) return result;
        size_t count = sec.size / sec.entsize;
        for (size_t i = 0; i < count; i++) {
            RelaInfo ri;
            ri.has_addend = isRela;
            if (isRela) {
                const Elf32_Rela* r = reinterpret_cast<const Elf32_Rela*>(
                    secData + i * sec.entsize);
                ri.offset  = read32(&r->r_offset);
                ri.info    = read32(&r->r_info);
                ri.addend  = static_cast<int64_t>(
                    static_cast<int32_t>(read32(
                        reinterpret_cast<const uint32_t*>(&r->r_addend))));
            } else {
                const Elf32_Rel* r = reinterpret_cast<const Elf32_Rel*>(
                    secData + i * sec.entsize);
                ri.offset  = read32(&r->r_offset);
                ri.info    = read32(&r->r_info);
                ri.addend  = 0;
            }
            ri.sym_idx = static_cast<uint32_t>(ELF32_R_SYM(ri.info));
            ri.type    = static_cast<uint32_t>(ELF32_R_TYPE(ri.info));

            if (sym_sec >= 0) {
                auto syms = getSymbols(sym_sec);
                if (ri.sym_idx < syms.size())
                    ri.sym_name = syms[ri.sym_idx].name;
            }
            result.push_back(ri);
        }
    }
    return result;
}
