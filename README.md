# myreadelf — ELF 文件解析器

模拟 GNU `readelf` 工具的 C++17 实现，支持 ELF32/ELF64、大小端字节序，并在标准功能之上提供彩色输出、安全属性扫描（`--checksec`）和文件布局可视化（`--layout`）等扩展功能。

> 综合实训项目：ELF 文件解析器设计与实现

---

## 快速开始

```bash
git clone git@github.com:Perkinli/ELF-.git
cd ELF-
make
./myreadelf -h /bin/ls          # ELF 文件头
./myreadelf -a -C /bin/ls       # 彩色显示全部信息
./myreadelf --checksec /bin/ls  # 安全属性扫描
./myreadelf --layout /bin/ls    # 文件布局可视化
```

---

## 编译环境

| 依赖 | 版本要求 |
|------|---------|
| g++ / clang++ | 支持 C++17 |
| GNU Make | 任意版本 |
| Linux | 提供 `<elf.h>` |

```bash
make          # 编译
make clean    # 清理
make test     # 自动测试（可执行文件 / 共享库 / 目标文件）
```

---

## 选项一览

### 标准选项（兼容 GNU readelf）

| 选项 | 等价长选项 | 说明 |
|------|-----------|------|
| `-h` | `--file-headers` | 显示 ELF 文件头 |
| `-l` | `--program-headers` | 显示程序头（段） |
| `-S` | `--section-headers` | 显示节区头部 |
| `-t` | `--section-details` | 节区详细信息（`-S` 扩展） |
| `-e` | `--headers` | 全部头信息（`-h -l -S`） |
| `-s` | `--syms` | 显示符号表 |
| `-D` | `--dyn-syms` | 仅显示动态符号表 |
| `-r` | `--relocs` | 显示重定位信息 |
| `-d` | `--dynamic` | 显示动态段 |
| `-n` | `--notes` | 显示 Note 段 |
| `-g` | `--section-groups` | 显示节组（COMDAT groups） |
| `-A` | `--arch-specific` | 显示架构特定信息 |
| `-V` | `--version-info` | 显示版本信息 |
| `-I` | `--histogram` | 显示哈希桶柱状图 |
| `-x <n\|name>` | `--hex-dump` | 十六进制转储指定节区 |
| `-a` | `--all` | 显示全部信息 |

### 扩展选项（本项目特有）

| 选项 | 说明 |
|------|------|
| `--got-plt` | GOT/PLT 表深度分析，含延迟绑定机制解释 |
| `--checksec` | 安全属性全面扫描（PIE / NX / RELRO / Canary / FORTIFY） |
| `--layout` | ELF 文件物理布局可视化地图 |
| `-C` / `--color` | 启用 ANSI 彩色输出 |

---

## 示例输出

### ELF 文件头 `-h`

```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              DYN (共享目标文件/位置无关可执行文件)
  Machine:                           Advanced Micro Devices X86-64
  Entry point address:               0x6d30
  Number of section headers:         31
  Number of program headers:         13
```

### 安全属性扫描 `--checksec`

```
════════ 安全属性检查 (Security Hardening) ════════
  文件: /bin/ls

  属性           状态                 说明
  ------------------------------------------------------------------------
  PIE              PIE enabled         ✓  地址随机化（ASLR）有效，防ROP攻击
  NX               Enabled             ✓  栈不可执行，阻止shellcode注入
  RELRO            Full RELRO          ✓  GOT完全只读，防止GOT覆写攻击
  Stack Canary     Found               ✓  编译时启用-fstack-protector，检测栈溢出
  FORTIFY          Enabled             ✓  不安全函数已替换为带检查版本
  RPATH            Not set             ✓  无运行时库路径注入风险
  RUNPATH          Not set             ✓  无运行时库路径注入风险
  ------------------------------------------------------------------------
  安全评分: 6/6  总体评级: 优秀 (Excellent)
```

### 文件布局可视化 `--layout`

```
═══ ELF 文件布局地图 (File Layout Map) ══════════════════════════════
  文件: /bin/ls  大小: 139.0 KB (142312 bytes)

  Offset      Size      Type        Name                Bar (比例)
  --------------------------------------------------------------------------
  0x00000000      64 B  ELF Header                      [#...............]
  0x00000040     728 B  PHDRs       (13 entries)        [#...............]
  0x00000318      28 B  Section     .interp             [#...............]
  0x00000400    3.0 KB  Section     .dynsym             [#...............]
  0x00001000    1.5 KB  Section     .dynstr             [#...............]
  0x00001808    5.3 KB  Section     .rela.dyn           [#...............]
  0x00004020    1.6 KB  Section     .plt                [#...............]
  0x00004d70   80.4 KB  Section     .text               [#########.......]
  0x00019000   20.4 KB  Section     .rodata             [##..............]
  ...
  代码段: 83.0 KB   数据段: 50.4 KB   元数据: 24.3 KB
```

### GOT/PLT 深度分析 `--got-plt`

```
═══════════════════════════════════════════════════════
  GOT/PLT 深度分析报告
═══════════════════════════════════════════════════════

[安全属性]
  GNU_RELRO保护: 已启用
  BIND_NOW（立即绑定）: 已启用（Full RELRO）
  延迟绑定（Lazy Binding）: 已禁用

─── .got 节区（全局数据符号地址表）────────────────────
  作用：存放全局数据对象的运行时地址（GLOB_DAT重定位填写）

─── .plt 节区（过程链接表）─────────────────────────────
  作用：延迟绑定的跳转桩，第一次调用时触发动态链接器解析
```

---

## 项目结构

```
ELF-/
├── Makefile
└── src/
    ├── elf_parser.h          # 解析器接口 & 统一数据结构
    ├── elf_parser.cpp        # 核心解析实现（文件读取/字节序/节区/符号/重定位）
    ├── elf_strings.h         # ELF 常量到字符串的映射
    ├── color.h               # ANSI 彩色输出支持
    ├── main.cpp              # CLI 入口，getopt_long 参数解析
    ├── display_header.cpp    # -h  ELF 文件头
    ├── display_sections.cpp  # -S/-t 节区头部
    ├── display_segments.cpp  # -l  程序头（段）
    ├── display_symbols.cpp   # -s/-D 符号表
    ├── display_relocs.cpp    # -r  重定位信息
    ├── display_dynamic.cpp   # -d  动态段
    ├── display_misc.cpp      # -n/-g/-A/-V/-I/-x Note/节组/架构/版本/柱状图/十六进制
    ├── display_got_plt.cpp   # --got-plt  GOT/PLT 深度分析
    ├── display_checksec.cpp  # --checksec 安全属性扫描
    └── display_layout.cpp    # --layout   文件布局可视化
```

代码规模：**3210 行**（不含空行和注释约 2400 行有效代码）

---

## 支持的 ELF 格式

| 格式 | 说明 | 测试文件示例 |
|------|------|------------|
| ELF64 可执行文件 | ET_EXEC / ET_DYN（PIE） | `/bin/ls`、`/bin/bash` |
| ELF64 共享库 | ET_DYN `.so` | `/usr/lib/x86_64-linux-gnu/libc.so.6` |
| ELF64 可重定位目标文件 | ET_REL `.o` | `gcc -c foo.c -o foo.o` |
| ELF32 | 32 位 ABI | `gcc -m32 -c foo.c` |
| 大端/小端 | ELFDATA2MSB / ELFDATA2LSB | 均支持 |

---

## 技术要点

### 核心设计：无循环依赖的节区访问

`getString()` / `getSectionData()` / `getSectionName()` 三个函数直接操作原始 `Elf32/64_Shdr` 指针，不经过 `getSection()`，彻底消除循环递归。

### 字节序透明处理

```cpp
uint32_t ELFParser::read32(const void* p) const {
    uint32_t v; memcpy(&v, p, 4);
    if (!isLE_) v = __builtin_bswap32(v);
    return v;
}
```

所有字段读取统一经过字节序转换，ELF32/ELF64 对外提供相同接口。

### GOT/PLT 安全分析

通过扫描程序头检测 `GNU_RELRO`，扫描动态段检测 `DT_BIND_NOW` / `DF_1_NOW`，综合判断 Partial RELRO / Full RELRO 状态。

---

## 参考资料

- ELF 规范：System V ABI — *Tool Interface Standard (TIS) ELF Specification*
- 《程序员的自我修养——链接、装载与库》
- Linux 内核源码 `include/uapi/linux/elf.h`
- GNU Binutils `readelf` 源码
