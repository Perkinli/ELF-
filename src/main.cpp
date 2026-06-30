/*
 * main.cpp - myreadelf ELF解析工具主程序
 *
 * 本工具模拟GNU readelf的功能，用于分析ELF格式文件。
 * 用法：myreadelf <选项> <ELF文件> [...]
 *
 * 主要选项：
 *   -h           显示ELF文件头
 *   -l           显示程序头（段）
 *   -S           显示节区头部
 *   -t           显示节区详细信息（-S的扩展）
 *   -s           显示符号表
 *   -e           显示全部头部（等价于 -h -l -S）
 *   -r           显示重定位信息
 *   -d           显示动态段
 *   -n           显示note段
 *   -V           显示版本信息
 *   -I           显示符号哈希桶柱状图
 *   -x <num|name> 以十六进制显示指定节区内容
 *   --got-plt    显示GOT/PLT表深度分析（扩展功能）
 *   -a           显示所有信息
 *   -v           显示版本
 *   -H           显示帮助
 */

#include "elf_parser.h"
#include "elf_strings.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <getopt.h>

/* ── 显示函数前向声明 ─────────────────────────────────────── */
void display_elf_header(const ELFParser& elf);
void display_section_headers(const ELFParser& elf, bool detailed);
void display_program_headers(const ELFParser& elf);
void display_symbol_table(const ELFParser& elf, bool use_dynamic);
void display_relocations(const ELFParser& elf);
void display_dynamic_section(const ELFParser& elf);
void display_notes(const ELFParser& elf);
void display_hex_dump(const ELFParser& elf, int sec_num,
                     const std::string& sec_name);
void display_version_info(const ELFParser& elf);
void display_histogram(const ELFParser& elf);
void display_section_groups(const ELFParser& elf);
void display_arch_specific(const ELFParser& elf);
void display_got_plt(const ELFParser& elf);

/* ── 帮助信息 ─────────────────────────────────────────────── */
static void print_usage(const char* prog) {
    fprintf(stderr,
        "用法: %s <选项> <文件>...\n"
        "\n"
        "显示ELF格式文件的内容信息。\n"
        "\n"
        "选项:\n"
        "  -a              显示所有信息（等价于: -h -l -S -s -r -d -V -A -I）\n"
        "  -h              显示ELF文件头\n"
        "  -l              显示程序头（段头）\n"
        "  -S              显示节区头部\n"
        "  -t              显示节区详细信息（-S的扩展版本）\n"
        "  -e              显示全部头信息（等价于: -h -l -S）\n"
        "  -s              显示符号表\n"
        "  -D              配合 -s，仅显示动态符号表\n"
        "  -r              显示重定位信息\n"
        "  -d              显示动态段\n"
        "  -n              显示note段信息\n"
        "  -g              显示节组信息（COMDAT groups）\n"
        "  -A              显示处理器架构特定信息\n"
        "  -V              显示版本段信息\n"
        "  -I              显示符号哈希桶柱状图\n"
        "  -x <num|name>   以十六进制显示指定节区内容\n"
        "  --got-plt       显示GOT/PLT表深度分析（扩展功能）\n"
        "  -W              宽输出模式\n"
        "  -v              显示版本信息\n"
        "  -H              显示此帮助\n"
        "\n"
        "示例:\n"
        "  %s -h /bin/ls\n"
        "  %s -S /bin/ls\n"
        "  %s -a /usr/lib/libc.so.6\n"
        "  %s --got-plt /bin/ls\n"
        "  %s -x .rodata /bin/ls\n",
        prog, prog, prog, prog, prog, prog);
}

static void print_version() {
    printf("myreadelf 1.0 - ELF文件解析工具\n");
    printf("实训项目：ELF文件解析器设计与实现\n");
    printf("支持格式：ELF32 / ELF64，小端/大端字节序\n");
}

/* ── 长选项定义 ──────────────────────────────────────────── */
static struct option long_options[] = {
    {"all",          no_argument,       nullptr, 'a'},
    {"file-headers", no_argument,       nullptr, 'h'},
    {"program-headers", no_argument,    nullptr, 'l'},
    {"segments",     no_argument,       nullptr, 'l'},
    {"section-headers", no_argument,    nullptr, 'S'},
    {"sections",     no_argument,       nullptr, 'S'},
    {"section-details", no_argument,    nullptr, 't'},
    {"headers",      no_argument,       nullptr, 'e'},
    {"syms",         no_argument,       nullptr, 's'},
    {"symbols",      no_argument,       nullptr, 's'},
    {"dyn-syms",     no_argument,       nullptr, 'D'},
    {"relocs",       no_argument,       nullptr, 'r'},
    {"dynamic",      no_argument,       nullptr, 'd'},
    {"notes",        no_argument,       nullptr, 'n'},
    {"version-info", no_argument,       nullptr, 'V'},
    {"arch-specific",no_argument,       nullptr, 'A'},
    {"section-groups",no_argument,      nullptr, 'g'},
    {"histogram",    no_argument,       nullptr, 'I'},
    {"hex-dump",     required_argument, nullptr, 'x'},
    {"got-plt",      no_argument,       nullptr,  1 },  /* 自定义 */
    {"wide",         no_argument,       nullptr, 'W'},
    {"version",      no_argument,       nullptr, 'v'},
    {"help",         no_argument,       nullptr, 'H'},
    {nullptr, 0, nullptr, 0}
};

/* ── 处理单个ELF文件 ──────────────────────────────────────── */
static int process_file(const std::string& filename,
                        const ELFOptions& opts) {
    ELFParser elf;
    if (!elf.load(filename)) return 1;

    /* 多文件时显示文件名分隔符 */
    printf("\nFile: %s\n", filename.c_str());

    if (opts.file_header)
        display_elf_header(elf);

    if (opts.program_headers)
        display_program_headers(elf);

    if (opts.section_headers || opts.section_details)
        display_section_headers(elf, opts.section_details);

    if (opts.symbols)
        display_symbol_table(elf, opts.use_dynamic_syms);

    if (opts.relocs)
        display_relocations(elf);

    if (opts.dynamic)
        display_dynamic_section(elf);

    if (opts.notes)
        display_notes(elf);

    if (opts.section_groups)
        display_section_groups(elf);

    if (opts.arch_specific)
        display_arch_specific(elf);

    if (opts.version_info)
        display_version_info(elf);

    if (opts.histogram)
        display_histogram(elf);

    if (opts.hex_section_num >= 0 || !opts.hex_section_name.empty())
        display_hex_dump(elf, opts.hex_section_num, opts.hex_section_name);

    if (opts.got_plt)
        display_got_plt(elf);

    return 0;
}

/* ── main ─────────────────────────────────────────────────── */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    ELFOptions opts;
    int opt;

    while ((opt = getopt_long(argc, argv, "ahlStesrDdnVAIgx:WvH",
                              long_options, nullptr)) != -1) {
        switch (opt) {
        case 'a':
            opts.file_header = opts.program_headers = opts.section_headers =
            opts.symbols = opts.relocs = opts.dynamic = opts.notes =
            opts.version_info = opts.arch_specific = opts.histogram =
            opts.section_groups = true;
            break;
        case 'h': opts.file_header     = true; break;
        case 'l': opts.program_headers = true; break;
        case 'S': opts.section_headers = true; break;
        case 't': opts.section_details = true; opts.section_headers = true; break;
        case 'e':
            opts.file_header = opts.program_headers = opts.section_headers = true;
            break;
        case 's': opts.symbols         = true; break;
        case 'D': opts.use_dynamic_syms= true; opts.symbols = true; break;
        case 'r': opts.relocs          = true; break;
        case 'd': opts.dynamic         = true; break;
        case 'n': opts.notes           = true; break;
        case 'V': opts.version_info    = true; break;
        case 'A': opts.arch_specific   = true; break;
        case 'g': opts.section_groups  = true; break;
        case 'I': opts.histogram       = true; break;
        case 'W': opts.wide            = true; break;
        case 1:   opts.got_plt         = true; break;  /* --got-plt */
        case 'x':
            /* -x 可接受节区编号或名称 */
            if (optarg && optarg[0] >= '0' && optarg[0] <= '9') {
                opts.hex_section_num = atoi(optarg);
            } else if (optarg) {
                opts.hex_section_name = optarg;
                opts.hex_section_num  = -1;
            }
            break;
        case 'v':
            print_version();
            return 0;
        case 'H':
            print_usage(argv[0]);
            return 0;
        default:
            fprintf(stderr, "未知选项。使用 -H 查看帮助。\n");
            return 1;
        }
    }

    /* 没有指定任何显示选项则显示帮助 */
    if (!opts.file_header && !opts.program_headers && !opts.section_headers &&
        !opts.section_details && !opts.symbols && !opts.relocs &&
        !opts.dynamic && !opts.notes && !opts.version_info &&
        !opts.arch_specific && !opts.section_groups &&
        !opts.histogram && !opts.got_plt &&
        opts.hex_section_num < 0 && opts.hex_section_name.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    /* 处理每个输入文件 */
    int ret = 0;
    for (int i = optind; i < argc; i++) {
        ret |= process_file(argv[i], opts);
    }

    return ret;
}
