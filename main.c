#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "libelf/elf_user.h"
#include "libelf/elf32.h"

#include "exp.h"

#define VERBOSE 1

#if VERBOSE
#define INFO(...)            \
    do                       \
    {                        \
        printf(__VA_ARGS__); \
    } while (0)
#else
#define INFO(...)
#endif

#define LD_MODE_ELF_TO_EXP 0
#define LD_MODE_REDIR__EXP 1

#define PAGE_SIZE (1024)

char path_appelf[512];
char path_symtab[512];
char path_exp[512];

char *sysbuild_date;

char ld_mode = LD_MODE_ELF_TO_EXP;

FILE *f_appelf;
FILE *f_symtab;
FILE *f_exp;

size_t sz_appelf;
size_t sz_symtab;
size_t sz_rel_info;
size_t sz_exp;

uint8_t *buf_appelf;
uint8_t *buf_symtab;
uint8_t *buf_exp;

uint8_t *buf_rec_table;
uint8_t buf_text_rodata[4 * 1048576];
uint8_t buf_data[4 * 1048576];
uint8_t buf_rel_info[8 * 1048576];

uint32_t off_dynsym_exp;
uint32_t off_dynstr_exp;
uint32_t off_rel_plt_exp;
uint32_t num_rel_plt_exp;
uint32_t off_rel_dyn_exp;
uint32_t num_rel_dyn_exp;
uint32_t off_got_exp;

uint32_t total_export_syms = 0;

elf_t elf_app;
exp_header_t *exp_h;

uint32_t syssym_hash;
void Usage();

uint32_t calc_sys_sym_hash()
{
    uint32_t hash = 0x5a5a1234;
    int fr;
    uint32_t addr;
    char type;
    char s[1024];

    int i = 0;

    fr = sscanf((const char *)&buf_symtab[i], "%08X %c %s", &addr, &type, s);
    while (fr == 3)
    {
        if ((type >= 'A') && type <= 'Z')
        {
            // printf("adr:%08x, type:%c, sym:%s\n", addr, type, s);
            hash ^= addr;
            hash ^= hash << 16;
        }
        i++;
        if (buf_symtab[i] == 0)
        {
            break;
        }
        while ((buf_symtab[i] != '\n'))
        {
            i++;
            if (buf_symtab[i] == 0)
            {
                break;
            }
        }
        fr = sscanf((const char *)&buf_symtab[i], "%08X %c %s", &addr, &type, s);
    }

    return hash;
}

void dump_str_to_ldscript()
{
    FILE *lds = fopen("lds.txt", "wb+");
    if (!lds)
    {
        return;
    }
    int fr;
    uint32_t addr;
    char type;
    char s[1024];
    fseek(f_symtab, 0, SEEK_SET);

    fr = fscanf(f_symtab, "%08X %c %s\n", &addr, &type, s);
    while (fr == 3)
    {
        if ((type >= 'A') && type <= 'Z')
        {
            // printf("adr:%08x, type:%c, sym:%s\n", addr, type, s);
            fprintf(lds, "PROVIDE(%s = 0x%08x);\n", s, addr);
        }
        fr = fscanf(f_symtab, "%08X %c %s\n", &addr, &type, s);
    }

    fclose(lds);

    // exit(0);
}

uint32_t search_sys_sym(char *sym_name)
{
    int fr;
    uint32_t addr;
    char type;
    char s[1024];
    fseek(f_symtab, 0, SEEK_SET);
    int i = 0;

    fr = sscanf((const char *)&buf_symtab[i], "%08X %c %s", &addr, &type, s);
    while (fr == 3)
    {
        if ((type >= 'A') && type <= 'Z')
        {
            // printf("adr:%08x, type:%c, sym:%s\n", addr, type, s);
            if (strcmp(sym_name, s) == 0)
            {
                return addr;
            }
        }
        i++;
        if (buf_symtab[i] == 0)
        {
            break;
        }
        while ((buf_symtab[i] != '\n'))
        {
            i++;
            if (buf_symtab[i] == 0)
            {
                break;
            }
        }
        fr = sscanf((const char *)&buf_symtab[i], "%08X %c %s", &addr, &type, s);
    }

    return 0;
}

int main(int argc, const char *argv[])
{
    int ret = 0;
    int vaild = 0;
    if (argc == 7)
    {
        for (int i = 0; i < 7; i++)
        {
            if (strcmp(argv[i], "--appelf") == 0)
            {
                strcpy(path_appelf, argv[i + 1]);
                i++;
                vaild++;
            }
            if (strcmp(argv[i], "--symtab") == 0)
            {
                strcpy(path_symtab, argv[i + 1]);
                i++;
                vaild++;
            }
            if (strcmp(argv[i], "--exp") == 0)
            {
                strcpy(path_exp, argv[i + 1]);
                i++;
                vaild++;
            }
        }
        if (vaild != 3)
        {
            Usage();
        }
        ld_mode = LD_MODE_ELF_TO_EXP;
    }
    else if (argc == 5)
    {
        for (int i = 0; i < 5; i++)
        {
            if (strcmp(argv[i], "--symtab") == 0)
            {
                strcpy(path_symtab, argv[i + 1]);
                i++;
                vaild++;
            }
            if (strcmp(argv[i], "--exp") == 0)
            {
                strcpy(path_exp, argv[i + 1]);
                i++;
                vaild++;
            }
        }
        if (vaild != 2)
        {
            Usage();
        }
        ld_mode = LD_MODE_REDIR__EXP;
    }
    else
    {
        Usage();
    }

    if (ld_mode == LD_MODE_ELF_TO_EXP)
    {
        f_symtab = fopen(path_symtab, "rb");
        if (!f_symtab)
        {
            fprintf(stderr, "Failed to open symtab\n");
            exit(-1);
        }
        f_appelf = fopen(path_appelf, "rb");
        if (!f_appelf)
        {
            fprintf(stderr, "Failed to open appelf\n");
            fclose(f_symtab);
            exit(-1);
        }
        f_exp = fopen(path_exp, "wb");
        if (!f_exp)
        {
            fprintf(stderr, "Failed to open exp\n");
            fclose(f_symtab);
            fclose(f_appelf);
            exit(-1);
        }

        // printf("tests:%08x\n", search_sys_sym("f_open"));

        fseek(f_symtab, 0, SEEK_END);
        sz_symtab = ftell(f_symtab);
        fseek(f_symtab, 0, SEEK_SET);

        fseek(f_appelf, 0, SEEK_END);
        sz_appelf = ftell(f_appelf);
        fseek(f_appelf, 0, SEEK_SET);

        buf_appelf = malloc(sz_appelf);
        if (!buf_appelf)
        {
            fprintf(stderr, "Failed to alloc memory 2\n");
            ret = -1;
            goto exit1;
        }

        buf_symtab = malloc(sz_symtab);
        if (!buf_symtab)
        {
            fprintf(stderr, "Failed to alloc memory 1\n");
            ret = -1;
            goto exit1;
        }
        fread(buf_appelf, 1, sz_appelf, f_appelf);
        fread(buf_symtab, 1, sz_symtab, f_symtab);

        elf_app.elfFile = buf_appelf;
        elf_app.elfClass = ELFCLASS32;
        elf_app.elfSize = sz_appelf;

        if (elf_checkFile(&elf_app))
        {
            fprintf(stderr, "Error AppELF Format!\n");
            goto exit2;
        }
        uint32_t Relocate_vbase, sz_rel, fo_rel;
        uint32_t text_vbase, sz_text, fo_text;
        uint32_t data_vbase, sz_data, fo_data;

        uint32_t app_entry = (uint32_t)elf_getEntryPoint(&elf_app);
        size_t numPH = elf_getNumProgramHeaders(&elf_app);
        size_t fileOffset;
        uint32_t vaddr;
        uint32_t paddr;
        uint32_t sz;

        printf("app_entry:%08x\n", app_entry);
        syssym_hash = calc_sys_sym_hash();
        printf("sys hash:%08x\n", syssym_hash);

        // dump_str_to_ldscript();

        for (int i = 0; i < numPH; i++)
        {
            printf("PH:%d:\n", i);
            if (elf_getProgramHeaderFlags(&elf_app, i) == (PF_R | PF_X))
            {
                fileOffset = elf_getProgramHeaderOffset(&elf_app, i);
                vaddr = elf_getProgramHeaderVaddr(&elf_app, i);
                paddr = elf_getProgramHeaderPaddr(&elf_app, i);
                sz = elf_getProgramHeaderFileSize(&elf_app, i);
                printf("(text, rodata) Executable, fileOffset:%08x, vaddr:%08x, paddr:%08x, sz:%d\n", fileOffset, vaddr, paddr, sz);
                sz_text = sz;
                text_vbase = vaddr;
                fo_text = fileOffset;

                memcpy(buf_text_rodata, &buf_appelf[fo_text], sz_text);
                continue;
            }

            if (elf_getProgramHeaderFlags(&elf_app, i) == (PF_R | PF_W))
            {
                fileOffset = elf_getProgramHeaderOffset(&elf_app, i);
                vaddr = elf_getProgramHeaderVaddr(&elf_app, i);
                paddr = elf_getProgramHeaderPaddr(&elf_app, i);
                sz = elf_getProgramHeaderFileSize(&elf_app, i);
                printf("(data) RW, fileOffset:%08x, vaddr:%08x, paddr:%08x, sz:%d\n", fileOffset, vaddr, paddr, sz);
                sz_data = sz;
                data_vbase = vaddr;
                fo_data = fileOffset;

                memcpy(buf_data, &buf_appelf[fo_data], sz_data);
            }
        }

        printf("Searching Section.\n");

        static Elf32_Sym *app_sym_table;
        static uint32_t app_sym_total;
        static const char *app_sym_str;

        const char *sname;
        size_t numSection = elf_getNumSections(&elf_app);
        printf("numSection:%d\n", numSection);

        for (int i = 0; i < numSection; i++)
        {
            sname = elf_getSectionName(&elf_app, i);
            if (strlen(sname) >= sizeof(".symtab") - 1)
                if (strcmp(sname, ".symtab") == 0)
                {
                    app_sym_table = (Elf32_Sym *)elf_getSectionOffset(&elf_app, i);
                    app_sym_total = elf_getSectionSize(&elf_app, i) / sizeof(Elf32_Sym);
                    printf("app_symtab:%p, item:%d\n", app_sym_table, app_sym_total);
                    app_sym_table = (Elf32_Sym *)((uint32_t)app_sym_table + (uint32_t)buf_appelf);
                }
            if (strlen(sname) >= sizeof(".strtab") - 1)
                if (strcmp(sname, ".strtab") == 0)
                {
                    app_sym_str = (char *)elf_getSectionOffset(&elf_app, i);
                    printf("app_symstr:%p\n", app_sym_str);
                    app_sym_str += (uint32_t)buf_appelf;
                }
        }

        Elf32_Rel *rel_base;
        uint32_t rel_num = 0;
        uint32_t ptr_rinfo = 0;
        char strbuf[2048];
        for (int i = 0; i < numSection; i++)
        {
            sname = elf_getSectionName(&elf_app, i);
            if (strlen(sname) >= 4)
                if (memcmp(sname, ".rel", sizeof(".rel") - 1) == 0)
                {
                    if (strlen(sname) >= sizeof(".rel.debug") - 1)
                    {
                        if (memcmp(sname, ".rel.debug", sizeof(".rel.debug") - 1) == 0)
                        {
                            continue;
                        }
                    }
                    rel_base = (Elf32_Rel *)elf_getSectionOffset(&elf_app, i);
                    rel_num = elf_getSectionSize(&elf_app, i) / sizeof(Elf32_Rel);
                    printf("rel_tab:%s, addr:%p, num:%d\n", sname, rel_base, rel_num);
                    rel_base = (Elf32_Rel *)((uint32_t)rel_base + (uint32_t)buf_appelf);

                    Elf32_Sym *sym;
                    uint32_t *fill_addr;
                    uint32_t fill_addr_fo;
                    char fill_addr_sec;

                    for (int j = 0; j < rel_num; j++)
                    {
                        sym = app_sym_table;
                        sym += rel_base[j].r_info >> 8;
                        switch (rel_base[j].r_info & 0xFF)
                        {
                        case R_ARM_ABS32:
                        {
                            if (sym->st_value == 0)
                            {
                                INFO("ABS32, at:%08x, cur:%08x, ", rel_base[j].r_offset, sym->st_value);
                                if ((rel_base[j].r_offset >= data_vbase) && (rel_base[j].r_offset < data_vbase + sz_data))
                                {
                                    fill_addr_sec = 'd';
                                    fill_addr_fo = rel_base[j].r_offset - data_vbase;
                                    fill_addr = ((uint32_t *)(&buf_data[rel_base[j].r_offset - data_vbase]));
                                    INFO("content(in DATA): %08x ", *fill_addr);
                                }
                                else if ((rel_base[j].r_offset >= text_vbase) && (rel_base[j].r_offset < text_vbase + sz_text))
                                {
                                    fill_addr_sec = 't';
                                    fill_addr_fo = rel_base[j].r_offset - text_vbase;
                                    fill_addr = ((uint32_t *)(&buf_text_rodata[rel_base[j].r_offset - text_vbase]));
                                    INFO("content(in TEXT): %08x ", *fill_addr);
                                }
                                else
                                {
                                    fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &app_sym_str[sym->st_name]);
                                    ret = -1;
                                    goto exit2;
                                }
                                uint32_t reladr = search_sys_sym((char *)&app_sym_str[sym->st_name]);

                                INFO("Relocate to:%08x ", reladr);
                                INFO("sym :%s\n", &app_sym_str[sym->st_name]);

                                sprintf(strbuf, "%08x %c %s\n", fill_addr_fo, fill_addr_sec, &app_sym_str[sym->st_name]);
                                strcpy(&buf_rel_info[ptr_rinfo], strbuf);
                                ptr_rinfo += strlen(strbuf);
                                sz_rel_info = ptr_rinfo;

                                if (!reladr)
                                {
                                    fprintf(stderr, "ERROR 3: Unresolved Symbol:%s\n", &app_sym_str[sym->st_name]);
                                    ret = -1;
                                    goto exit2;
                                }

                                *fill_addr = reladr;
                            }
                            // printf("ABS32: %s, %d,at:%08x val:%08x\n",  &app_sym_str[sym->st_name], sym->st_info, rel_base[j].r_offset ,sym->st_value  );
                        }
                        break;
                        case R_ARM_CALL:
                        {
                            if (sym->st_value == 0)
                            {
                                INFO("CALL , at:%08x, link_to_addr:%08x, ", rel_base[j].r_offset, sym->st_value);
                                if ((rel_base[j].r_offset >= data_vbase) && (rel_base[j].r_offset < data_vbase + sz_data))
                                {
                                    fill_addr = ((uint32_t *)(&buf_data[rel_base[j].r_offset - data_vbase]));
                                    INFO("content(in DATA): %08x ", *fill_addr);
                                }
                                else if ((rel_base[j].r_offset >= text_vbase) && (rel_base[j].r_offset < text_vbase + sz_text))
                                {
                                    fill_addr = ((uint32_t *)(&buf_text_rodata[rel_base[j].r_offset - text_vbase]));
                                    INFO("content(in TEXT): %08x ", *fill_addr);
                                }
                                else
                                {
                                    fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &app_sym_str[sym->st_name]);
                                    ret = -1;
                                    goto exit2;
                                }

                                INFO("sym :%s\n", &app_sym_str[sym->st_name]);
                                printf("Unsupported Type: R_ARM_CALL\n");
                                exit(-1);
                            }
                            // printf("CALL: %s, %d,at:%08x val:%08x\n", &app_sym_str[sym->st_name], sym->st_info, rel_base[j].r_offset, sym->st_value);
                        }
                        break;
                        case R_ARM_JUMP24:
                        {
                            if (sym->st_value == 0)
                            {
                                INFO("JMP24, at:%08x, link_to_addr:%08x, ", rel_base[j].r_offset, sym->st_value);
                                if ((rel_base[j].r_offset >= data_vbase) && (rel_base[j].r_offset < data_vbase + sz_data))
                                {
                                    fill_addr = ((uint32_t *)(&buf_data[rel_base[j].r_offset - data_vbase]));
                                    INFO("content(in DATA): %08x ", *fill_addr);
                                }
                                else if ((rel_base[j].r_offset >= text_vbase) && (rel_base[j].r_offset < text_vbase + sz_text))
                                {
                                    fill_addr = ((uint32_t *)(&buf_text_rodata[rel_base[j].r_offset - text_vbase]));
                                    INFO("content(in TEXT): %08x ", *fill_addr);
                                }
                                else
                                {
                                    fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &app_sym_str[sym->st_name]);
                                    ret = -1;
                                    goto exit2;
                                }

                                INFO("sym :%s\n", &app_sym_str[sym->st_name]);
                                printf("Unsupported Type: R_ARM_JUMP24\n");
                                exit(-1);
                            }
                        }
                        break;
                        case R_ARM_THM_PC22:
                        {
                            if (sym->st_value == 0)
                            {
                                INFO("JMP24, at:%08x, link_to_addr:%08x, ", rel_base[j].r_offset, sym->st_value);
                                if ((rel_base[j].r_offset >= data_vbase) && (rel_base[j].r_offset < data_vbase + sz_data))
                                {
                                    fill_addr = ((uint32_t *)(&buf_data[rel_base[j].r_offset - data_vbase]));
                                    INFO("content(in DATA): %08x ", *fill_addr);
                                }
                                else if ((rel_base[j].r_offset >= text_vbase) && (rel_base[j].r_offset < text_vbase + sz_text))
                                {
                                    fill_addr = ((uint32_t *)(&buf_text_rodata[rel_base[j].r_offset - text_vbase]));
                                    INFO("content(in TEXT): %08x ", *fill_addr);
                                }
                                else
                                {
                                    fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &app_sym_str[sym->st_name]);
                                    ret = -1;
                                    goto exit2;
                                }

                                INFO("sym :%s\n", &app_sym_str[sym->st_name]);
                                printf("Unsupported Type: R_ARM_THM_PC22\n");
                                exit(-1);
                            }
                        }
                        case R_ARM_V4BX:
                        {
                            if (sym->st_value == 0)
                            {
                                INFO("V4BX , at:%08x, link_to_addr:%08x, ", rel_base[j].r_offset, sym->st_value);
                                if ((rel_base[j].r_offset >= data_vbase) && (rel_base[j].r_offset < data_vbase + sz_data))
                                {
                                    fill_addr = ((uint32_t *)(&buf_data[rel_base[j].r_offset - data_vbase]));
                                    INFO("content(in DATA): %08x ", *fill_addr);
                                }
                                else if ((rel_base[j].r_offset >= text_vbase) && (rel_base[j].r_offset < text_vbase + sz_text))
                                {
                                    fill_addr = ((uint32_t *)(&buf_text_rodata[rel_base[j].r_offset - text_vbase]));
                                    INFO("content(in TEXT): %08x ", *fill_addr);
                                }
                                else
                                {
                                    fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &app_sym_str[sym->st_name]);
                                    ret = -1;
                                    goto exit2;
                                }
                                *fill_addr &= 0xf000000f;
                                *fill_addr |= 0x01a0f000;
                                INFO(" -> mov pc,r%d\n", *fill_addr & 0xF);
                                printf("Unsupported Type: R_ARM_V4BX\n");
                                exit(-1);
                            }
                        }
                        break;
                        case R_ARM_PREL31:
                        {
                            if (sym->st_value == 0)
                            {
                                INFO("PREL31, at:%08x, link_to_addr:%08x, ", rel_base[j].r_offset, sym->st_value);
                                if ((rel_base[j].r_offset >= data_vbase) && (rel_base[j].r_offset < data_vbase + sz_data))
                                {
                                    fill_addr = ((uint32_t *)(&buf_data[rel_base[j].r_offset - data_vbase]));
                                    INFO("content(in DATA): %08x ", *fill_addr);
                                }
                                else if ((rel_base[j].r_offset >= text_vbase) && (rel_base[j].r_offset < text_vbase + sz_text))
                                {
                                    fill_addr = ((uint32_t *)(&buf_text_rodata[rel_base[j].r_offset - text_vbase]));
                                    INFO("content(in TEXT): %08x ", *fill_addr);
                                }
                                else
                                {
                                    fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &app_sym_str[sym->st_name]);
                                    ret = -1;
                                    goto exit2;
                                }

                                int32_t offset;
                                offset = *fill_addr + sym->st_value - rel_base[j].r_offset;
                                *fill_addr = offset & 0x7fffffff;

                                INFO(" -> %08x\n", *fill_addr);
                                printf("Unsupported Type: R_ARM_PREL31\n");
                                exit(-1);
                            }
                        }
                        break;
                        case R_ARM_NONE:
                            break;
                        default:
                        {
                            printf("Unknown Type:%08x\n", rel_base[j].r_info);
                            exit(-1);
                        }
                        break;
                        }
                    }
                }
        }

        sz_rel = 0;
        Relocate_vbase = 0;

        sz_exp = (((sizeof(exp_header_t) + (PAGE_SIZE - 1)) & (~(PAGE_SIZE - 1))) +
                  ((sz_text + (PAGE_SIZE - 1)) & (~(PAGE_SIZE - 1))) +
                  ((sz_data + (PAGE_SIZE - 1)) & (~(PAGE_SIZE - 1))) +
                  ((sz_rel + (PAGE_SIZE - 1)) & (~(PAGE_SIZE - 1))) +
                  ((sz_rel_info + (PAGE_SIZE - 1)) & (~(PAGE_SIZE - 1))));

        printf("outputSize:%d\n", sz_exp);

        buf_exp = malloc(sz_exp);
        if (!buf_exp)
        {
            fprintf(stderr, "Failed to alloc memory 2\n");
            ret = -1;
            goto exit2;
        }

        exp_header_t *expHeader = (exp_header_t *)buf_exp;

        expHeader->Mark0 = 0x5AA52333;
        expHeader->Mark1 = 1936291909;
        expHeader->Mark2 = 1347436916;

        expHeader->exp_ver = 1;
        expHeader->sys_hash = syssym_hash;
        expHeader->entry = app_entry;

        expHeader->reloc_load_addr = Relocate_vbase;
        expHeader->data_load_addr = data_vbase;
        expHeader->text_load_addr = text_vbase;

        expHeader->reloc_fo = (sizeof(exp_header_t) + (PAGE_SIZE - 1)) & (~(PAGE_SIZE - 1));
        expHeader->data_fo = expHeader->reloc_fo + ((sz_rel + (PAGE_SIZE - 1)) & (~(PAGE_SIZE - 1)));
        expHeader->text_fo = expHeader->data_fo + ((sz_data + (PAGE_SIZE - 1)) & (~(PAGE_SIZE - 1)));

        expHeader->reloc_sz = sz_rel;
        expHeader->data_sz = sz_data;
        expHeader->text_sz = sz_text;

        expHeader->dynsym_of = expHeader->text_fo + ((sz_text + (PAGE_SIZE - 1)) & (~(PAGE_SIZE - 1)));

        // expHeader->dynsym_of = expHeader->text_fo + off_dynsym_exp;
        // expHeader->dynstr_of = expHeader->text_fo + off_dynstr_exp;

        // expHeader->rel_dyn_of = expHeader->reloc_fo + off_rel_dyn_exp;
        // expHeader->rel_plt_of = expHeader->reloc_fo + off_rel_plt_exp;

        expHeader->num_rel_dyn = sz_rel_info;

        expHeader->num_rel_plt = 0;

        expHeader->got_of = 0;

        memcpy(&buf_exp[expHeader->data_fo], buf_data, sz_data);
        memcpy(&buf_exp[expHeader->text_fo], buf_text_rodata, sz_text);
        memcpy(&buf_exp[expHeader->dynsym_of], buf_rel_info, sz_rel_info);

        // strcpy(&expHeader->sys_build_date[0], sysbuild_date);

        fwrite(buf_exp, 1, sz_exp, f_exp);

        free(buf_exp);
    }
    else
    {
        f_symtab = fopen(path_symtab, "rb");
        if (!f_symtab)
        {
            fprintf(stderr, "Failed to open symtab\n");
            exit(-1);
        }
        f_exp = fopen(path_exp, "rb+");
        if (!f_exp)
        {
            fprintf(stderr, "Failed to open exp\n");
            fclose(f_symtab);
            exit(-1);
        }

        fseek(f_symtab, 0, SEEK_END);
        sz_symtab = ftell(f_symtab);
        fseek(f_symtab, 0, SEEK_SET);

        buf_symtab = malloc(sz_symtab);
        if (!buf_symtab)
        {
            fprintf(stderr, "Failed to alloc memory 1\n");
            ret = -1;
            goto exit1;
        }
        fread(buf_symtab, 1, sz_symtab, f_symtab);

        syssym_hash = calc_sys_sym_hash();
        printf("sys hash:%08x\n", syssym_hash);

        exp_header_t expHeader;

        fread(&expHeader, 1, sizeof(exp_header_t), f_exp);

        expHeader.sys_hash = syssym_hash;
        uint32_t rec_fill_adr, symadr;
        char fill_sec;
        char symn[1024];
        long savep;
        int fr;
        fseek(f_exp, expHeader.dynsym_of, SEEK_SET);
        fr = fscanf(f_exp, "%08x %c %s\n", &rec_fill_adr, &fill_sec, symn);
        while (fr == 3)
        {
            
            savep = ftell(f_exp);
            //printf("%08x, %c, %s, %08x\n",rec_fill_adr, fill_sec, symn, savep );
            symadr = search_sys_sym(symn);
            if (!symadr)
            {
                fprintf(stderr, "ERROR 3: Unresolved Symbol:%s\n", symn);
                ret = -1;
                goto exit02;
            }
            
            switch (fill_sec)
            {
            case 'd': // data
                printf("Relocate, at:%08x, to:%08x, sym:%s\n", rec_fill_adr + expHeader.data_fo, symadr,   symn   );
                fseek(f_exp, rec_fill_adr + expHeader.data_fo, SEEK_SET);
                fwrite(&symadr, 1, 4, f_exp);
                break;
            case 't': // text
                printf("Relocate, at:%08x, to:%08x, sym:%s\n", rec_fill_adr + expHeader.text_fo, symadr,   symn   );
                fseek(f_exp, rec_fill_adr + expHeader.text_fo, SEEK_SET);
                fwrite(&symadr, 1, 4, f_exp);
                break;
            default:
                break;
            }

            //printf("savep:%ld\n",savep);
            fseek(f_exp, savep, SEEK_SET);
            fr = fscanf(f_exp, "%08x %c %s\n", &rec_fill_adr, &fill_sec, symn);
            
        }
        printf("Relocate done.\n");

        fseek(f_exp, 0, SEEK_SET);
        fwrite(&expHeader, 1, sizeof(exp_header_t), f_exp);
        fclose(f_exp);

    }
exit2:
    free(buf_appelf);

exit1:
    fclose(f_symtab);
    fclose(f_appelf);
    fclose(f_exp);

exit0:
    return ret;

exit02:
    free(buf_exp);

exit01:
    fclose(f_symtab);
    fclose(f_exp);

exit00:
    return ret;
}
void Usage()
{
    // eld --appelf xxx.elf --symtab xxx.txt --exp xxx.exp
    // eld --symtab xxx.txt --exp xxx.exp
    printf("Usage:\n");
    printf("\teld --appelf xxx.elf --symtab xxx.txt --exp xxx.exp\n");
    printf("\teld --symtab xxx.txt --exp xxx.exp\n");
    exit(-1);
}
