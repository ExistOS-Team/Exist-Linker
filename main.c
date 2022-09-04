#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "libelf/elf_user.h"
#include "libelf/elf32.h"

#include "exp.h"

#define VERBOSE 0

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
char path_syself[512];
char path_exp[512];

char *sysbuild_date;

char ld_mode = LD_MODE_ELF_TO_EXP;

FILE *f_appelf;
FILE *f_syself;
FILE *f_exp;

size_t sz_syself;
size_t sz_appelf;
size_t sz_exp;

uint8_t *buf_syself;
uint8_t *buf_appelf;
uint8_t *buf_exp;

uint8_t *buf_rec_table;
uint8_t *buf_text_rodata;
uint8_t *buf_data;

uint32_t off_dynsym_exp;
uint32_t off_dynstr_exp;
uint32_t off_rel_plt_exp;
uint32_t num_rel_plt_exp;
uint32_t off_rel_dyn_exp;
uint32_t num_rel_dyn_exp;
uint32_t off_got_exp;

static Elf32_Sym *sys_symtab;
static const char *sys_symstr;
static size_t syssym_num;

elf_t elf_sys;
elf_t elf_app;
exp_header_t *exp_h;

uint32_t syssym_hash;
void Usage();

uint32_t search_sys_sym(char *name)
{
    for (int i = 0; i < syssym_num; i++)
    {
        if (strcmp(name, &sys_symstr[sys_symtab[i].st_name]) == 0)
        {
            return sys_symtab[i].st_value;
        }
        // printf("%08x, syssym:%s\n", sys_symtab[i].st_value, &sys_symstr[sys_symtab[i].st_name]);
    }
    return 0xFFFFFFFF;
}

uint32_t calc_sys_sym_hash()
{
    uint32_t hash = 0x5a5a1234;
    for (int i = 0; i < syssym_num; i++)
    {
        hash ^= sys_symtab[i].st_value;
        hash ^= hash << 16;
    }
    return hash;
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
            if (strcmp(argv[i], "--syself") == 0)
            {
                strcpy(path_syself, argv[i + 1]);
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
            if (strcmp(argv[i], "--syself") == 0)
            {
                strcpy(path_syself, argv[i + 1]);
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
        f_syself = fopen(path_syself, "rb");
        if (!f_syself)
        {
            fprintf(stderr, "Failed to open syself\n");
            exit(-1);
        }
        f_appelf = fopen(path_appelf, "rb");
        if (!f_appelf)
        {
            fprintf(stderr, "Failed to open appelf\n");
            fclose(f_syself);
            exit(-1);
        }
        f_exp = fopen(path_exp, "wb");
        if (!f_exp)
        {
            fprintf(stderr, "Failed to open exp\n");
            fclose(f_syself);
            fclose(f_appelf);
            exit(-1);
        }

        fseek(f_syself, 0, SEEK_END);
        sz_syself = ftell(f_syself);
        fseek(f_syself, 0, SEEK_SET);

        fseek(f_appelf, 0, SEEK_END);
        sz_appelf = ftell(f_appelf);
        fseek(f_appelf, 0, SEEK_SET);

        buf_syself = malloc(sz_syself);
        if (!buf_syself)
        {
            fprintf(stderr, "Failed to alloc memory 1\n");
            ret = -1;
            goto exit1;
        }

        buf_appelf = malloc(sz_appelf);
        if (!buf_appelf)
        {
            fprintf(stderr, "Failed to alloc memory 2\n");
            ret = -1;
            goto exit1;
        }

        fread(buf_appelf, 1, sz_appelf, f_appelf);
        fread(buf_syself, 1, sz_syself, f_syself);

        elf_sys.elfFile = buf_syself;
        elf_sys.elfClass = ELFCLASS32;
        elf_sys.elfSize = sz_syself;

        elf_app.elfFile = buf_appelf;
        elf_app.elfClass = ELFCLASS32;
        elf_app.elfSize = sz_appelf;

        if (elf_checkFile(&elf_sys))
        {
            fprintf(stderr, "Error SysELF Format!\n");
            goto exit2;
        }

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
        size_t fileOffset, fileOffset2;
        uint32_t vaddr, vaddr2;
        uint32_t paddr, paddr2;
        uint32_t sz, sz2;

        for (int i = 0; i < numPH; i++)
        {
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
                ++i;

                buf_text_rodata = malloc(sz);
                if (!buf_text_rodata)
                {
                    fprintf(stderr, "Failed to alloc memory 3\n");
                    ret = -1;
                    goto exit2;
                }
                memcpy(buf_text_rodata, &buf_appelf[fo_text], sz_text);

                fileOffset2 = elf_getProgramHeaderOffset(&elf_app, i);
                vaddr2 = elf_getProgramHeaderVaddr(&elf_app, i);
                paddr2 = elf_getProgramHeaderPaddr(&elf_app, i);
                sz2 = elf_getProgramHeaderFileSize(&elf_app, i);
                printf("(data) RW, fileOffset:%08x, vaddr:%08x, paddr:%08x, sz:%d\n", fileOffset2, vaddr2, paddr2, sz2);
                sz_data = sz2;
                data_vbase = vaddr2;
                fo_data = fileOffset;

                buf_data = malloc(sz);
                if (!buf_data)
                {
                    fprintf(stderr, "Failed to alloc memory 4\n");
                    ret = -1;
                    goto exit2;
                }
                memcpy(buf_data, &buf_appelf[fileOffset2], sz2);
            }

            if (elf_getProgramHeaderFlags(&elf_app, i) == (PF_R | PF_X | PF_W))
            {
                fileOffset = elf_getProgramHeaderOffset(&elf_app, i);
                vaddr = elf_getProgramHeaderVaddr(&elf_app, i);
                paddr = elf_getProgramHeaderPaddr(&elf_app, i);
                sz = elf_getProgramHeaderFileSize(&elf_app, i);
                Relocate_vbase = vaddr;
                sz_rel = sz;
                fo_rel = fileOffset;
                printf("(Dyn ) Relocate, fileOffset:%08x, vaddr:%08x, paddr:%08x, sz:%d\n", fileOffset, vaddr, paddr, sz);

                buf_rec_table = malloc(sz);
                if (!buf_rec_table)
                {
                    fprintf(stderr, "Failed to alloc memory 4\n");
                    ret = -1;
                    goto exit2;
                }
                memcpy(buf_rec_table, &buf_appelf[fileOffset], sz);
            }
        }

        static uint32_t *got_table;
        static Elf32_Sym *dynamic_table;
        static uint32_t *rel_plt;
        static uint32_t rel_plt_num;
        static uint32_t *rel_dyn;
        static uint32_t rel_dyn_num;
        static const char *dynstr;

        const char *sname;

        size_t SysNumSection = elf_getNumSections(&elf_sys);
        for (int i = 0; i < SysNumSection; i++)
        {
            sname = elf_getSectionName(&elf_sys, i);
            if (strcmp(sname, ".symtab") == 0)
            {
                sys_symtab = (Elf32_Sym *)elf_getSectionOffset(&elf_sys, i);
                syssym_num = elf_getSectionSize(&elf_sys, i) / sizeof(Elf32_Sym);
                printf("sys_symtab:%08x, item:%d\n", sys_symtab, syssym_num);
                sys_symtab = (Elf32_Sym *)((uint32_t)sys_symtab + (uint32_t)buf_syself);
            }
            if (strcmp(sname, ".strtab") == 0)
            {
                sys_symstr = (char *)elf_getSectionOffset(&elf_sys, i);
                printf("sys_symstr:%08x\n", sys_symstr);
                sys_symstr += (uint32_t)buf_syself;
            }
            if (strcmp(sname, ".sysinfo") == 0)
            {
                sysbuild_date = (char *)elf_getSectionOffset(&elf_sys, i);
                printf("sysinfo:%08x\n", sysbuild_date);
                sysbuild_date += (uint32_t)buf_syself;
                printf("sysbuid date:%s\n", sysbuild_date);
            }
        }
        syssym_hash = calc_sys_sym_hash();
        printf("sys hash:%08x\n", syssym_hash);

        size_t numSection = elf_getNumSections(&elf_app);

        for (int i = 0; i < numSection; i++)
        {
            sname = elf_getSectionName(&elf_app, i);
            if (strcmp(sname, ".got") == 0)
            {
                got_table = (uint32_t *)elf_getSectionOffset(&elf_app, i);
                off_got_exp = (uint32_t)got_table - fo_rel;
                printf("got_table:%08x\n", got_table);
            }
            if (strcmp(sname, ".dynsym") == 0)
            {
                dynamic_table = (Elf32_Sym *)elf_getSectionOffset(&elf_app, i);
                off_dynsym_exp = (uint32_t)dynamic_table - fo_text;
                printf("dynamic_table:%08x, item:%d\n", dynamic_table, elf_getSectionSize(&elf_app, i) / sizeof(Elf32_Sym));
            }

            if (strcmp(sname, ".rel.plt") == 0)
            {
                rel_plt = (uint32_t *)elf_getSectionOffset(&elf_app, i);
                rel_plt_num = elf_getSectionSize(&elf_app, i) / sizeof(Elf32_Rel);
                off_rel_plt_exp = (uint32_t)rel_plt - fo_rel;
                num_rel_plt_exp = rel_plt_num;
                printf("rel_plt:%08x, item:%d\n", rel_plt, rel_plt_num);
            }

            if (strcmp(sname, ".rel.dyn") == 0)
            {
                rel_dyn = (uint32_t *)elf_getSectionOffset(&elf_app, i);
                rel_dyn_num = elf_getSectionSize(&elf_app, i) / sizeof(Elf32_Rel);
                off_rel_dyn_exp = (uint32_t)rel_dyn - fo_rel;
                num_rel_dyn_exp = rel_dyn_num;
                printf("rel_dyn:%08x, item:%d\n", rel_dyn, rel_dyn_num);
            }

            if (strcmp(sname, ".dynstr") == 0)
            {
                dynstr = (const char *)elf_getSectionOffset(&elf_app, i);
                off_dynstr_exp = (uint32_t)dynstr - fo_text;
                printf("dynstr:%08x\n", dynstr);
                dynstr += (uint32_t)buf_appelf;
            }
        }
        printf("resolve rel.dyn: \n\n");
        // resolve rel.dyn
        uint32_t *fill_addr;
        Elf32_Sym *sym;
        Elf32_Rel *rel_d = (Elf32_Rel *)(buf_appelf + (uint32_t)rel_dyn);
        for (int i = 0; i < rel_dyn_num; i++)
        {
            sym = (Elf32_Sym *)((uint32_t)buf_appelf + (uint32_t)dynamic_table);
            sym += (uint32_t)(rel_d[i].r_info >> 8);

            if ((rel_d[i].r_info & 0xFF) == R_ARM_RELATIVE)
            {
            }
            else if ((rel_d[i].r_info & 0xFF) == R_ARM_GLOB_DAT)
            {
                // printf("GLOB_DAT, at:%08x, link_to_addr:%08x, sym:%s \n",rel_d[i].r_offset, sym->st_value, &dynstr[sym->st_name]  );

                INFO("GLOB_DAT, at:%08x, link_to_addr:%08x, ", rel_d[i].r_offset, sym->st_value);
                if ((rel_d[i].r_offset >= data_vbase) && (rel_d[i].r_offset < data_vbase + sz_data))
                {
                    fill_addr = ((uint32_t *)(&buf_data[rel_d[i].r_offset - data_vbase]));
                    INFO("content(in DATA): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= Relocate_vbase) && (rel_d[i].r_offset < Relocate_vbase + sz_rel))
                {
                    fill_addr = ((uint32_t *)(&buf_rec_table[rel_d[i].r_offset - Relocate_vbase]));
                    INFO("content(in REL ): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= text_vbase) && (rel_d[i].r_offset < text_vbase + sz_text))
                {
                    fill_addr = ((uint32_t *)(&buf_text_rodata[rel_d[i].r_offset - text_vbase]));
                    INFO("content(in TEXT): %08x ", *fill_addr);
                }
                else
                {
                    fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &dynstr[sym->st_name]);
                    ret = -1;
                    goto exit2;
                }

                INFO("sym :%s\n", &dynstr[sym->st_name]);
                if (*fill_addr == 0)
                {
                    if (sym->st_value == 0)
                    {
                        uint32_t sym_in_sys = search_sys_sym((char *)&dynstr[sym->st_name]);
                        if (sym_in_sys == 0xFFFFFFFF)
                        {
                            fprintf(stderr, "ERROR: Unresolved Symbol:%s\n", &dynstr[sym->st_name]);
                            ret = -1;
                            goto exit2;
                        }
                        *fill_addr = sym_in_sys;

                        printf("GLOB_DAT, at:%08x, link_addr-app:%08x -> sys:%08x, sym: %s \n", rel_d[i].r_offset, sym->st_value, *fill_addr, &dynstr[sym->st_name]);
                    }
                    else
                    {
                        *fill_addr = sym->st_value;

                        // printf("GLOB_DAT, at:%08x, link_addr-app:%08x -> app:%08x, sym: %s \n", rel_d[i].r_offset, sym->st_value, *fill_addr, &dynstr[sym->st_name]);
                    }
                }
            }
            else if ((rel_d[i].r_info & 0xFF) == R_ARM_ABS32)
            {
                INFO("ABS32   , at:%08x, link_to_addr:%08x, ", rel_d[i].r_offset, sym->st_value);
                if ((rel_d[i].r_offset >= data_vbase) && (rel_d[i].r_offset < data_vbase + sz_data))
                {
                    fill_addr = ((uint32_t *)(&buf_data[rel_d[i].r_offset - data_vbase]));
                    INFO("content(in DATA): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= Relocate_vbase) && (rel_d[i].r_offset < Relocate_vbase + sz_rel))
                {
                    fill_addr = ((uint32_t *)(&buf_rec_table[rel_d[i].r_offset - Relocate_vbase]));
                    INFO("content(in REL ): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= text_vbase) && (rel_d[i].r_offset < text_vbase + sz_text))
                {
                    fill_addr = ((uint32_t *)(&buf_text_rodata[rel_d[i].r_offset - text_vbase]));
                    INFO("content(in TEXT): %08x ", *fill_addr);
                }
                else
                {
                    fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &dynstr[sym->st_name]);
                    ret = -1;
                    goto exit2;
                }
                INFO("sym :%s\n", &dynstr[sym->st_name]);

                if (*fill_addr == 0)
                {
                    if (sym->st_value == 0)
                    {
                        uint32_t sym_in_sys = search_sys_sym((char *)&dynstr[sym->st_name]);
                        if (sym_in_sys == 0xFFFFFFFF)
                        {
                            fprintf(stderr, "ERROR: Unresolved Symbol:%s\n", &dynstr[sym->st_name]);
                            ret = -1;
                            goto exit2;
                        }

                        *fill_addr = sym_in_sys;

                        printf("ABS32   , at:%08x, link_addr-app:%08x -> sys:%08x, sym: %s \n", rel_d[i].r_offset, sym->st_value, *fill_addr, &dynstr[sym->st_name]);
                    }
                    else
                    {
                        *fill_addr = sym->st_value;

                        // printf("ABS32   , at:%08x, link_addr-app:%08x -> app:%08x, sym: %s \n", rel_d[i].r_offset, sym->st_value, *fill_addr, &dynstr[sym->st_name]);
                    }
                }
            }
            else if ((rel_d[i].r_info & 0xFF) == R_ARM_JUMP_SLOT)
            {
                INFO("R_ARM_JUMP_SLOT, at:%08x, link_to_addr:%08x, ", rel_d[i].r_offset, sym->st_value);
                if ((rel_d[i].r_offset >= data_vbase) && (rel_d[i].r_offset < data_vbase + sz_data))
                {
                    fill_addr = ((uint32_t *)(&buf_data[rel_d[i].r_offset - data_vbase]));
                    INFO("content(in DATA): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= Relocate_vbase) && (rel_d[i].r_offset < Relocate_vbase + sz_rel))
                {
                    fill_addr = ((uint32_t *)(&buf_rec_table[rel_d[i].r_offset - Relocate_vbase]));
                    INFO("content(in REL ): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= text_vbase) && (rel_d[i].r_offset < text_vbase + sz_text))
                {
                    fill_addr = ((uint32_t *)(&buf_text_rodata[rel_d[i].r_offset - text_vbase]));
                    INFO("content(in TEXT): %08x ", *fill_addr);
                }
                else
                {
                    fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &dynstr[sym->st_name]);
                    ret = -1;
                    goto exit2;
                }
                INFO("sym :%s\n", &dynstr[sym->st_name]);

                // if (*fill_addr == 0)
                {
                    if (sym->st_value == 0)
                    {
                        uint32_t sym_in_sys = search_sys_sym((char *)&dynstr[sym->st_name]);
                        if (sym_in_sys == 0xFFFFFFFF)
                        {
                            fprintf(stderr, "ERROR: Unresolved Symbol:%s\n", &dynstr[sym->st_name]);
                            ret = -1;
                            goto exit2;
                        }

                        *fill_addr = sym_in_sys;

                        printf("R_ARM_JUMP_SLOT, at:%08x, link_addr-app:%08x -> sys:%08x, sym: %s \n", rel_d[i].r_offset, sym->st_value, *fill_addr, &dynstr[sym->st_name]);
                    }
                    else
                    {
                        *fill_addr = sym->st_value;

                        // printf("R_ARM_JUMP_SLOT, at:%08x, link_addr-app:%08x -> app:%08x, sym: %s \n", rel_d[i].r_offset, sym->st_value, *fill_addr, &dynstr[sym->st_name]);
                    }
                }
            }
            else
            {
                fprintf(stderr, "at rel.dyn: Unimplemented Relocation:%d\n", rel_d[i].r_info & 0xFF);
                ret = -1;
                goto exit2;
            }
        }

        // resolve rel.plt

        printf("resolve rel.plt: \n\n");

        rel_d = (Elf32_Rel *)(buf_appelf + (uint32_t)rel_plt);
        for (int i = 0; i < rel_plt_num; i++)
        {
            sym = (Elf32_Sym *)((uint32_t)buf_appelf + (uint32_t)dynamic_table);
            sym += (uint32_t)(rel_d[i].r_info >> 8);

            if ((rel_d[i].r_info & 0xFF) == R_ARM_JUMP_SLOT)
            {
                INFO("R_ARM_JUMP_SLOT, at:%08x, link_to_addr:%08x, ", rel_d[i].r_offset, sym->st_value);
                if ((rel_d[i].r_offset >= data_vbase) && (rel_d[i].r_offset < data_vbase + sz_data))
                {
                    fill_addr = ((uint32_t *)(&buf_data[rel_d[i].r_offset - data_vbase]));
                    INFO("content(in DATA): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= Relocate_vbase) && (rel_d[i].r_offset < Relocate_vbase + sz_rel))
                {
                    fill_addr = ((uint32_t *)(&buf_rec_table[rel_d[i].r_offset - Relocate_vbase]));
                    INFO("content(in REL ): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= text_vbase) && (rel_d[i].r_offset < text_vbase + sz_text))
                {
                    fill_addr = ((uint32_t *)(&buf_text_rodata[rel_d[i].r_offset - text_vbase]));
                    INFO("content(in TEXT): %08x ", *fill_addr);
                }
                else
                {
                    fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &dynstr[sym->st_name]);
                    ret = -1;
                    goto exit2;
                }
                INFO("sym :%s\n", &dynstr[sym->st_name]);

                // if (*fill_addr == 0)
                {
                    if (sym->st_value == 0)
                    {
                        uint32_t sym_in_sys = search_sys_sym((char *)&dynstr[sym->st_name]);
                        if (sym_in_sys == 0xFFFFFFFF)
                        {
                            fprintf(stderr, "ERROR: Unresolved Symbol:%s\n", &dynstr[sym->st_name]);
                            ret = -1;
                            goto exit2;
                        }

                        *fill_addr = sym_in_sys;
                        printf("R_ARM_JUMP_SLOT, at:%08x, link_addr-app:%08x -> sys:%08x, sym: %s \n", rel_d[i].r_offset, sym->st_value, *fill_addr, &dynstr[sym->st_name]);
                    }
                    else
                    {
                        *fill_addr = sym->st_value;
                        // printf("R_ARM_JUMP_SLOT, at:%08x, link_addr-app:%08x -> app:%08x, sym: %s \n", rel_d[i].r_offset, sym->st_value, *fill_addr, &dynstr[sym->st_name]);
                    }
                }
            }
            else
            {
                fprintf(stderr, "at rel.plt: Unimplemented Relocation:%d\n", rel_d[i].r_info & 0xFF);
                ret = -1;
                goto exit2;
            }
        }

        sz_exp = (((sizeof(exp_header_t) + (PAGE_SIZE - 1)) & (~(PAGE_SIZE - 1))) +
                  ((sz_text + (PAGE_SIZE - 1)) & (~(PAGE_SIZE - 1))) +
                  ((sz_data + (PAGE_SIZE - 1)) & (~(PAGE_SIZE - 1))) +
                  ((sz_rel + (PAGE_SIZE - 1)) & (~(PAGE_SIZE - 1))));

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

        expHeader->dynsym_of = expHeader->text_fo + off_dynsym_exp;
        expHeader->dynstr_of = expHeader->text_fo + off_dynstr_exp;

        expHeader->rel_dyn_of = expHeader->reloc_fo + off_rel_dyn_exp;
        expHeader->rel_plt_of = expHeader->reloc_fo + off_rel_plt_exp;

        expHeader->num_rel_dyn = num_rel_dyn_exp;
        expHeader->num_rel_plt = num_rel_plt_exp;

        expHeader->got_of = expHeader->reloc_fo + off_got_exp;

        memcpy(&buf_exp[expHeader->reloc_fo], buf_rec_table, sz_rel);
        memcpy(&buf_exp[expHeader->data_fo], buf_data, sz_data);
        memcpy(&buf_exp[expHeader->text_fo], buf_text_rodata, sz_text);

        strcpy(&expHeader->sys_build_date[0], sysbuild_date);

        fwrite(buf_exp, 1, sz_exp, f_exp);

        free(buf_exp);
    }
    else
    {

        f_syself = fopen(path_syself, "rb");
        if (!f_syself)
        {
            fprintf(stderr, "Failed to open syself\n");
            exit(-1);
        }

        f_exp = fopen(path_exp, "rb+");
        if (!f_exp)
        {
            fprintf(stderr, "Failed to open exp\n");
            fclose(f_syself);
            exit(-1);
        }

        fseek(f_syself, 0, SEEK_END);
        sz_syself = ftell(f_syself);
        fseek(f_syself, 0, SEEK_SET);

        fseek(f_exp, 0, SEEK_END);
        sz_exp = ftell(f_exp);
        fseek(f_exp, 0, SEEK_SET);

        printf("sz_exp:%d\n", sz_exp);

        buf_syself = malloc(sz_syself);
        if (!buf_syself)
        {
            fprintf(stderr, "Failed to alloc memory 1\n");
            ret = -1;
            goto exit01;
        }

        buf_exp = malloc(sz_exp);
        if (!buf_exp)
        {
            fprintf(stderr, "Failed to alloc memory 2\n");
            ret = -1;
            goto exit01;
        }

        fread(buf_exp, 1, sz_exp, f_exp);

        fread(buf_syself, 1, sz_syself, f_syself);

        elf_sys.elfFile = buf_syself;
        elf_sys.elfClass = ELFCLASS32;
        elf_sys.elfSize = sz_syself;

        exp_h = (exp_header_t *)buf_exp;

        if (elf_checkFile(&elf_sys))
        {
            fprintf(stderr, "Error SysELF Format!\n");
            goto exit02;
        }

        if (exp_h->Mark0 != 0x5AA52333 ||
            exp_h->Mark1 != 1936291909 ||
            exp_h->Mark2 != 1347436916)
        {
            fprintf(stderr, "Error EXP Format!\n");
            goto exit02;
        }
        const char *sname;
        size_t SysNumSection = elf_getNumSections(&elf_sys);
        for (int i = 0; i < SysNumSection; i++)
        {
            sname = elf_getSectionName(&elf_sys, i);
            if (strcmp(sname, ".symtab") == 0)
            {
                sys_symtab = (Elf32_Sym *)elf_getSectionOffset(&elf_sys, i);
                syssym_num = elf_getSectionSize(&elf_sys, i) / sizeof(Elf32_Sym);
                printf("sys_symtab:%08x, item:%d\n", sys_symtab, syssym_num);
                sys_symtab = (Elf32_Sym *)((uint32_t)sys_symtab + (uint32_t)buf_syself);
            }
            if (strcmp(sname, ".strtab") == 0)
            {
                sys_symstr = (char *)elf_getSectionOffset(&elf_sys, i);
                printf("sys_symstr:%08x\n", sys_symstr);
                sys_symstr += (uint32_t)buf_syself;
            }
            if (strcmp(sname, ".sysinfo") == 0)
            {
                sysbuild_date = (char *)elf_getSectionOffset(&elf_sys, i);
                printf("sysinfo:%08x\n", sysbuild_date);
                sysbuild_date += (uint32_t)buf_syself;
                printf("sysbuid date:%s\n", sysbuild_date);
            }
        }
        syssym_hash = calc_sys_sym_hash();
        printf("sys hash:%08x == %08x\n", syssym_hash, exp_h->sys_hash);
        if (syssym_hash == exp_h->sys_hash)
        {
            printf("Hash is same, just copy date.\n");
            strcpy(&exp_h->sys_build_date[0], sysbuild_date);
            fseek(f_exp, 0, SEEK_SET);
            fwrite(buf_exp, 1, sz_exp, f_exp);
            goto exit02;
        }
        printf("resolve rel.dyn: \n\n");
        // resolve rel.dyn
        uint32_t *fill_addr;
        Elf32_Sym *sym;
        Elf32_Rel *rel_d = (Elf32_Rel *)(buf_exp + (uint32_t)exp_h->rel_dyn_of);

        for (int i = 0; i < exp_h->num_rel_dyn; i++)
        {
            sym = (Elf32_Sym *)((uint32_t)buf_exp + (uint32_t)exp_h->dynsym_of);
            sym += (uint32_t)(rel_d[i].r_info >> 8);
            // printf("sym:%08x\n", sym->st_value);

            if ((rel_d[i].r_info & 0xFF) == R_ARM_RELATIVE)
            {
                continue;
            }
            else if ((rel_d[i].r_info & 0xFF) == R_ARM_GLOB_DAT)
            {
                // printf("GLOB_DAT, at:%08x, link_to_addr:%08x, sym:%s \n",rel_d[i].r_offset, sym->st_value, &dynstr[sym->st_name]  );

                INFO("GLOB_DAT, at:%08x, link_to_addr:%08x, ", rel_d[i].r_offset, sym->st_value);
                if ((rel_d[i].r_offset >= exp_h->data_load_addr) && (rel_d[i].r_offset < exp_h->data_load_addr + exp_h->data_sz))
                {
                    fill_addr = ((uint32_t *)(&buf_exp[rel_d[i].r_offset - exp_h->data_load_addr + exp_h->data_fo]));
                    INFO("content(in DATA): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= exp_h->reloc_load_addr) && (rel_d[i].r_offset < exp_h->reloc_load_addr + exp_h->reloc_sz))
                {
                    fill_addr = ((uint32_t *)(&buf_exp[rel_d[i].r_offset - exp_h->reloc_load_addr + exp_h->reloc_fo]));
                    INFO("content(in REL ): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= exp_h->text_load_addr) && (rel_d[i].r_offset < exp_h->text_load_addr + exp_h->text_sz))
                {
                    fill_addr = ((uint32_t *)(&buf_exp[rel_d[i].r_offset - exp_h->text_load_addr + exp_h->text_fo]));
                    INFO("content(in TEXT): %08x ", *fill_addr);
                }
                else
                {
                    fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &buf_exp[sym->st_name + exp_h->dynstr_of]);
                    ret = -1;
                    goto exit02;
                }

                INFO("sym :%s\n", &buf_exp[sym->st_name + exp_h->dynstr_of]);
            }
            else if ((rel_d[i].r_info & 0xFF) == R_ARM_ABS32)
            {

                INFO("R_ARM_ABS32, at:%08x, link_to_addr:%08x, ", rel_d[i].r_offset, sym->st_value);
                if ((rel_d[i].r_offset >= exp_h->data_load_addr) && (rel_d[i].r_offset < exp_h->data_load_addr + exp_h->data_sz))
                {
                    fill_addr = ((uint32_t *)(&buf_exp[rel_d[i].r_offset - exp_h->data_load_addr + exp_h->data_fo]));
                    INFO("content(in DATA): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= exp_h->reloc_load_addr) && (rel_d[i].r_offset < exp_h->reloc_load_addr + exp_h->reloc_sz))
                {
                    fill_addr = ((uint32_t *)(&buf_exp[rel_d[i].r_offset - exp_h->reloc_load_addr + exp_h->reloc_fo]));
                    INFO("content(in REL ): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= exp_h->text_load_addr) && (rel_d[i].r_offset < exp_h->text_load_addr + exp_h->text_sz))
                {
                    fill_addr = ((uint32_t *)(&buf_exp[rel_d[i].r_offset - exp_h->text_load_addr + exp_h->text_fo]));
                    INFO("content(in TEXT): %08x ", *fill_addr);
                }
                else
                {
                    fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &buf_exp[sym->st_name + exp_h->dynstr_of]);
                    ret = -1;
                    goto exit02;
                }

                INFO("sym :%s\n", &buf_exp[sym->st_name + exp_h->dynstr_of]);
            }
            else if ((rel_d[i].r_info & 0xFF) == R_ARM_JUMP_SLOT)
            {

                INFO("R_ARM_JUMP_SLOT, at:%08x, link_to_addr:%08x, ", rel_d[i].r_offset, sym->st_value);
                if ((rel_d[i].r_offset >= exp_h->data_load_addr) && (rel_d[i].r_offset < exp_h->data_load_addr + exp_h->data_sz))
                {
                    fill_addr = ((uint32_t *)(&buf_exp[rel_d[i].r_offset - exp_h->data_load_addr + exp_h->data_fo]));
                    INFO("content(in DATA): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= exp_h->reloc_load_addr) && (rel_d[i].r_offset < exp_h->reloc_load_addr + exp_h->reloc_sz))
                {
                    fill_addr = ((uint32_t *)(&buf_exp[rel_d[i].r_offset - exp_h->reloc_load_addr + exp_h->reloc_fo]));
                    INFO("content(in REL ): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= exp_h->text_load_addr) && (rel_d[i].r_offset < exp_h->text_load_addr + exp_h->text_sz))
                {
                    fill_addr = ((uint32_t *)(&buf_exp[rel_d[i].r_offset - exp_h->text_load_addr + exp_h->text_fo]));
                    INFO("content(in TEXT): %08x ", *fill_addr);
                }
                else
                {
                    fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &buf_exp[sym->st_name + exp_h->dynstr_of]);
                    ret = -1;
                    goto exit02;
                }

                INFO("sym :%s\n", &buf_exp[sym->st_name + exp_h->dynstr_of]);
            }
            else
            {

                fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &buf_exp[sym->st_name + exp_h->dynstr_of]);
                ret = -1;
                goto exit02;
            }

            if (sym->st_value == 0)
            {
                uint32_t sym_in_sys = search_sys_sym((char *)&buf_exp[sym->st_name + exp_h->dynstr_of]);
                if (sym_in_sys == 0xFFFFFFFF)
                {
                    fprintf(stderr, "ERROR: Unresolved Symbol:%s\n", &buf_exp[sym->st_name + exp_h->dynstr_of]);
                    ret = -1;
                    goto exit2;
                }
                *fill_addr = sym_in_sys;
                printf("Relocate, at:%08x, link_addr-app:%08x -> new sys:%08x, sym: %s \n", rel_d[i].r_offset, sym->st_value, *fill_addr, &buf_exp[sym->st_name + exp_h->dynstr_of]);
            }
        }

        // resolve rel.plt
        printf("resolve rel.plt: \n\n");

        rel_d = (Elf32_Rel *)(buf_exp + (uint32_t)exp_h->rel_plt_of);
        for (int i = 0; i < exp_h->num_rel_plt; i++)
        {
            sym = (Elf32_Sym *)((uint32_t)buf_exp + (uint32_t)exp_h->dynsym_of);
            sym += (uint32_t)(rel_d[i].r_info >> 8);

            if ((rel_d[i].r_info & 0xFF) == R_ARM_JUMP_SLOT)
            {

                INFO("R_ARM_JUMP_SLOT, at:%08x, link_to_addr:%08x, ", rel_d[i].r_offset, sym->st_value);
                if ((rel_d[i].r_offset >= exp_h->data_load_addr) && (rel_d[i].r_offset < exp_h->data_load_addr + exp_h->data_sz))
                {
                    fill_addr = ((uint32_t *)(&buf_exp[rel_d[i].r_offset - exp_h->data_load_addr + exp_h->data_fo]));
                    INFO("content(in DATA): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= exp_h->reloc_load_addr) && (rel_d[i].r_offset < exp_h->reloc_load_addr + exp_h->reloc_sz))
                {
                    fill_addr = ((uint32_t *)(&buf_exp[rel_d[i].r_offset - exp_h->reloc_load_addr + exp_h->reloc_fo]));
                    INFO("content(in REL ): %08x ", *fill_addr);
                }
                else if ((rel_d[i].r_offset >= exp_h->text_load_addr) && (rel_d[i].r_offset < exp_h->text_load_addr + exp_h->text_sz))
                {
                    fill_addr = ((uint32_t *)(&buf_exp[rel_d[i].r_offset - exp_h->text_load_addr + exp_h->text_fo]));
                    INFO("content(in TEXT): %08x ", *fill_addr);
                }
                else
                {
                    fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &buf_exp[sym->st_name + exp_h->dynstr_of]);
                    ret = -1;
                    goto exit02;
                }
                INFO("sym :%s\n", &buf_exp[sym->st_name + exp_h->dynstr_of]);
            }
            else
            {

                fprintf(stderr, "ERROR 2: Unresolved Symbol:%s\n", &buf_exp[sym->st_name + exp_h->dynstr_of]);
                ret = -1;
                goto exit02;
            }
            if (sym->st_value == 0)
            {
                uint32_t sym_in_sys = search_sys_sym((char *)&buf_exp[sym->st_name + exp_h->dynstr_of]);
                if (sym_in_sys == 0xFFFFFFFF)
                {
                    fprintf(stderr, "ERROR: Unresolved Symbol:%s\n", &buf_exp[sym->st_name + exp_h->dynstr_of]);
                    ret = -1;
                    goto exit2;
                }
                *fill_addr = sym_in_sys;
                printf("Relocate, at:%08x, link_addr-app:%08x -> new sys:%08x, sym: %s \n", rel_d[i].r_offset, sym->st_value, *fill_addr, &buf_exp[sym->st_name + exp_h->dynstr_of]);
            }
        }
        exp_h->sys_hash = syssym_hash;
        strcpy(&exp_h->sys_build_date[0], sysbuild_date);
        fseek(f_exp, 0, SEEK_SET);
        fwrite(buf_exp, 1, sz_exp, f_exp);
        goto exit02;
    }

exit2:
    free(buf_syself);
    free(buf_appelf);

exit1:
    fclose(f_syself);
    fclose(f_appelf);
    fclose(f_exp);

exit0:
    return ret;

exit02:
    free(buf_exp);
    free(buf_syself);

exit01:
    fclose(f_syself);
    fclose(f_exp);

exit00:
    return ret;
}
void Usage()
{
    // eld --appelf xxx.elf --syself xxx.elf --exp xxx.exp
    // eld --syself xxx.elf --exp xxx.exp
    printf("Usage:\n");
    printf("\teld --appelf xxx.elf --syself xxx.elf --exp xxx.exp\n");
    printf("\teld --syself xxx.elf --exp xxx.exp\n");
    exit(-1);
}
