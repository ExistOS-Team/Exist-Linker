#pragma once

#include <stdint.h>

typedef struct exp_header_t
{
    uint32_t Mark0;     //0x5AA52333
    uint32_t Mark1;     //1936291909    Exis
    uint32_t Mark2;     //1347436916    tApp

    uint32_t exp_ver;   //1

    uint32_t sys_hash;

    uint32_t entry;

    uint32_t reloc_load_addr;
    uint32_t data_load_addr;
    uint32_t text_load_addr;

    uint32_t reloc_fo;
    uint32_t data_fo;
    uint32_t text_fo;

    uint32_t reloc_sz;
    uint32_t data_sz;
    uint32_t text_sz;

    uint32_t dynsym_of;
    uint32_t dynstr_of;
    uint32_t rel_dyn_of;
    uint32_t rel_plt_of;
    uint32_t got_of;

    uint32_t num_rel_dyn;
    uint32_t num_rel_plt;

    char sys_build_date[32];

}exp_header_t;


