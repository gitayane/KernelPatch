/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "hook.h"

#include <stdint.h>

static uint64_t mem_region_start = 0;
static uint64_t mem_region_end = 0;

typedef struct
{
    int using;
    enum hook_type type;
    uintptr_t addr;
    // must align 8
    union
    {
        hook_t inl;
        hook_chain_t inl_chain;
        fp_hook_chain_t fp_chain;
    } chain __attribute__((aligned(8)));
} hook_mem_warp_t __attribute__((aligned(16)));

int hook_mem_add(uint64_t start, int32_t size)
{
    for (uint64_t i = start; i < start + size; i += 8) {
        *(uint64_t *)i = 0;
    }
    mem_region_start = start;
    mem_region_end = start + size;
    return 0;
}

void *hook_mem_zalloc(uintptr_t origin_addr, enum hook_type type)
{
    uint64_t start = mem_region_start;
    for (uint64_t addr = start; addr < mem_region_end; addr += sizeof(hook_mem_warp_t)) {
        hook_mem_warp_t *wrap = (hook_mem_warp_t *)addr;
        if (wrap->using) continue;

        wrap->using = 1;
        wrap->addr = origin_addr;
        wrap->type = type;

        uint64_t slot = (addr - mem_region_start) / sizeof(hook_mem_warp_t);
        uint64_t chain = (uint64_t)&wrap->chain;
        logkv("KP DBG hmem alloc: slot=%llu warp=%llx chain=%llx type=%d origin=%llx normal_transit=%llx fp_transit=%llx size=%llx\n",
              slot, addr, chain, (int)type, (uint64_t)origin_addr,
              chain + 0x280, chain + 0x340, (uint64_t)sizeof(hook_mem_warp_t));

        for (uintptr_t i = (uintptr_t)&wrap->chain; i < (uintptr_t)&wrap->chain + sizeof(wrap->chain); i += 8) {
            *(uint64_t *)i = 0;
        }

        // todo: assert
        if (((uintptr_t)&wrap->chain) & 0b111) {
            return 0;
        }
        return &wrap->chain;
    }
    return 0;
}

void hook_mem_free(void *hook_mem)
{
    hook_mem_warp_t *warp = local_container_of(hook_mem, hook_mem_warp_t, chain);
    uint64_t slot = ((uint64_t)warp - mem_region_start) / sizeof(hook_mem_warp_t);
    logkv("KP DBG hmem free: slot=%llu warp=%llx chain=%llx type=%d origin=%llx\n",
          slot, (uint64_t)warp, (uint64_t)&warp->chain, (int)warp->type, (uint64_t)warp->addr);
    warp->using = 0;
}

void *hook_get_mem_from_origin(uint64_t origin_addr)
{
    uint64_t start = mem_region_start;

    for (uint64_t addr = start; addr < mem_region_end; addr += sizeof(hook_mem_warp_t)) {
        hook_mem_warp_t *wrap = (hook_mem_warp_t *)addr;
        if (wrap->using && wrap->addr == origin_addr) {
            uint64_t slot = (addr - mem_region_start) / sizeof(hook_mem_warp_t);
            uint64_t chain = (uint64_t)&wrap->chain;
            logkv("KP DBG hmem lookup: slot=%llu warp=%llx chain=%llx type=%d origin=%llx normal_transit=%llx fp_transit=%llx\n",
                  slot, addr, chain, (int)wrap->type, (uint64_t)origin_addr,
                  chain + 0x280, chain + 0x340);
            return &wrap->chain;
        }
    }
    return 0;
}
