/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 */

#ifndef _KP_HOTPATCH_H_
#define _KP_HOTPATCH_H_

#include <stdint.h>

int hotpatch(void *addrs[], uint32_t values[], int cnt);
int hotpatch_nosync(void *addr, uint32_t value);
int hotpatch_data_u64(void *addr, uint64_t value);

#endif