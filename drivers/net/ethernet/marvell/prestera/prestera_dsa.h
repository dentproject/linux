/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved. */

#ifndef _PRESTERA_DSA_H_
#define _PRESTERA_DSA_H_

#include <linux/types.h>

#define PRESTERA_DSA_HLEN	16
#define PRESTERA_DSA_AC5_HLEN	8

enum prestera_dsa_type {
	/* 16 bytes eDSA for eARCH devices: AC3X, ALDRIN2, AC5X */
	PRESTERA_DSA_TYPE_EDSA16 = 0,

	/* 8 bytes extended DSA for AC5 */
	PRESTERA_DSA_TYPE_EXTDSA8,
};

enum prestera_dsa_cmd {
	/* DSA command is "To CPU" */
	PRESTERA_DSA_CMD_TO_CPU = 0,

	/* DSA command is "FROM CPU" */
	PRESTERA_DSA_CMD_FROM_CPU = 1,

	/* DSA command is "FORWARD" */
	PRESTERA_DSA_CMD_FORWARD = 3,
};

struct prestera_dsa_common {
	/* the value vlan priority tag (APPLICABLE RANGES: 0..7) */
	u8 vpt;

	/* CFI bit of the vlan tag (APPLICABLE RANGES: 0..1) */
	u8 cfi_bit;

	/* Vlan id */
	u16 vid;
};

struct prestera_dsa_to_cpu {
	bool is_tagged;
	u32 hw_dev_num;
	bool src_is_trunk;
	u8 cpu_code;
	struct {
		u16 src_trunk_id;
		u32 port_num;
		u32 eport;
	} iface;
};

struct prestera_dsa_from_cpu {
	struct prestera_iface dst_iface;	/* vid/port */
	bool egr_filter_en;
	bool egr_filter_registered;
	u32 src_id;
	u32 src_hw_dev;
	u32 dst_eport;	/* for port but not for vid */
};

struct prestera_dsa {
	struct prestera_dsa_common common_params;
	enum prestera_dsa_cmd dsa_cmd;
	enum prestera_dsa_type dsa_type;
	union {
		struct prestera_dsa_to_cpu to_cpu;
		struct prestera_dsa_from_cpu from_cpu;
	} dsa_info;
};

int prestera_dsa_parse(const u8 *dsa_bytes_ptr,
		       struct prestera_dsa *dsa_info_ptr);
int prestera_dsa_build(const struct prestera_dsa *dsa_info_ptr,
		       u8 *dsa_bytes_ptr);

#endif /* _PRESTERA_DSA_H_ */
