/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#ifndef _MVSW_PRESTERA_FW_COMM_H_
#define _MVSW_PRESTERA_FW_COMM_H_

#include <linux/miscdevice.h>

#define PRESTERA_FW_COMM_DRIVER_NAME        "mvsw_fw_comm_debug"
#define PRESTERA_FW_COMM_HELP_CMD           "help"

#define PRESTERA_FW_COMM_MAX_MINORS         1
#define PRESTERA_FW_COMM_MAX_MSG_TYPE_SIZE  32
#define PRESTERA_FW_COMM_MAX_ARGS_SIZE      128

#define PRESTERA_FW_COMM_MAX_CMD_SIZE       (PRESTERA_FW_COMM_MAX_MSG_TYPE_SIZE + \
											PRESTERA_FW_COMM_MAX_ARGS_SIZE)

#define PRESTERA_FW_IN_USE_BIT              0

/**
 * Use 512 kB as a buffer
 */
#define PRESTERA_FW_COMM_DEV_MAX_BUFF_SIZE  (512 * 1024)
#define PRESTERA_FW_COMM_MAX_RECV_CHUNKS    (PRESTERA_FW_COMM_DEV_MAX_BUFF_SIZE /  \
											PRESTERA_MSG_DEBUG_INFRA_CHUNK_SIZE)

enum {
	PRESTERA_FW_COMM_TYPE_HELP,
	PRESTERA_FW_COMM_TYPE_SYS_METRICS,
	PRESTERA_FW_COMM_TYPE_KERNEL_LOGS,
	PRESTERA_FW_COMM_TYPE_CPSS_LOGS,
	PRESTERA_FW_COMM_TYPE_EXEC_LUACLI,
	PRESTERA_FW_COMM_TYPE_MAX
};

enum {
	PRESTERA_FW_COMM_ERR_CODE_OK = 0,
	PRESTERA_FW_COMM_ERR_CODE_PIPE,
	PRESTERA_FW_COMM_ERR_CODE_FORK,
	PRESTERA_FW_COMM_ERR_CODE_MAIN_TIMEOUT,
	PRESTERA_FW_COMM_ERR_CODE_READ,
	PRESTERA_FW_COMM_ERR_CODE_OPEN,
	PRESTERA_FW_COMM_ERR_CODE_SEEK,
	PRESTERA_FW_COMM_ERR_CODE_INVALID_REQ,
	PRESTERA_FW_COMM_ERR_CODE_CHILD_FAIL,
	PRESTERA_FW_COMM_ERR_CODE_OFFSET_OVERFLOW,
	PRESTERA_FW_COMM_ERR_CODE_MAX,
};

struct prestera_switch;

struct prestera_fw_comm {
	struct miscdevice misc_dev;
	struct prestera_switch *sw;
	unsigned long flags;
	char *output_buff;
	int output_size;
	bool is_locked;
};

int pr_fw_communication_init(struct prestera_switch *sw);
void pr_fw_communication_fini(struct prestera_switch *sw);

#endif /* _MVSW_PRESTERA_FW_COMM_H_ */
