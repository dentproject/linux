// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "prestera_fw_comm.h"
#include "prestera_hw.h"
#include "prestera.h"

static const char *pr_fw_comm_msg_id_to_str[PRESTERA_FW_COMM_TYPE_MAX] = {
	[PRESTERA_FW_COMM_TYPE_HELP] = "help",
	[PRESTERA_FW_COMM_TYPE_SYS_METRICS] = "system_metrics",
	[PRESTERA_FW_COMM_TYPE_KERNEL_LOGS] = "kernel_logs",
	[PRESTERA_FW_COMM_TYPE_CPSS_LOGS] = "cpss_logs",
	[PRESTERA_FW_COMM_TYPE_EXEC_LUACLI] = "exec_luacli"
};

static const char *pr_fw_err_code_to_str[PRESTERA_FW_COMM_ERR_CODE_MAX] = {
	[PRESTERA_FW_COMM_ERR_CODE_PIPE] =
		"[DbgInfra] FW-CPU: Error when running pipe()",
	[PRESTERA_FW_COMM_ERR_CODE_FORK] =
		"[DbgInfra] FW-CPU: Error when running fork()",
	[PRESTERA_FW_COMM_ERR_CODE_MAIN_TIMEOUT] =
		"[DbgInfra] FW-CPU: Child process timeout while executing command",
	[PRESTERA_FW_COMM_ERR_CODE_READ] =
		"[DbgInfra] FW-CPU: Error when running read()",
	[PRESTERA_FW_COMM_ERR_CODE_OPEN] =
		"[DbgInfra] FW-CPU: Error when running open()",
	[PRESTERA_FW_COMM_ERR_CODE_SEEK] =
		"[DbgInfra] FW-CPU: Error when running lseek()",
	[PRESTERA_FW_COMM_ERR_CODE_INVALID_REQ] =
		"[DbgInfra] FW-CPU: Invalid request",
	[PRESTERA_FW_COMM_ERR_CODE_CHILD_FAIL] =
		"[DbgInfra] FW-CPU: Child process returned an error",
	[PRESTERA_FW_COMM_ERR_CODE_OFFSET_OVERFLOW] =
		"[DbgInfra] FW-CPU: File offset overflow. Resetting pointer."
};

static const char pr_fw_comm_help_prompt[] = \
"Available commands:\n \
help - shows this prompt\n \
system_metrics - shows system metrics from FW CPU\n \
kernel_logs  - shows logs from kernel ring buffer\n \
cpss_logs - shows logs of appDemo service\n \
kernel_logs/cpss_logs <reset> - resets the pointer to the beginning of the logs\n \
exec_luacli <command> - executes <command> in luaCLI in FW CPU\n\0";

/**
 * pr_fw_communication_parse_request() - Method parsing the string
 *   received from the user space.
 * @request: pointer to the string
 * @msg_type: message type
 * @msg_args: message arguments
 *
 * The method is splitting the string into type and arguments.
 * The request must contain at least a type, arguments being
 * optional for most of the types. Once the string containing
 * the type is determined, the corresponding enum type
 * will be found in @pr_fw_comm_msg_id_to_str.
 *
 * Return: 0 if successful, error code otherwise. Returns message type
 * through @msg_type and message arguments through @msg_args.
 */
static int pr_fw_communication_parse_request(char *request, int *msg_type,
					     char *msg_args)
{
	char msg_type_str[PRESTERA_FW_COMM_MAX_MSG_TYPE_SIZE] = { 0 };
	char *msg_type_ppos, *args_ppos;
	char *aux_buf = request;
	int i, ret = 0;

	*msg_type = PRESTERA_FW_COMM_TYPE_MAX;

	/* Split the request in two: a message type and a string
	 * containing all the args(if any).
	 */
	msg_type_ppos = strsep(&aux_buf, " \t\0");
	args_ppos = strsep(&aux_buf, "\0");

	/* Message type is mandatory. Args can be skipped.
	 */
	if (!msg_type_ppos) {
		ret = -EINVAL;
		goto out;
	}

	/* Make sure that the strings are valid.
	 */
	if (iscntrl(msg_type_ppos[0]) || isspace(msg_type_ppos[0]) ||
	    msg_type_ppos[0] == '\0' ||
				strlen(msg_type_ppos) > PRESTERA_FW_COMM_MAX_MSG_TYPE_SIZE) {
		ret = -EINVAL;
		goto out;
	}

	strcpy(msg_type_str, msg_type_ppos);

	if (args_ppos) {
		if (iscntrl(args_ppos[0]) || isspace(args_ppos[0]) ||
		    args_ppos[0] == '\0' ||
			strlen(args_ppos) > PRESTERA_FW_COMM_MAX_ARGS_SIZE) {
			ret = -EINVAL;
			goto out;
		}
		strcpy(msg_args, args_ppos);
	}

	/* Try to match the requested message type to an internal message type.
	 */
	for (i = 0; i < PRESTERA_FW_COMM_TYPE_MAX; ++i) {
		if (!strcmp(msg_type_str, pr_fw_comm_msg_id_to_str[i])) {
			*msg_type = i;
			break;
		}
	}

	/* We expect arguments only for PRESTERA_FW_COMM_TYPE_EXEC_LUACLI
	 */
	if ((*msg_type == PRESTERA_FW_COMM_TYPE_MAX) ||
	    (*msg_type == PRESTERA_FW_COMM_TYPE_EXEC_LUACLI && !args_ppos))
		ret = -EINVAL;

out:
	return ret;
}

/**
 * pr_fw_communication_reset_buff() - Method clearing the
 *  output buffer before storing a new request's response.
 * @fw_comm_data: structure containing the buffer
 *
 */
static void pr_fw_communication_reset_buff(struct prestera_fw_comm *fw_comm_data)
{
	memset(fw_comm_data->output_buff, 0, PRESTERA_FW_COMM_DEV_MAX_BUFF_SIZE);
	fw_comm_data->output_size = 0;
}

/**
 * pr_fw_communication_handle_request() - Method handling the incoming requests
 *
 * @msg_type: type of the message to filter for
 * @msg_args: arguments passed in from the console
 * @fw_comm_data: structure containing the output buffer
 *
 * Return: 0 if successful, error code otherwise.
 */
static int pr_fw_communication_handle_request(int msg_type,
					      char *msg_args, struct prestera_fw_comm *fw_comm_data)
{
	int ret = 0;
	unsigned char fw_err_code = PRESTERA_FW_COMM_ERR_CODE_OK;
	struct prestera_switch *sw = fw_comm_data->sw;

	pr_fw_communication_reset_buff(fw_comm_data);

	switch (msg_type) {
	case PRESTERA_FW_COMM_TYPE_HELP:
		fw_comm_data->output_size = sizeof(pr_fw_comm_help_prompt);
		memcpy(fw_comm_data->output_buff, pr_fw_comm_help_prompt, fw_comm_data->output_size);
		break;
	case PRESTERA_FW_COMM_TYPE_SYS_METRICS:
	case PRESTERA_FW_COMM_TYPE_KERNEL_LOGS:
	case PRESTERA_FW_COMM_TYPE_CPSS_LOGS:
	case PRESTERA_FW_COMM_TYPE_EXEC_LUACLI:
		/* Send a message to the FW CPU */
		ret = prestera_hw_dbg_req_send(sw, msg_type, msg_args, &fw_err_code);
		if (fw_err_code > PRESTERA_FW_COMM_ERR_CODE_OK &&
		    fw_err_code < PRESTERA_FW_COMM_ERR_CODE_MAX)
			dev_err(sw->dev->dev, pr_fw_err_code_to_str[fw_err_code]);
			pr_err("ERROR CODE IS : %d\n", fw_err_code);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * pr_fw_communication_open() - Method called every time
 * the /dev entry is opened(including when reading/writing to the file).
 *
 * @inode: kernel-internal structure representing the entry on the disk
 * @file: kernel-internal structure representing the open /dev entry
 *
 * This method is getting the prestera_fw_comm structure from the miscdevice
 * stored as a private_data in the struct file. Once opened, it sets the IN_USE
 * bit so no other process can open the driver and send commands.
 *
 * Return: 0 if successful, error code otherwise.
 */
static int pr_fw_communication_open(struct inode *inode, struct file *file)
{
	struct miscdevice *misc_dev = file->private_data;
	struct prestera_fw_comm *fw_comm_data =
		container_of(misc_dev, struct prestera_fw_comm, misc_dev);

	file->private_data = fw_comm_data;

	if (test_and_set_bit(PRESTERA_FW_IN_USE_BIT, &fw_comm_data->flags))
		return -EBUSY;

	return 0;
}

/**
 * pr_fw_communication_close() - Method called every time
 * the /dev entry is closed(including when reading/writing to the file).
 *
 * @inode: kernel-internal structure representing the entry on the disk
 * @file: kernel-internal structure representing the open /dev entry
 *
 * Clears the IN_USE bit that blocked clients to open the device driver.
 *
 * Return: 0 if successful, error code otherwise.
 */
static int pr_fw_communication_release(struct inode *inode, struct file *file)
{
	struct miscdevice *misc_dev = file->private_data;
	struct prestera_fw_comm *fw_comm_data =
		container_of(misc_dev, struct prestera_fw_comm, misc_dev);

	smp_mb__before_atomic();
	clear_bit(PRESTERA_FW_IN_USE_BIT, &fw_comm_data->flags);
	return 0;
}

/**
 * pr_fw_communication_read() - Method called when reading
 * from the /dev entry. This will display the output of a prior request.
 *
 * @file: kernel-internal structure representing the open /dev entry
 * @ubuff: destination buffer in userspace
 * @size: size of the destination buffer
 * @offset: offset in the source buffer
 *
 *
 * On success, the number of bytes read is returned and the offset @offset is
 * advanced by this number, or negative value is returned on error.
 */
static ssize_t pr_fw_communication_read(struct file *file,
					char __user *ubuff, size_t size, loff_t *offset)
{
	struct prestera_fw_comm *fw_comm_data = file->private_data;
	char *kbuff = fw_comm_data->output_buff;
	size_t kbuff_size = fw_comm_data->output_size;

	return simple_read_from_buffer(ubuff, size, offset, kbuff, kbuff_size);
}

/**
 * pr_fw_communication_write() - Method called when writing
 * to the /dev entry. This will send a request to the FW CPU.
 *
 * @file: kernel-internal structure representing the open /dev entry
 * @ubuff: source buffer present in userspace
 * @size: size of the source buffer
 * @offset: offset in the source buffer
 *
 *
 * On success, the number of bytes read from userspace is returned,
 * or negative value is returned on error.
 */
static ssize_t pr_fw_communication_write(struct file *file,
					 const char __user *ubuff, size_t size, loff_t *offset)
{
	struct prestera_fw_comm *fw_comm_data = file->private_data;
	struct prestera_switch *sw = fw_comm_data->sw;
	char tmp_buf[PRESTERA_FW_COMM_MAX_CMD_SIZE] = { 0 };
	char msg_args[PRESTERA_FW_COMM_MAX_ARGS_SIZE] = { 0 };
	int msg_type;
	size_t len_to_copy = size - 1;
	int ret = size;

	if (len_to_copy > PRESTERA_FW_COMM_MAX_CMD_SIZE) {
		dev_err(sw->dev->dev, "Len is > than max(%zu vs max possible %d)\n",
			len_to_copy, PRESTERA_FW_COMM_MAX_CMD_SIZE);
		ret = -ENOSPC;
		goto out;
	}

	if (copy_from_user(tmp_buf, ubuff, len_to_copy)) {
		ret = -EFAULT;
		goto out;
	}

	if (pr_fw_communication_parse_request(tmp_buf, &msg_type, msg_args))
		size = -EINVAL;
	else if (pr_fw_communication_handle_request(msg_type, msg_args, fw_comm_data))
		size = -EINVAL;

out:
	return size;
}

const struct file_operations pr_fw_comm_fops = {
	.owner = THIS_MODULE,
	.open = pr_fw_communication_open,
	.release = pr_fw_communication_release,
	.read = pr_fw_communication_read,
	.write = pr_fw_communication_write,
};

int pr_fw_communication_init(struct prestera_switch *sw)
{
	int ret = 0;
	struct prestera_fw_comm *fw_comm_data;

	fw_comm_data = kzalloc(sizeof(*fw_comm_data), GFP_KERNEL);
	if (!fw_comm_data)
		return -ENOMEM;

	fw_comm_data->output_buff = kzalloc(PRESTERA_FW_COMM_DEV_MAX_BUFF_SIZE, GFP_KERNEL);
	if (!fw_comm_data->output_buff) {
		kfree(fw_comm_data);
		return -ENOMEM;
	}
	fw_comm_data->output_size = 0;

	fw_comm_data->misc_dev.minor = MISC_DYNAMIC_MINOR;
	fw_comm_data->misc_dev.name = PRESTERA_FW_COMM_DRIVER_NAME;
	fw_comm_data->misc_dev.fops = &pr_fw_comm_fops;

	ret = misc_register(&fw_comm_data->misc_dev);
	if (ret) {
		kfree(fw_comm_data->output_buff);
		kfree(fw_comm_data);
		dev_err(sw->dev->dev, "Failed at misc_register() step : %d\n", ret);
		return ret;
	}

	sw->fw_comm = fw_comm_data;
	fw_comm_data->sw = sw;

	return 0;
}

void pr_fw_communication_fini(struct prestera_switch *sw)
{
	struct prestera_fw_comm *fw_comm_data = sw->fw_comm;

	misc_deregister(&fw_comm_data->misc_dev);
	kfree(fw_comm_data->output_buff);
	kfree(fw_comm_data);
}
