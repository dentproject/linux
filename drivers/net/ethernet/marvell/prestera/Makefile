# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_PRESTERA)	+= prestera.o
prestera-objs		:= prestera_main.o prestera_hw.o prestera_dsa.o \
			   prestera_rxtx.o prestera_devlink.o prestera_ethtool.o \
			   prestera_switchdev.o prestera_acl.o prestera_flow.o \
			   prestera_flower.o prestera_span.o prestera_counter.o \
			   prestera_router.o prestera_router_hw.o prestera_matchall.o \
			   prestera_ct.o prestera_dcb.o prestera_qdisc.o \
			   prestera_fw.o prestera_debugfs.o prestera_fw_log.o \
			   prestera_nve.o

prestera-$(CONFIG_MRVL_PRESTERA_DEBUG) += prestera_log.o
ccflags-$(CONFIG_MRVL_PRESTERA_DEBUG) += -DCONFIG_MRVL_PRESTERA_DEBUG

obj-$(CONFIG_PRESTERA_PCI)	+= prestera_pci.o
obj-$(CONFIG_PRESTERA_SHM)	+= prestera_shm.o
