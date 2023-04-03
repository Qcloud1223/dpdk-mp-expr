# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Intel Corporation

subdirs := mp_client mp_server

.PHONY: all static shared clean debug $(subdirs)
all static shared clean debug: $(subdirs)

$(subdirs):
	$(MAKE) -C $@ $(MAKECMDGOALS)
