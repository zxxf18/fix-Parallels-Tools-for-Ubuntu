/*
 *	prltg_call.h
 *	Parallels Toolgate driver kernelspace interface
 *	Copyright (c) 1999-2016 Parallels International GmbH. All rights reserved.
 */

#include "Toolgate/Guest/Linux/Interfaces/prltg.h"
extern int call_tg_sync(struct pci_dev *, TG_REQ_DESC *);
