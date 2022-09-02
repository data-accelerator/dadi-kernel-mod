#ifndef __DM_OVBD_HEADER__
#define __DM_OVBD_HEADER__

#include "log-format.h"
#include "dm-lsmt.h"
#include "dm-zfile.h"
#include <linux/module.h>

typedef struct ovbd_context {
	struct workqueue_struct *wq;
} ovbd_context;

ovbd_context* get_ovbd_context(void);

#endif