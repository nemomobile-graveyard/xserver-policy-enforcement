#ifndef POLICY_IPC_H
#define POLICY_IPC_H

#include <X11/Xdefs.h>

#include "videoipc.h"

Bool IpcInit(void);
void IpcExit(void);
void IpcUpdate(unsigned long);

#endif	/* POLICY_IPC_H */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
