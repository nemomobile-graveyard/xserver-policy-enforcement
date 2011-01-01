#ifndef POLICY_XRANDR_H
#define POLICY_XRANDR_H

#include <dix.h>
#include <extnsionst.h>

Bool XrandrInit(void);
void XrandrExit(void);
int  XrandrAuthorizeRequest(ClientPtr, ExtensionEntry *);

#endif	/* POLICY_XRANDR_H */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
