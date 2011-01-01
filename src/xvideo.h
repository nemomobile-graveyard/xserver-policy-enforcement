#ifndef POLICY_XVIDEO_H
#define POLICY_XVIDEO_H

#include <dix.h>
#include <extnsionst.h>

#include <X11/extensions/Xv.h>


Bool XvideoInit(void);
void XvideoExit(void);
int  XvideoAuthorizeRequest(ClientPtr, ExtensionEntry *);
void XvideoFixupProcVector(int);
void XvideoKillUnathorizedClients(unsigned char, pid_t *, int);;
Bool XvideoClientHoldsResource(ClientPtr);

#endif	/* POLICY_XVIDEO_H */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
