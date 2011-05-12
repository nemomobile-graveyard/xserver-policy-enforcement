#ifndef POLICY_XVIDEO_H
#define POLICY_XVIDEO_H

#include <dix.h>
#include <extnsionst.h>

#include <X11/extensions/Xv.h>

#define XVIDEO_RESTRICT_XVATTR_ACCESS   "restrict-xvattr-access"

Bool XvideoInit(void);
void XvideoExit(void);
Bool XvideoParseOption(char *, char *);
int  XvideoAuthorizeRequest(ClientPtr, ExtensionEntry *);
void XvideoFixupProcVector(int);
void XvideoKillUnathorizedClients(unsigned char, pid_t *, int, pid_t);
Bool XvideoClientHoldsResource(ClientPtr);

#endif	/* POLICY_XVIDEO_H */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
