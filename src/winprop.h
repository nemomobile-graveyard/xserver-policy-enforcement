#ifndef POLICY_WINPROP_H
#define POLICY_WINPROP_H

#include <dix.h>
#include <property.h>

Bool WinpropInit(void);
void WinpropExit(void);
int  WinpropAuthorizeRequest(ClientPtr, WindowPtr, PropertyPtr, CARD32);

#endif	/* POLICY_WINPROP_H */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
