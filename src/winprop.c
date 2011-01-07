#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "policy.h"
#include "winprop.h"
#include "client.h"
#include "authorize.h"

#include <misc.h>
#include <dixstruct.h>
#include <dixaccess.h>
#include <scrnintstr.h>
#include <windowstr.h>
#include <propertyst.h>

#include <X11/X.h>
#include <X11/Xatom.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define VIDEO_CLIENTS   "_MEEGO_VIDEO_CLIENT_PIDS"

static ATOM   VideoClientsAtom;

static int VideoClientsChanged(WindowPtr, PropertyPtr, CARD32, int *);


Bool
WinpropInit(void)
{
    VideoClientsAtom = MakeAtom(VIDEO_CLIENTS, strlen(VIDEO_CLIENTS), TRUE);

    if (VideoClientsAtom == None)
        return FALSE;

    return TRUE;
}

void
WinpropExit(void)
{
}

int
WinpropAuthorizeRequest(ClientPtr    client,
			WindowPtr    window,
			PropertyPtr  property,
			CARD32       access)
{
    int result = Success;

    if ((access & DixWriteAccess) == DixWriteAccess) {
        if (window->parent == NULL) { /* root window */

            do { /* not a loop */
                if (VideoClientsChanged(window, property, access, &result))
                    break;

            } while(0);
        }
    }

    return result;
}

static int
VideoClientsChanged(WindowPtr    window,
                    PropertyPtr  property,
                    CARD32       access,
                    int         *result)
{
    int    done;
    int    npid;
    pid_t  pids[MAXCLIENTS];
    int    i;
    char   buf[512];
    char  *p, *e;

    return TRUE; /* disable this */

    if (property->propertyName != VideoClientsAtom)
        done = FALSE;
    else {
        done = TRUE;

        if (property->type != XA_CARDINAL || property->format != 32)
            *result = BadMatch;
        else {
            npid = property->size;

            if (npid < 0 || npid >= MAXCLIENTS)
                *result = BadValue;
            else {
                for (i = 0; i < npid; i++)
                    pids[i] = (pid_t)((CARD32 *)property->data)[i];

                for (i=0, e=(p=buf)+sizeof(buf);   i < npid && p < e;   i++)
                    p += snprintf(p, e-p, "%s%u", (i ? ", ":""), pids[i]);

                PolicyDebug("Root property '%s' changed: [%s]",
                            VIDEO_CLIENTS, buf);

                AuthorizeClients(AuthorizeXvideo, 5000, pids, npid);
            }
        }
    }

    return done;
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
