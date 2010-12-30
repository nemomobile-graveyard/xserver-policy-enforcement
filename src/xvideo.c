#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "policy.h"
#include "xvideo.h"
#include "client.h"

#include <resource.h>
#include <registry.h>
#include <extnsionst.h>
#include <dixstruct.h>
#include <scrnintstr.h>
#include <xvdix.h>


#include <stdio.h>

#ifdef XREGISTRY
#define RESOURCE_NAME(r)  LookupresourceName(r)
#else
#define RESOURCE_NAME(r)  #r
#endif

typedef struct {
    ClientPtr client;
    int hits;
    struct {
        RESTYPE type;
        const char *name;
    } res;
} ResourceLookupRec;

static Bool KillUnathorizedClient(ClientPtr, pid_t *, int, const char *);
static void FoundResource(pointer, XID, pointer);
static const char *RequestName(unsigned short);
static int  RequestPort(unsigned short, pointer);


Bool
XvideoInit(void)
{
    return TRUE;
}

void
XvideoExit(void)
{
}

int
XvideoAuthorizeRequest(ClientPtr client, pointer data)
{
    ExtensionEntry *ext    = (ExtensionEntry *)data;
    unsigned short  opcode = StandardMinorOpcode(client);
    ClientPolicyPtr policy = ClientGetPolicyRec(client);
    int             port   = RequestPort(opcode, client->requestBuffer);
     

    if (port < 0) {
        PolicyTrace("client %p (pid %u exe '%s') requested Xv %s",
                    client, policy->pid, policy->exe, RequestName(opcode));
    }
    else {
        PolicyTrace("client %p (pid %u exe '%s') requested Xv %s (port %d)",
                    client, policy->pid, policy->exe,
                    RequestName(opcode), port);
    }


    return Success;
}

void
XvideoKillUnathorizedClients(unsigned char adaptor_type,
                             pid_t        *AuthorizedClients,
                             int           NumberOfClients)
{
    DevPrivateKey key;
    ScreenPtr     scrn;
    XvScreenPtr   xvsc;
    XvAdaptorPtr  adapt;
    XvPortPtr     port;
    ClientPtr     client;
    char          reason[256];
    int           i, j, k;

    if ((key = XvGetScreenKey()) == NULL)
        return; /* should not happen */

    for (i = 0;    i < screenInfo.numScreens;   i++) {
        scrn = screenInfo.screens[i];

        if (scrn != NULL) {
            xvsc = (XvScreenPtr)dixLookupPrivate(&scrn->devPrivates, key);

            if (xvsc != NULL) {
                for (j = 0;   j < xvsc->nAdaptors;   j++) {
                    adapt = xvsc->pAdaptors + j;
                    
                    if ((adaptor_type & adapt->type) != 0) {

                        for (k = 0;  k < adapt->nPorts;  k++) {
                            port = adapt->pPorts + k;

                            snprintf(reason, sizeof(reason), "unauthorized "
                                     "use of Xv port %lu on adaptor '%s'",
                                     port->id, adapt->name);

                            if ((client = port->grab.client) != NULL) {
                                KillUnathorizedClient(client,
                                                      AuthorizedClients,
                                                      NumberOfClients,
                                                      reason);
                            }

                            if (port->client && port->client != client) {
                                KillUnathorizedClient(port->client,
                                                      AuthorizedClients,
                                                      NumberOfClients,
                                                      reason);
                            }
                        }
                    }
                }
            }
        }
    }
}

Bool
XvideoClientHoldsResource(ClientPtr client)
{
    ResourceLookupRec lookups[] = {
        {client, 0, {XvRTGrab, RESOURCE_NAME(XvRTGrab)}},
        {NULL  , 0, {   0    , NULL                   }}
    };
    ResourceLookupRec *lookup;
    Bool               holds;

    for (lookup = lookups, holds = FALSE;    lookup->client;    lookup++) {
        FindClientResourcesByType(lookup->client,
                                  lookup->res.type,
                                  FoundResource,
                                  lookup);
        if (lookup->hits > 0)
            holds = TRUE;
    }

    return holds;
}

static Bool
KillUnathorizedClient(ClientPtr   client,
                      pid_t      *AuthorizedClients,
                      int         NumberOfClients,
                      const char *reason)
{
    ClientPolicyPtr policy;
    pid_t           pid;
    int             i;

    if (client == NULL)
        return FALSE;

    policy = ClientGetPolicyRec(client);
    pid    = policy->pid;

    if (!pid)
        return FALSE;


    if (AuthorizedClients != NULL) {
        for (i = 0;    i < NumberOfClients;    i++) {
            if (pid == AuthorizedClients[i])
                return FALSE;
        }
    }


    PolicyDebug("close down connection to client %p (pid %u exe '%s') "
                "because of %s", client, pid, policy->exe, reason);

#if 0
    if (!client->clientGone)
        client->closeDownMode = DestroyAll;
#endif

    CloseDownClient(client);
    
    return TRUE;
} 

static void
FoundResource(pointer value, XID rsid, pointer cdata)
{
    ResourceLookupRec *lookup = (ResourceLookupRec *)cdata;
    ClientPtr          client  = lookup->client;
    ClientPolicyPtr    policy  = ClientGetPolicyRec(client);

    (void)value;

    PolicyDebug("client %p (pid %u exe '%s') holds '%s' resource",
                client, policy->pid, policy->exe,
                lookup->res.name ? lookup->res.name : "?");

    lookup->hits++;
}


static const char *
RequestName(unsigned short opcode)
{
    switch (opcode) {
    case xv_QueryExtension:        return "QueryExtension";
    case xv_QueryAdaptors:         return "QueryAdaptors";
    case xv_QueryEncodings:        return "QueryEncodings";
    case xv_GrabPort:              return "GrabPort";
    case xv_UngrabPort:            return "UngrabPort";
    case xv_PutVideo:              return "PutVideo";
    case xv_PutStill:              return "PutStill";
    case xv_GetVideo:              return "GetVideo";
    case xv_GetStill:              return "GetStill";
    case xv_StopVideo:             return "StopVideo";
    case xv_SelectVideoNotify:     return "SelectVideoNotify";
    case xv_SelectPortNotify:      return "SelectPortNotify";
    case xv_QueryBestSize:         return "QueryBestSize";
    case xv_SetPortAttribute:      return "SetPortAttribute";
    case xv_GetPortAttribute:      return "GetPortAttribute";
    case xv_QueryPortAttributes:   return "QueryPortAttributes";
    case xv_ListImageFormats:      return "ListImageFormats";
    case xv_QueryImageAttributes:  return "QueryImageAttributes";
    case xv_PutImage:              return "PutImage";
    case xv_ShmPutImage:           return "ShmPutImage";
    default:                       return "<unknown>";
    }
}

static int
RequestPort(unsigned short opcode, pointer buf)
{
    int port;

    if (buf == NULL)
        port = -1;
    else {
        switch (opcode) {
        case xv_GrabPort:
            port = ((xvGrabPortReq *)buf)->port;
            break;
        case xv_UngrabPort:
        port = ((xvUngrabPortReq *)buf)->port;
        break;
        case xv_PutVideo:
            port = ((xvPutVideoReq *)buf)->port;
            break;
        case xv_PutStill:
            port = ((xvPutStillReq *)buf)->port;
            break;
        case xv_GetVideo:
            port = ((xvGetVideoReq *)buf)->port;
            break;
        case xv_GetStill:
            port = ((xvGetStillReq *)buf)->port;
            break;
        case xv_StopVideo:
            port = ((xvStopVideoReq *)buf)->port;
            break;
        case xv_SelectPortNotify:
            port = ((xvSelectPortNotifyReq *)buf)->port;
            break;
        case xv_QueryBestSize:
            port = ((xvQueryBestSizeReq *)buf)->port;
            break;
        case xv_SetPortAttribute:
            port = ((xvSetPortAttributeReq *)buf)->port;
            break;
        case xv_GetPortAttribute:
            port = ((xvGetPortAttributeReq *)buf)->port;
            break;
        case xv_QueryPortAttributes:
            port = ((xvQueryPortAttributesReq *)buf)->port;
            break;
        case xv_ListImageFormats:
            port = ((xvListImageFormatsReq *)buf)->port;
            break;
        case xv_QueryImageAttributes:
            port = ((xvQueryImageAttributesReq *)buf)->port;
            break;
        case xv_PutImage:
            port = ((xvPutImageReq *)buf)->port;
            break;
        case xv_ShmPutImage:
            port = ((xvShmPutImageReq *)buf)->port;
            break;
        default:
            port = -1;
            break;
        }
    }

    return port;
}





/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
