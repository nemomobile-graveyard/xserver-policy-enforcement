#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "policy.h"
#include "xvideo.h"
#include "client.h"
#include "ipc.h"

#include <misc.h>
#include <resource.h>
#include <registry.h>
#include <dixstruct.h>
#include <scrnintstr.h>
#include <xvdix.h>

#include <X11/X.h>

#include <stdio.h>

#ifdef XREGISTRY
#define RESOURCE_NAME(r)    LookupResourceName(r)
#else
#define RESOURCE_NAME(r)    #r
#endif

#define PORT_HASH_BITS      6
#define PORT_HASH_DIM       (1 << (PORT_HASH_BITS - 1))
#define PORT_HASH_MASK      (PORT_HASH_DIM - 1)
#define PORT_HASH_INDEX(p)  ((p) & PORT_HASH_MASK)

typedef struct {
    ClientPtr client;
    int hits;
    struct {
        RESTYPE type;
        const char *name;
    } res;
} ResourceLookupRec;

typedef struct _PortHash {
    struct _PortHash  *next;
    unsigned long      port;                 /* port ID */
    int                nclidx;               /* no of client indeces */
    int                clidxs[MAXCLIENTS];   /* client indeces */
} PortHashRec, *PortHashPtr;

static int (*ProcDispatchOriginal)(ClientPtr);
static int (*SProcDispatchOriginal)(ClientPtr);
static PortHashPtr PortHash[PORT_HASH_DIM];


static Bool KillUnathorizedClient(ClientPtr, pid_t *, int, const char *);
static void FoundResource(pointer, XID, pointer);
static int  ProcDispatch(ClientPtr);
static int  ProcGrabPort(ClientPtr);
static int  ProcFallback(ClientPtr);
static void QueueClient(unsigned long, ClientPtr);
static int  GetQueuedClients(unsigned long, ClientPtr *, int);
static void ResourceFreed(CallbackListPtr *, pointer, pointer);
static const char *RequestName(unsigned short);
static int  RequestPort(unsigned short, pointer);
static const char *AccessModeName(AccessMode);


Bool
XvideoInit(void)
{
    if (!AddCallback(&ResourceStateCallback, ResourceFreed, NULL))
        return FALSE;

    return TRUE;
}

void
XvideoExit(void)
{
}

int
XvideoAuthorizeRequest(ClientPtr client, ExtensionEntry *ext)
{
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
XvideoFixupProcVector(int index)
{
    if ((ProcDispatchOriginal  = ProcVector[index]       ) != NULL &&
        (SProcDispatchOriginal = SwappedProcVector[index]) != NULL    )
    {
        ProcVector[index]        = ProcDispatch;
        SwappedProcVector[index] = ProcDispatch;
    }
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

#if 0
                            if (port->client && port->client != client) {
                                KillUnathorizedClient(port->client,
                                                      AuthorizedClients,
                                                      NumberOfClients,
                                                      reason);
                            }
#endif
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

    if (client == NULL || (policy = ClientGetPolicyRec(client)) == NULL)
        return FALSE;

    if (!(pid = policy->pid))
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

static int
ProcDispatch(ClientPtr client)
{
    unsigned short opcode = StandardMinorOpcode(client);
    AccessMode     acmode = ClientAccessMode(client, AuthorizeXvideo);
    int            result;

    IpcUpdate(AUTHORIZE_XVIDEO);

    PolicyTrace("client %p Xv AccessMode '%s'", client,AccessModeName(acmode));

    switch (acmode) {

    default:
    case AccessUnathorized:
        switch (opcode) {

        case xv_QueryExtension:
        case xv_QueryAdaptors:
        case xv_QueryEncodings:
        case xv_SelectVideoNotify:
        case xv_SelectPortNotify:
        case xv_QueryBestSize:
        case xv_GetPortAttribute:
        case xv_QueryPortAttributes:
        case xv_ListImageFormats:
        case xv_QueryImageAttributes:
            result = ProcFallback(client);
            break;
            
        default:
            result = BadAccess;
            break;
        }
        break;

    case AccessAuthorized:
        result = ProcFallback(client);
        break;

    case AccessDeferred:
        if (opcode == xv_GrabPort)
            result = ProcGrabPort(client);
        else
            result = ProcFallback(client);
        break;

    case AccessTolerated:
        if (opcode == xv_GrabPort)
            result = BadAccess;
        else
            result = ProcFallback(client);
        break;
    }

    return result;
}

static int
ProcGrabPort(ClientPtr client)
{
    xvGrabPortReq *req = (xvGrabPortReq *)client->requestBuffer;
    unsigned long  id  = req->port;
    XvPortPtr      port;
    int            rc;

    rc = dixLookupResourceByType((pointer *)&port, id, XvRTPort,
                                 client, DixReadAccess);

    if (rc != Success)
        return rc;

    if (port->grab.client && client != port->grab.client) {
        QueueClient(id, client);
        ClientBlock(client, TRUE);
        return Success;
    }

    return ProcFallback(client);
}

static int
ProcFallback(ClientPtr client)
{
    int result;

    if (client->swapped)
        result = SProcDispatchOriginal(client);
    else
        result = ProcDispatchOriginal(client);

    return result;
}

static void
QueueClient(unsigned long port, ClientPtr client)
{
    int hidx  = PORT_HASH_INDEX(port);
    int clidx = client->index;
    PortHashPtr prev, entry;
    int i;

    for (prev = (PortHashPtr)&PortHash[hidx];  prev->next; prev = prev->next) {
        entry = prev->next;

        if (entry->nclidx >= MAXCLIENTS)
            return; /* overflow: should never happen */

        if (entry->port == port) {
            for (i = 0;  i < entry->nclidx;  i++) {
                if (clidx == entry->clidxs[i])
                    return;     /* it's already queued */
            }
            
            /* append to the end */
            entry->clidxs[i] = clidx;
            entry->nclidx++;
            
            return;
        }
    }

    if ((entry = malloc(sizeof(PortHashRec))) == NULL)
        return;

    memset(entry, 0, sizeof(PortHashRec));
    entry->port = port;
    entry->nclidx = 1;
    entry->clidxs[0] = clidx; 

    prev->next = entry;
}

static int
GetQueuedClients(unsigned long port, ClientPtr *clbuf, int length)
{
    int hidx  = PORT_HASH_INDEX(port);
    PortHashPtr prev, entry;
    int clidx;
    int i, j, n;

    for (prev = (PortHashPtr)&PortHash[hidx];  prev->next; prev = prev->next) {
        entry = prev->next;

        if (port == entry->port) {
            prev->next = entry->next;

            n = (length > entry->nclidx) ? entry->nclidx : length;

            for (i = j = 0;   i < n;   i++) {
                clidx = entry->clidxs[i];

                if (clidx < 1 || clidx >= MAXCLIENTS)
                    continue;

                if ((clbuf[j] = clients[clidx]) != NullClient)
                    j++;
            }

            free(entry);

            return j;
        }
    }

    return 0;
}



static void
ResourceFreed(CallbackListPtr *list,
              pointer          closure,
              pointer          data)
{
    ResourceStateInfoRec *rinfo = (ResourceStateInfoRec *)data;
    DevPrivateKey         key;
    ScreenPtr             scrn;
    XvScreenPtr           xvsc;
    XvAdaptorPtr          adapt;
    XvPortPtr             port;
    XvGrabPtr             grab;
    ClientPtr             cls[MAXCLIENTS];
    int                   i, j, k, m, n;

    (void)list;
    (void)closure;

    if (rinfo->state == ResourceStateFreeing) {
        if (rinfo->type == XvRTGrab) {
            if ((grab = (XvGrabPtr)rinfo->value) != NULL &&
                (key  = XvGetScreenKey())        != NULL   )
            {
                for (i = 0;  i < screenInfo.numScreens;  i++) {
                    scrn = screenInfo.screens[i];
                    xvsc = (XvScreenPtr)dixLookupPrivate(&scrn->devPrivates,
                                                         key);
                    
                    if (xvsc == NULL)
                        continue;

                    for (j = 0;   j < xvsc->nAdaptors;   j++) {
                        adapt = xvsc->pAdaptors + j;

                        for (k = 0;   k < adapt->nPorts;   k++) {
                            port = adapt->pPorts + k;

                            if (grab == &port->grab) {
                                PolicyDebug("Xv port %lu ungrabbed", port->id);
                                m = GetQueuedClients(port->id, cls,MAXCLIENTS);

                                for (n = 0; n < m; n++)
                                    ClientUnblock(cls[n]);

                                return;
                            }
                        } /* for port */
                    } /* for adapt */
                } /* for scrn */

                PolicyError("Failed to find corresponding port "
                            "when grab resource freed");
            } 
        }
    }
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

static const char *
AccessModeName(AccessMode acmode)
{
    switch (acmode) {
    case AccessUnathorized:   return "Unathorized";
    case AccessAuthorized:    return "Authorized";
    case AccessDeferred:      return "Deferred";
    case AccessTolerated:     return "Tolerated";
    default:                  return "<unknown>";
    }
}




/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
