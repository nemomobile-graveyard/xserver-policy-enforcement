#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "client.h"
#include "authorize.h"

#include <misc.h>
#include <privates.h>
#include <callback.h>
#include <dixstruct.h>

#include <X11/Xproto.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#define ClientPrivateKey    (&ClientPrivateKeyRec)

static DevPrivateKeyRec     ClientPrivateKeyRec;


static void ClientCallback(CallbackListPtr *, pointer, pointer);
static void ClientPolicyRecInit(ClientPtr, ClientPolicyPtr);
static void ClientPolicyRecReset(ClientPtr, ClientPolicyPtr);
static const char *ClientStateName(ClientState);


Bool
ClientInit(void)
{
    unsigned rec_size = sizeof(ClientPolicyRec);

    if (dixRegisterPrivateKey(ClientPrivateKey, PRIVATE_CLIENT, rec_size) &&
        AddCallback(&ClientStateCallback, ClientCallback, NULL))
    {
        return TRUE;
    }

    return FALSE;
}

void
ClientExit(void)
{
    DeleteCallback(&ClientStateCallback, ClientCallback, NULL);
}

ClientPolicyPtr
ClientGetPolicyRec(ClientPtr client)
{
    ClientPolicyPtr rec;

    if (!client)
        rec = NULL;
    else {
        rec = (ClientPolicyPtr)dixLookupPrivate(&client->devPrivates,
                                                ClientPrivateKey);
    }

    return rec;
}

AccessMode
ClientAccessMode(ClientPtr client, AuthorizationClass class)
{
    ClientPolicyPtr  policy = ClientGetPolicyRec(client);
    AccessMode       acmode = AccessUnathorized;

    if (policy != NULL)
        acmode = AuthorizeGetAccessMode(class, policy->pid);

    return acmode;
}

void
ClientBlock(ClientPtr client, Bool replay)
{
    xReq            *reqbuf = (xReq *)client->requestBuffer;
    ClientPolicyPtr  policy = ClientGetPolicyRec(client);
    pointer          copy;
    int              size;

    if (policy && !policy->blocked) {
        if (!replay || !reqbuf) {
            size = 0;
            copy = NULL;
        }
        else {
            size = reqbuf->length * 4;

            if ((copy = malloc(size)) != NULL)
                memcpy(copy, reqbuf, size);
            else {
                PolicyError("Failed to allocate %u byte memory for "
                            "blocking request", size);
                return;
            }
        }

        free(policy->reqbuf);

        PolicyDebug("client %p (pid %u exe '%s') is blocked",
                    client, policy->pid, policy->exe);

        policy->blocked = TRUE;
        policy->reqbuf  = copy;
        policy->reqsize = size;

        IgnoreClient(client);
    }
}

void
ClientUnblock(ClientPtr client)
{
    ClientPolicyPtr  policy = ClientGetPolicyRec(client);

    if (policy && policy->blocked) {
        PolicyDebug("client %p (pid %u exe '%s') is unblocked",
                    client, policy->pid, policy->exe);

        policy->blocked = FALSE;

        AttendClient(client);

        if (policy->reqbuf && policy->reqsize > 0) {
            client->sequence--;
            InsertFakeRequest(client, policy->reqbuf, policy->reqsize);
        }
    }
}


static void
ClientCallback(CallbackListPtr *list,
               pointer          closure,
               pointer          data)
{
    NewClientInfoRec *clientinfo = (NewClientInfoRec *)data;
    ClientPtr         client = clientinfo->client;
    ClientPolicyPtr   policy = ClientGetPolicyRec(client);

    (void)list;
    (void)closure;

    if (policy != NULL) {
    
        switch (client->clientState) {

        case ClientStateInitial:
            ClientPolicyRecInit(client, policy);
            PolicyDebug("client %p, (pid %u exe '%s') created",
                        client, policy->pid, policy->exe);
            break;
            
        case ClientStateGone:
            PolicyDebug("client %p (pid %u exe '%s') destroyed",
                        client, policy->pid, policy->exe);
            AuthorizeClearClient(policy->pid);
            ClientPolicyRecReset(client, policy);
            break;

        default:
            PolicyDebug("client %p (pid %u exe '%s') %s",
                        client, policy->pid, policy->exe,
                        ClientStateName(client->clientState));
            break;
        }
    }
}

static void
ClientPolicyRecInit(ClientPtr client, ClientPolicyPtr policy)
{
    LocalClientCredRec  *lcc;
    int                  fd;
    int                  len;
    char                 path[256];
    char                 buf[1024];
    char                *p;

    if (GetLocalClientCreds(client, &lcc) < 0)
        policy->pid = -1;
    else {
        policy->pid = (lcc->fieldsSet & LCC_PID_SET) ? lcc->pid : 0;
        FreeLocalClientCreds(lcc);
    }

    if (policy->pid < 0)
        policy->exe = strdup("<unknown>");
    else {
        snprintf(path, sizeof(path), "/proc/%u/cmdline", policy->pid);

        if ((fd  = open(path, O_RDONLY)) < 0) {
            policy->pid = -1;
            policy->exe = strdup("<unknown>");
        }
        else {
            for (;;) {
                if ((len = read(fd, buf, sizeof(buf)-1)) <= 0) {
                    if (errno == EINTR)
                        continue;

                    policy->pid = -1;
                    policy->exe = strdup("<unknown>");

                    break;
                }

                buf[len] = '\0';

                for (p = buf;  *p;  p++) {
                    if (*p == ' ' || *p == '\n') {
                        *p = '\0';
                        break;
                    }
                }
                
                policy->exe = strdup(buf);

                break;
            }

            close(fd);
        }
    }
}

static void
ClientPolicyRecReset(ClientPtr client, ClientPolicyPtr policy)
{
    free((void *)policy->exe);
    free(policy->reqbuf);
    memset(policy, 0, sizeof(ClientPolicyRec));
}

static const char *
ClientStateName(ClientState state)
{
    switch (state) {
    case ClientStateInitial:            return "initial";
    case ClientStateAuthenticating:     return "authenticating";
    case ClientStateRunning:            return "running";
    case ClientStateRetained:           return "retained";
    case ClientStateGone:               return "gone";
    case ClientStateCheckingSecurity:   return "checking security";
    case ClientStateCheckedSecurity:    return "checked security";
    }

    return "<unknown>";
}



/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
