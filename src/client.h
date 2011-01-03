#ifndef POLICY_CLIENT_H
#define POLICY_CLIENT_H

#include <sys/types.h>

#include <dix.h>

#include "policy.h"

/* Policy client private. */
typedef struct {
    pid_t       pid;            /* pid of the client */
    const char *exe;            /* arg0 of the command line */
    Bool        blocked;
    pointer     reqbuf;
    int         reqsize;
} ClientPolicyRec, *ClientPolicyPtr;

Bool ClientInit(void);
void ClientExit(void);
ClientPolicyPtr ClientGetPolicyRec(ClientPtr);
AccessMode ClientAccessMode(ClientPtr, AuthorizationClass);
void ClientBlock(ClientPtr, Bool);
void ClientUnblock(ClientPtr);



#endif	/* POLICY_CLIENT_H */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
