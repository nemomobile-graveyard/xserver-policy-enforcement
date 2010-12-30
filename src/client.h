#ifndef POLICY_CLIENT_H
#define POLICY_CLIENT_H

#include <sys/types.h>

#include <dix.h>



/* Policy client private. */
typedef struct {
    pid_t       pid;            /* pid of the client */
    const char *exe;            /* arg0 of the command line */
} ClientPolicyRec, *ClientPolicyPtr;

Bool ClientInit(void);
void ClientExit(void);
ClientPolicyPtr ClientGetPolicyRec(ClientPtr);


#endif	/* POLICY_CLIENT_H */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
