#ifndef POLICY_AUTHORIZE_H
#define POLICY_AUTHORIZE_H

#include "policy.h"

#define AUTHORIZE_IDLE_XVATTR_ACCESS "allow-idle-xvattr-access"

Bool AuthorizeInit(void);
void AuthorizeExit(void);
Bool AuthorizeParseOption(char *, char *);
void AuthorizeClients(AuthorizationClass, unsigned long, pid_t *, int);
AccessMode AuthorizeGetAccessMode(AuthorizationClass, pid_t);
void AuthorizeClearClient(pid_t);


#endif	/* POLICY_AUTHORIZE_H */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
