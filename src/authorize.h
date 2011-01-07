#ifndef POLICY_AUTHORIZE_H
#define POLICY_AUTHORIZE_H

#include "policy.h"

Bool AuthorizeInit(void);
void AuthorizeExit(void);
void AuthorizeClients(AuthorizationClass, unsigned long, pid_t *, int);
AccessMode AuthorizeGetAccessMode(AuthorizationClass, pid_t);


#endif	/* POLICY_AUTHORIZE_H */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
