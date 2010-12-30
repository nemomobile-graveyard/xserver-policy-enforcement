#ifndef POLICY_AUTHORIZE_H
#define POLICY_AUTHORIZE_H

typedef enum {
    AuthorizeXvideo = 0,
    AuthorizeXrandr,
    /* must be the last */
    MAXAUTHCLASSES
} AuthorizationClass;

Bool AuthorizeInit(void);
void AuthorizeExit(void);
void AuthorizeClients(AuthorizationClass, pid_t *, int);


#endif	/* POLICY_AUTHORIZE_H */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
