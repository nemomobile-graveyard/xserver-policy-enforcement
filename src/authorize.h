#ifndef POLICY_AUTHORIZE_H
#define POLICY_AUTHORIZE_H

typedef enum {
    /* classes that need transition management + access control*/
    AuthorizeXvideo = 0,

    MAXTRANSITCLASS,

    /* classes for access control only */
    AuthorizeXrandr = MAXTRANSITCLASS,

    /* must be the last */
    MAXAUTHCLASSES
} AuthorizationClass;

typedef enum {
    AccessUnathorized = 0,
    AccessAuthorized,
    AccessDeferred,
    AccessTolerated
} AccessMode;

Bool AuthorizeInit(void);
void AuthorizeExit(void);
void AuthorizeClients(AuthorizationClass, pid_t *, int);
AccessMode AuthorizeGetAccessMode(AuthorizationClass, pid_t);


#endif	/* POLICY_AUTHORIZE_H */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
