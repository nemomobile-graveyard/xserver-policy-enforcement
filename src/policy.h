#ifndef POLICY_H
#define POLICY_H

#include <sys/types.h>

#include <xorg-server.h>
#include <extnsionst.h>
#include <dix.h>
#include <os.h>


#define PolicyTrace(f, a...)  LogMessageVerb(X_DEFAULT,3,"Policy: "f"\n" , ##a)
#define PolicyDebug(f, a...)  LogMessageVerb(X_DEFAULT,2,"Policy: "f"\n" , ##a)
#define PolicyInfo(f, a...)   LogMessageVerb(X_INFO,1,f"\n" , ##a)
#define PolicyWarning(f,a...) LogMessageVerb(X_WARNING,-1,"Policy: "f"\n", ##a)
#define PolicyError(f, a...)  LogMessageVerb(X_ERROR,-1,"Policy: "f"\n"  , ##a)


typedef enum {
    /* classes that need transition management + access control*/
    AuthorizeXvideo = 0,

    MAXTRANSITCLASS,

    /* classes for access control only */
    AuthorizeXrandr = MAXTRANSITCLASS,

    /* must be the last */
    MAXAUTHCLASSES
} AuthorizationClass;

#define AUTHORIZE_XVIDEO (1 << AuthorizeXvideo)
#define AUTHORIZE_XRANDR (1 << AuthorizeXrandr)

typedef enum {
    AccessUnathorized = 0,
    AccessAuthorized,
    AccessDeferred,
    AccessTolerated
} AccessMode;

typedef Bool (*PolicyParserFunc)(char *, char *);
typedef int  (*PolicyExtensionHandler)(ClientPtr, ExtensionEntry *);


#endif	/* POLICY_H */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
