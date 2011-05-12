#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "authorize.h"
#include "winprop.h"
#include "xvideo.h"
#include "xrandr.h"

#include <misc.h>
#include <dixstruct.h>
#include <xace.h>
#include <xacestr.h>

#include <X11/extensions/Xv.h>
#include <X11/extensions/randr.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>


typedef struct {
    const char *name;
    PolicyExtensionHandler handler;
    void (*fixup)(int);
} ExtensionHandlerDef;

typedef struct {
    pid_t          pids[MAXCLIENTS];
    int            npid;
} ClientAuthorizationRec;

typedef struct {
    OsTimerPtr             timer;
    ClientAuthorizationRec tolerate;
    ClientAuthorizationRec defer;
} ClientTransitionRec;

static PolicyExtensionHandler  ExtensionHandlers[MAXEXTENSIONS];
static ClientAuthorizationRec  AuthorizedClients[MAXAUTHCLASSES];
static pid_t                   IdleClients[MAXAUTHCLASSES];
static ClientTransitionRec     Transition[MAXTRANSITCLASS];
static Bool                    authorize_idle;


static void SetupExtensionHandlers(CallbackListPtr *, pointer, pointer);
static void TeardownExtensionHandlers(void);
static void ScheduleEnforcement(AuthorizationClass, unsigned long,
                                ClientAuthorizationRec *, pid_t *, int);
static void CancelEnforcement(void);
static CARD32 ExecuteEnforcement(OsTimerPtr, CARD32, pointer);
static Bool SetupXace(void);
static void TeardownXace(void);
static void PropertyCallback(CallbackListPtr *, pointer, pointer);
static void ExtDispatchCallback(CallbackListPtr *, pointer, pointer);
static const char *AuthorizationClassName(AuthorizationClass);
static void PrintPidList(const char *, pid_t *, int);
static Bool ParseIdleXvattrAccess(char *);

static inline Bool PidIsOnTheList(ClientAuthorizationRec *list, pid_t pid)
{
    int i;

    for (i = 0;  i < list->npid;  i++) {
        if (pid == list->pids[i])
            return TRUE;
    }

    return FALSE;
}


static inline Bool ListIsIdle(ClientAuthorizationRec *list)
{
    return (list->npid == 1 && list->pids[0] == 0) || list->npid <= 0;
}


Bool
AuthorizeInit(void)
{
    if (!SetupXace())
        return FALSE;

    if (!AddCallback(&ClientStateCallback, SetupExtensionHandlers, NULL))
        return FALSE;
        
    return TRUE;
}

void
AuthorizeExit(void)
{
    CancelEnforcement();
    TeardownExtensionHandlers();
    TeardownXace();
}

Bool
AuthorizeParseOption(char *name, char *value)
{
    Bool  success = TRUE;

    if (!strcmp(name, AUTHORIZE_IDLE_XVATTR_ACCESS)) {
        success = ParseIdleXvattrAccess(value);
    }
    else {
        success = FALSE;
        PolicyError("unsupported policy authorization option: '%s'", name);
    }

    return success;
}


void
AuthorizeClients(AuthorizationClass class,
                 unsigned long      period,
                 pid_t             *pids,
                 int                npid)
{
    static pid_t zero_pid;

    ClientAuthorizationRec *authorized;
    Bool changed;
    size_t size;

    if (class < 0 || class >= MAXAUTHCLASSES)
        return;

    if (pids == NULL) {
        pids = &zero_pid;
        npid = 0;
    }

    if (npid > MAXCLIENTS)
        npid = MAXCLIENTS;

    authorized = AuthorizedClients + class;

    if (npid == 0) {
        changed = (authorized->npid != 0);
        if (changed) {
            ScheduleEnforcement(class, period, authorized, pids, npid);
            memset(authorized->pids, 0, sizeof(authorized->pids));
        }
    }
    else {
        size = sizeof(pid_t) * npid;
        changed = (npid != authorized->npid) ||
                  memcmp(pids, authorized->pids, size);
        if (changed) {
            ScheduleEnforcement(class, period, authorized, pids, npid);
            memcpy(authorized->pids, pids, size);
        }
    }

    authorized->npid = npid;

    if (changed) {
        PrintPidList("PIDs of authorized clients", authorized->pids, npid);
    }
}

AccessMode
AuthorizeGetAccessMode(AuthorizationClass class, pid_t pid)
{
    ClientTransitionRec *transition         =  Transition + class;
    Bool                 ManageTransitions  =  (class < MAXTRANSITCLASS);
    pid_t                idle;

    if (class < 0 || class >= MAXAUTHCLASSES)
        return AccessUnathorized;

    if (pid == 0)  /* Nobody */
        return AccessUnathorized;
    
    if (pid == 1)  /* Everybody */
        return AccessAuthorized;

    if (ManageTransitions && PidIsOnTheList(&transition->defer, pid))
            return AccessDeferred;
    
    if (PidIsOnTheList(&AuthorizedClients[class], pid))
        return AccessAuthorized;

    if (ManageTransitions && PidIsOnTheList(&transition->tolerate, pid))
        return AccessTolerated;

    if (ListIsIdle(&AuthorizedClients[class]) && authorize_idle) {
        idle = IdleClients[class];
        
        if (pid == idle)
            return AccessAuthorized;

        if (idle == 0) {
            PolicyDebug("allowing unauthorized client PID %u to access idle "
                        "class 0x%x", pid, class);
            IdleClients[class] = pid;
            return AccessAuthorized;
        }

        PolicyDebug("idle client PID %u denied (busy by PID %u)", pid, idle);
    }
    
    return AccessUnathorized;
}

void
AuthorizeClearClient(pid_t pid)
{
    int class;

    /*
     * if unauthorized clients are allowed to access idle resources,
     * we need to clear any such client idle records when it exits or
     * crashes
     */

    if (authorize_idle && pid != 0) {
        for (class = 0; class < MAXAUTHCLASSES; class++) {
            if (IdleClients[class] == pid) {
                IdleClients[class] = 0;
                PolicyDebug("idle client PID %u cleared from class 0x%x",
                            pid, class);
            }
        }
    }
}

static Bool
SetupXace(void)
{
    Bool success = TRUE;

    XaceRegisterCallback(XACE_PROPERTY_ACCESS, PropertyCallback, NULL);
    XaceRegisterCallback(XACE_EXT_DISPATCH, ExtDispatchCallback, NULL);

    return success;
}

static
void TeardownXace(void)
{
    XaceDeleteCallback(XACE_EXT_DISPATCH, ExtDispatchCallback, NULL);
    XaceDeleteCallback(XACE_PROPERTY_ACCESS, PropertyCallback, NULL);
}



static void
SetupExtensionHandlers(CallbackListPtr *list,
                       pointer          closure,
                       pointer          data)
{
    static ExtensionHandlerDef defs[] = {
        { XvName    , XvideoAuthorizeRequest, XvideoFixupProcVector},
        { RANDR_NAME, XrandrAuthorizeRequest, NULL                 }, 
        { NULL      , NULL                  , NULL                 }
    };

    ExtensionEntry       *ext;
    ExtensionHandlerDef  *def;
    Bool                 success;


    for (def = defs, success = TRUE;    def->name;    def++) {
        if ((ext = CheckExtension(def->name)) == NULL) {
            success = FALSE;
            PolicyError("Can't find %s extension", def->name);
            continue;
        }

        if (ext->index >= MAXEXTENSIONS) {
            success = FALSE;
            PolicyError("%s extension index %d exceeds the allowed max %d",
                        def->name, ext->index, MAXEXTENSIONS);
            continue;
        }

        ExtensionHandlers[ext->index] = def->handler;

        if (def->fixup)
            def->fixup(EXTENSION_BASE + ext->index);
    }

    if (success)
        PolicyInfo("Policy: found all mandatory extensions");
    else {
    }

    /* we do extension setup only once */
    DeleteCallback(&ClientStateCallback, SetupExtensionHandlers, NULL);
}

static void
TeardownExtensionHandlers(void)
{
    memset(ExtensionHandlers, 0, sizeof(ExtensionHandlers));
}

static void
ScheduleEnforcement(AuthorizationClass      class,
                    unsigned long           period,
                    ClientAuthorizationRec *OldClients,
                    pid_t                  *NewClientPids,
                    int                     NewClientNpid)
{
    ClientTransitionRec *transition = Transition + class;
    pid_t pid, idle;
    int i, j, k;

    if (class < 0)
        return;

    if (class >= MAXTRANSITCLASS) {
        if (class < MAXAUTHCLASSES) {
            PolicyDebug("%s authorization change",
                        AuthorizationClassName(class));
        }
        return;
    }

    memset(&transition->tolerate, 0, sizeof(transition->tolerate));
    if (!period)
        transition->tolerate.npid = 0;
    else {
        /*
         * during the transition period every old client, that is not
         * among the new ones will be tolerated, ie. given the possibility
         * to gently fade away; any client that was let in unauthorized
         * while the resource was idle will not be given a toleration
         * period
         */
        for (i = k = 0;  i < OldClients->npid;  i++) {
            pid = transition->tolerate.pids[k++] = OldClients->pids[i];

            for (j = 0;  j < NewClientNpid;  j++) {
                if (pid == NewClientPids[j]) {
                    k--;
                    break;
                }
            }
        }
        transition->tolerate.npid = k;
    }

    memset(&transition->defer, 0, sizeof(transition->defer));
    if (!period)
        transition->defer.npid = 0;
    else {
        /*
         * during the transition period every new client, that was not
         * on the old list, will be deferred, ie. if needed delayed until
         * no resource conflict remains; any client that was let in
         * unauthorized while the reource was idle but became later
         * authorized does not need to be deferred but its idle record
         * needs to be cleared
         */
        idle = IdleClients[class];
        for (i = k = 0;   i < NewClientNpid;   i++) {
            pid = transition->defer.pids[k++] = NewClientPids[i];
            
            if (pid == idle) {
                k--;
                IdleClients[class] = 0;
                PolicyDebug("PID %u changed from idle to authorized", idle);
            }
            else {
                for (j = 0;  j < OldClients->npid;  j++) {
                    if (pid == OldClients->pids[j]) {
                        k--;
                        break;
                    }
                }
            }
        }
        transition->defer.npid = k;
    }

    if (NewClientNpid > 0) {
        /*
         * if we have authorized clients we need to get rid of any
         * unauthorized clients that were let it while the resource was
         * idle
         */
        IdleClients[class] = 0;
    }

    if (period) {
        PolicyDebug("%s transition period starts (length %lumsec)",
                    AuthorizationClassName(class), period);
    }

    if ((i = transition->tolerate.npid) > 0)
        PrintPidList("PIDs of tolerated clients", transition->tolerate.pids,i);

    if ((i = transition->defer.npid) > 0)
        PrintPidList("PIDs of deferred clients", transition->defer.pids,i);

    if (IdleClients[class] != 0)
        PolicyDebug("PID of authorized idle client: %u", IdleClients[class]);

    if (period) {
        transition->timer = TimerSet(transition->timer, 0, period,
                                     ExecuteEnforcement, (pointer)class);
    }
}

static void
CancelEnforcement(void)
{
    ClientTransitionRec *transition;
    int i;


    for (i = 0, transition = Transition;   i < MAXTRANSITCLASS;   i++) {

        memset(&transition->tolerate.pids, 0,
               sizeof(transition->tolerate.pids));

        transition->tolerate.npid = 0;

        TimerCancel(transition->timer);
    }
}

static CARD32
ExecuteEnforcement(OsTimerPtr timer,
                   CARD32     time,
                   pointer    data)
{
    AuthorizationClass      class      = (AuthorizationClass)data;
    ClientAuthorizationRec *authorized = AuthorizedClients + class;
    ClientTransitionRec    *transition = Transition + class;

    (void)timer;
    (void)time;

    memset(&transition->defer.pids, 0, sizeof(transition->defer.pids));
    transition->defer.npid = 0;

    memset(&transition->tolerate.pids, 0, sizeof(transition->tolerate.pids));
    transition->tolerate.npid = 0;

    PolicyDebug("%s transition period ends", AuthorizationClassName(class));
    PrintPidList("PIDs of tolerated clients", transition->tolerate.pids, 0);
    PrintPidList("PIDs of deferred clients", transition->defer.pids, 0);

    XvideoKillUnathorizedClients(XvVideoMask,
                                 authorized->pids,
                                 authorized->npid,
                                 IdleClients[class]);

    return 0; /* no new timing */
}

static void
PropertyCallback(CallbackListPtr *list,
                 pointer          closure,
                 pointer          data)
{
    XacePropertyAccessRec *proprec = (XacePropertyAccessRec *)data;

    (void)list;
    (void)closure;

    proprec->status = WinpropAuthorizeRequest(proprec->client,
                                              proprec->pWin,
                                              *(proprec->ppProp),
                                              proprec->access_mode);
}

static void
ExtDispatchCallback(CallbackListPtr *list,
                    pointer          closure,
                    pointer          data)
{
    XaceExtAccessRec       *extrec = (XaceExtAccessRec *)data;
    ClientPtr               client = extrec->client;
    ExtensionEntry         *ext    = extrec->ext;
    PolicyExtensionHandler  exthlr;
    int                     index;

    (void)list;
    (void)closure;

    if ((index = ext->index) < MAXEXTENSIONS &&
        (exthlr = ExtensionHandlers[index]) != NULL)
    {
        extrec->status = exthlr(client, ext); /* xxxAuthorizeRequest() */
    }
}

static const char *
AuthorizationClassName(AuthorizationClass class)
{
    switch (class) {
    case AuthorizeXvideo:    return "Xvideo";
    case AuthorizeXrandr:    return "Xrandr";
    default:                 return "<unknown>";
    }
}

static void
PrintPidList(const char *text, pid_t *pids, int npid)
{
#define PRINT_TO_BUF(f, a...)    if (p < e)  p += snprintf(p, e-p, f , ##a)

    char buf[4096];
    char *p, *e;
    int i;

    e = (p = buf) + sizeof(buf);

    if (!pids || !npid) {
        PRINT_TO_BUF("<none>");
    }
    else {
        for (i = 0;  i < npid;  i++) {
            PRINT_TO_BUF("%s%u", (i ? ", " : ""), pids[i]);
        }
    }

    PolicyDebug("%s %s", text, buf);

#undef PRINT_TO_BUF
}


static Bool
ParseIdleXvattrAccess(char *str)
{
    if (!str || !str[0]) {
        PolicyError("option '%s' requires a boolean value",
                    AUTHORIZE_IDLE_XVATTR_ACCESS);
        return FALSE;
    }

    if (!strcasecmp(str, "true"))
        authorize_idle = TRUE;
    else if (!strcasecmp(str, "false"))
        authorize_idle = FALSE;
    else {
        PolicyError("option '%s' has invalid value '%s', boolean expected",
                    AUTHORIZE_IDLE_XVATTR_ACCESS, str);
        return FALSE;
    }

    PolicyInfo("access to idle Xv port: %s",
               authorize_idle ? "allowed" : "blocked");

    return TRUE;
}

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
