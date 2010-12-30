#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "policy.h"
#include "authorize.h"
#include "xvideo.h"
#include "xrandr.h"

#include <misc.h>
#include <dixstruct.h>
#include <extnsionst.h>
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
} ExtensionHandlerDef;

typedef struct {
    pid_t          pids[MAXCLIENTS];
    int            npid;
} ClientAuthorizationRec;

typedef struct {
    CARD32                 period;
    OsTimerPtr             timer;
    ClientAuthorizationRec clients;
} ClientToleranceRec;

static PolicyExtensionHandler  ExtensionHandlers[MAXEXTENSIONS];
static ClientAuthorizationRec  AuthorizedClients[MAXAUTHCLASSES];
static ClientToleranceRec      Tolerate;

static void SetupExtensionHandlers(CallbackListPtr *, pointer, pointer);
static void TeardownExtensionHandlers(void);
static void ScheduleVideoEnforcement(ClientAuthorizationRec *, pid_t *, int);
static void CancelVideoEnforcement(void);
static CARD32 ExecVideoEnforcement(OsTimerPtr, CARD32, pointer);
static Bool SetupXace(void);
static void TeardownXace(void);
static void PropertyCallback(CallbackListPtr *, pointer, pointer);
static void ExtDispatchCallback(CallbackListPtr *, pointer, pointer);
static void PrintPidList(const char *, pid_t *, int);


Bool
AuthorizeInit(void)
{
    if (SetupXace() &&
        AddCallback(&ClientStateCallback, SetupExtensionHandlers, NULL))
    {
        Tolerate.period = 5000; /* ms */
        return TRUE;
    }
        
    return FALSE;
}

void
AuthorizeExit(void)
{
    CancelVideoEnforcement();
    TeardownExtensionHandlers();
    TeardownXace();
}

void
AuthorizeClients(AuthorizationClass class, pid_t *pids, int npid)
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
            ScheduleVideoEnforcement(authorized, pids, npid);
            memset(authorized->pids, 0, sizeof(authorized->pids));
        }
    }
    else {
        size = sizeof(pid_t) * npid;
        changed = (npid != authorized->npid) ||
                  memcmp(pids, authorized->pids, size);
        if (changed) {
            ScheduleVideoEnforcement(authorized, pids, npid);
            memcpy(authorized->pids, pids, size);
        }
    }

    authorized->npid = npid;

    if (changed) {
        PrintPidList("PIDs of authorized clients", authorized->pids, npid);
    }
}

static Bool
SetupXace(void)
{
    Bool success = TRUE;

    /*
    XaceRegisterCallback(XACE_RESOURCE_ACCESS, PropertyCallback, NULL);
    */
    XaceRegisterCallback(XACE_EXT_DISPATCH, ExtDispatchCallback, NULL);

    return success;
}

static
void TeardownXace(void)
{
    XaceDeleteCallback(XACE_EXT_DISPATCH, ExtDispatchCallback, NULL);
    /*
    XaceDeleteCallback(XACE_RESOURCE_ACCESS, PropertyCallback, NULL);
    */
}



static void
SetupExtensionHandlers(CallbackListPtr *list,
                       pointer          closure,
                       pointer          data)
{
    static ExtensionHandlerDef defs[] = {
        { XvName    , XvideoAuthorizeRequest},
        { RANDR_NAME, XrandrAuthorizeRequest}, 
        { NULL      , NULL}
    };

    ExtensionEntry      *ext;
    ExtensionHandlerDef *def;
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
ScheduleVideoEnforcement(ClientAuthorizationRec *OldClients,
                         pid_t                  *NewClientPids,
                         int                     NewClientNpid)
{
    pid_t pid;
    int i, j, k;

    if (Tolerate.period == 0)
        return;

    memset(&Tolerate.clients, 0, sizeof(Tolerate.clients));
    for (i = k = 0;  i < OldClients->npid;  i++) {
        pid = Tolerate.clients.pids[k++] = OldClients->pids[i];

        for (j = 0;  j < NewClientNpid;  j++) {
            if (pid == NewClientPids[j]) {
                k--;
                break;
            }
        }
    }
    Tolerate.clients.npid = k;

    PolicyDebug("Transition period starts");
    PrintPidList("PIDs of tolerated clients", Tolerate.clients.pids, k);

    Tolerate.timer = TimerSet(Tolerate.timer, 0, Tolerate.period,
                              ExecVideoEnforcement, NULL);
}

static void
CancelVideoEnforcement(void)
{
    memset(&Tolerate.clients.pids, 0, sizeof(Tolerate.clients.pids));
    Tolerate.clients.npid = 0;

    TimerCancel(Tolerate.timer);
}

static CARD32
ExecVideoEnforcement(OsTimerPtr timer,
                     CARD32     time,
                     pointer    data)
{
    ClientAuthorizationRec *authorized = AuthorizedClients + AuthorizeXvideo;

    (void)timer;
    (void)time;
    (void)data;

    memset(&Tolerate.clients.pids, 0, sizeof(Tolerate.clients.pids));
    Tolerate.clients.npid = 0;

    PolicyDebug("Transition period ends");
    PrintPidList("PIDs of tolerated clients", Tolerate.clients.pids,0);

    XvideoKillUnathorizedClients(XvVideoMask,
                                 authorized->pids,
                                 authorized->npid);

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

    PolicyDebug("property callback");
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


/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
