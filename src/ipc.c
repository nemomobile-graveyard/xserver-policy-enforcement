#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "policy.h"
#include "ipc.h"
#include "videoipc.h"
#include "authorize.h"

#include <dixstruct.h>
#include <dixaccess.h>
#include <windowstr.h>
#include <xace.h>
#include <xacestr.h>

#include <X11/X.h>
#include <X11/Xatom.h>
#include <X11/Xproto.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>



typedef struct {
    int8_t     idx;
    uint64_t   period;
} UserRec;

static size_t       length;
static videoipc_t  *ipc     = NOIPC;
static int          fd      = -1;

static ATOM         MessageTypeAtom;         /* VIDEOIPC_CLIENT_MESSAGE */
static UserRec      XVlocal = {-1, 5000000}; /* 5sec transition period */

static Bool InitiateSharedMemory(int, size_t);
static void SendCallback(CallbackListPtr *, pointer, pointer);
static void GetCurrentTime(uint64_t *);
static const char *PrintSectionMask(uint32_t, char *, int);


Bool
IpcInit(void)
{
    static const char *msgtyp = VIDEOIPC_CLIENT_MESSAGE;
    static int         flags = O_RDWR | O_CREAT;
    static mode_t      mode  = S_IRUSR|S_IWUSR | S_IRGRP | S_IROTH; /* 644 */

    size_t      page;
    struct stat st;

    do { /* not a loop */
        if ((MessageTypeAtom = MakeAtom(msgtyp,strlen(msgtyp), TRUE)) == None){
            PolicyError("failed to make atom '%s'", msgtyp);
            break;
        }

        page   = sysconf(_SC_PAGESIZE);
        length = ((sizeof(videoipc_t) + page - 1) / page) * page;

        if ((fd = shm_open(VIDEOIPC_SHARED_OBJECT, flags, mode)) < 0) {
            PolicyError("failed to create shared memory object '%s': %s",
                        VIDEOIPC_SHARED_OBJECT, strerror(errno));
            break;
        }

        if (fstat(fd, &st) < 0) {
            PolicyError("failed to stat shared memory object '%s': %s",
                        VIDEOIPC_SHARED_OBJECT, strerror(errno));
            break;
        }

        if (st.st_size < length) {
            if (!InitiateSharedMemory(fd, length))
                break;
        }
                        
        if ((ipc = mmap(NULL, length, PROT_READ,MAP_SHARED, fd, 0)) == NOIPC) {
            PolicyError("failed to map shared memory of '%s': %s",
                        VIDEOIPC_SHARED_OBJECT, strerror(errno));
            break;
        }

        if (ipc->version.major != VIDEOIPC_MAJOR_VERSION) {
            PolicyError("shared memory '%s' version mismatch. Shared "
                        "memory version %d.%d  plugin version %d.%d",
                        VIDEOIPC_SHARED_OBJECT,
                        (int)ipc->version.major, (int)ipc->version.minor,
                        VIDEOIPC_MAJOR_VERSION , VIDEOIPC_MINOR_VERSION);
            break;
        }
        else {
            if (ipc->version.minor == VIDEOIPC_MINOR_VERSION) {
                PolicyDebug("shared memory '%s' is OK (version %d.%d)",
                            VIDEOIPC_SHARED_OBJECT,
                            (int)ipc->version.major, (int)ipc->version.minor);
            }
            else {
                PolicyWarning("shared memory '%s' version mismatch. Shared "
                              "memory version %d.%d <> plugin version %d.%d",
                              VIDEOIPC_SHARED_OBJECT,
                              (int)ipc->version.major, (int)ipc->version.minor,
                              VIDEOIPC_MAJOR_VERSION , VIDEOIPC_MINOR_VERSION);
            }
        }

        XaceRegisterCallback(XACE_SEND_ACCESS, SendCallback, NULL);

        /* everything was OK */
        return TRUE;

    } while (0);

    /*
     * something went wrong
     */
    IpcExit();
        
    return FALSE;
}

void
IpcExit(void)
{
    XaceDeleteCallback(XACE_SEND_ACCESS, SendCallback, NULL);

    if (ipc != NOIPC && length > 0)
        munmap((void *)ipc, length);

    if (fd >= 0)
        shm_unlink(VIDEOIPC_SHARED_OBJECT);
}

void
IpcUpdate(unsigned long mask)
{
    uint8_t         idx;
    videoipc_set_t *set;
    uint64_t        now = 0ULL;        /* in usec's */
    uint64_t        time;              /* in usec's */
    unsigned long   tleft;             /* in msec's; max value is ~48days */

    if (ipc == NOIPC)
        return;

    if ((mask & AUTHORIZE_XVIDEO) != 0) {
        if ((idx = ipc->XVusers.idx) != XVlocal.idx) {
            XVlocal.idx = idx;

            GetCurrentTime(&now);

            if ((time = ipc->XVusers.set[idx].time + XVlocal.period) > now)
                tleft = (time - now) / 1000;
            else
                tleft = 0;

            set = (videoipc_set_t *)&ipc->XVusers.set[idx];

            AuthorizeClients(AuthorizeXvideo, tleft, set->pids, set->npid);
        }
    }
}


static Bool
InitiateSharedMemory(int fd, size_t size)
{
    char        buf[4096];
    size_t      junk;
    int         written;
    videoipc_t *vip;

    PolicyInfo("Policy: initiate shared memory object '%s'",
               VIDEOIPC_SHARED_OBJECT);

    memset(buf, 0, sizeof(buf));
    vip = (videoipc_t *)buf;

    vip->version.major = VIDEOIPC_MAJOR_VERSION;
    vip->version.minor = VIDEOIPC_MINOR_VERSION;

    while (size > 0) {
        junk  = (size > sizeof(buf)) ? sizeof(buf) : size;
        size -= junk;

        do {
            if ((written = write(fd, buf, junk)) <= 0) {
                if (errno == EINTR)
                    continue;

                PolicyError("error during shared memory initialization: %s",
                            strerror(errno));

                return FALSE;
            }

            junk -= written;

        } while (junk > 0);

        vip->version.major = 0;
        vip->version.minor = 0;
    }

    return TRUE;
}

static void
SendCallback(CallbackListPtr *list,
             pointer          closure,
             pointer          data)
{
    XaceSendAccessRec *sendrec = (XaceSendAccessRec *)data;
    xEventPtr          ev;
    int                i;
    uint32_t           mask;
    char               buf[512];

    (void)list;
    (void)closure;

    if (sendrec->dev != NULL || sendrec->pWin->parent != NULL)
        return;

    for (i = 0;   i < sendrec->count;   i++) {
        ev = sendrec->events + i;

        /* for the mysterious 0x80 see dix/event.c line 5088 */
        if (ev->u.u.type != (0x80 | ClientMessage))
            continue;

        if (ev->u.clientMessage.u.l.type != MessageTypeAtom)
            continue;

        if ((mask = (uint32_t)ev->u.clientMessage.u.l.longs0) == 0)
            continue;

        PolicyDebug("received update request %s",
                    PrintSectionMask(mask, buf, sizeof(buf)));

        IpcUpdate(mask);
    }
}

static void
GetCurrentTime(uint64_t *t)
{
    struct timeval tv;

    if (*t != 0ULL)
        return;

    if (gettimeofday(&tv, NULL) < 0)
        *t = 0ULL;
    else
        *t = ((uint64_t)tv.tv_sec) * 1000000ULL  + (uint64_t)tv.tv_usec;
}

static const char *
PrintSectionMask(uint32_t mask, char *buf, int len)
{
#define PRINT(f, a...) do {if (e > p) p += snprintf(p, e-p, f , ##a);} while(0)

    static char *names[MAXAUTHCLASSES] = {
        [AuthorizeXvideo] = "Xvideo",
        [AuthorizeXrandr] = "Xrandr",
    };

    char *p, *q, *e;
    int   i;

    e = (p = buf) + len;

    PRINT("(0x%x ", mask);

    if (!mask)
        PRINT("<none>");
    else {
        for (i = 0, q = p;   (i < MAXAUTHCLASSES) && mask;   i++, mask >>= 1) {
            PRINT("%s%s", (p>q ? ", ":""), (names[i] ? names[i]:"<unknown>"));
        }
    }

    PRINT(")");

    return buf;

#undef PRINT
}

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
