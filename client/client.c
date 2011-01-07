#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <X11/Xlib.h>
#include <X11/Xatom.h>

#include <videoipc.h>

#define TRUE     1
#define FALSE    0

#define DIM(a)   (sizeof(a) / sizeof(a[0]))

#define print_error(f, a...)  fprintf(stderr,"%s [error]: "f"\n",prognam , ##a)
#define print_info(f, a...)   fprintf(stderr,"%s: "f"\n",prognam , ##a)
#define print_warning(f,a...) fprintf(stderr,"%s [warn]: "f"\n",prognam , ##a)

static char       *prognam;     /* ie. basename of argv[0] */
static int         fd;          /* file descriptor for shared memory */
static int         length;      /* length of the shared memory */
static videoipc_t *ipc;         /* shared memory data */
static Display    *disp;        /* X server connection */
static Window      rwin;        /* root window */
static Atom        msgtyp;      /* client message type */

static int  init_shmem(void);
static void exit_shmem(void);
static int  init_shfile(int, size_t);
static int  init_xlib(char *);
static int  send_notification(long);
static int  error_handler(Display *, XErrorEvent *);
#if 0
static const char *strstatus(Status);
#endif
static uint64_t current_time(void);
static int  parse_args(int, char **, uint32_t *, pid_t *, int *);
static void usage(int);


int main(int argc, char **argv)
{
    uint32_t        mask;
    int             npid;
    pid_t           pids[16];
    int             idx;
    size_t          count;
    videoipc_set_t *set;

    prognam = basename(argv[0]);
    npid    = DIM(pids);

    if (!parse_args(argc,argv, &mask, pids,&npid) ||
        !init_shmem()                             ||
        !init_xlib(":0")                            )
    {
        return errno;
    }


    if ((mask & VIDEOIPC_XVIDEO_SECTION) == VIDEOIPC_XVIDEO_SECTION) {

        if ((idx = ipc->XVusers.idx + 1) >= DIM(ipc->XVusers.set))
            idx = 0;
            
        set = (videoipc_set_t *)&ipc->XVusers.set[idx];

        set->time = current_time();
        set->npid = npid;

        if ((count = npid * sizeof(pid_t)) > 0)
            memcpy(set->pids, pids, count);
        else
            memset(set->pids, 0, count);

        ipc->XVusers.idx = idx;
    }

    send_notification(mask);

    XSync(disp, False);

    return 0;
}


static int init_shmem(void)
{
    static int    flags = O_RDWR | O_CREAT;
    static mode_t mode  = S_IRUSR|S_IWUSR | S_IRGRP | S_IROTH; /* 644 */

    size_t        page;
    struct stat   st;
    
    do { /* not a loop */
        page   = sysconf(_SC_PAGESIZE);
        length = ((sizeof(videoipc_t) + page - 1) / page) * page;
        
        if ((fd = shm_open(VIDEOIPC_SHARED_OBJECT, flags, mode)) < 0) {
            print_error("failed to create shared memory object '%s': %s",
                        VIDEOIPC_SHARED_OBJECT, strerror(errno));
            break;
        }
        
        if (fstat(fd, &st) < 0) {
            print_error("failed to stat shared memory object '%s': %s",
                        VIDEOIPC_SHARED_OBJECT, strerror(errno));
            break;
        }
        
        if (st.st_size < length) {
            if (!init_shfile(fd, length))
                break;
        }
        
        if ((ipc = mmap(NULL,length, PROT_WRITE,MAP_SHARED, fd, 0)) == NOIPC) {
            print_error("failed to map shared memory of '%s': %s",
                        VIDEOIPC_SHARED_OBJECT, strerror(errno));
            break;
        }
        
        if (ipc->version.major != VIDEOIPC_MAJOR_VERSION) {
            print_error("shared memory '%s' version mismatch. Shared "
                        "memory version %d.%d  plugin version %d.%d",
                        VIDEOIPC_SHARED_OBJECT,
                        (int)ipc->version.major, (int)ipc->version.minor,
                        VIDEOIPC_MAJOR_VERSION , VIDEOIPC_MINOR_VERSION);
            errno = EINVAL;
            break;
        }
        else {
            if (ipc->version.minor == VIDEOIPC_MINOR_VERSION) {
                print_info("shared memory '%s' is OK (version %d.%d)",
			   VIDEOIPC_SHARED_OBJECT,
			   (int)ipc->version.major, (int)ipc->version.minor);
            }
            else {
                print_warning("shared memory '%s' version mismatch. Shared "
                              "memory version %d.%d <> plugin version %d.%d",
                              VIDEOIPC_SHARED_OBJECT,
                              (int)ipc->version.major, (int)ipc->version.minor,
                              VIDEOIPC_MAJOR_VERSION , VIDEOIPC_MINOR_VERSION);
            }
        }
        
        /* everything was OK */
        return TRUE;
        
    } while (0);
    
    /*
     * something went wrong
     */
    exit_shmem();
    
    return FALSE;
}

static void exit_shmem(void)
{
    if (ipc != NOIPC && length > 0)
        munmap((void *)ipc, length);
    
    if (fd >= 0)
        shm_unlink(VIDEOIPC_SHARED_OBJECT);
}

static int init_shfile(int fd, size_t size)
{
    char        buf[4096];
    size_t      junk;
    int         written;
    videoipc_t *vip;

    print_info("initiate shared memory object '%s'", VIDEOIPC_SHARED_OBJECT);

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

                print_error("error during shared memory initialization: %s",
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

static int init_xlib(char *display_name)
{
    XSetErrorHandler(error_handler);

    if ((disp   = XOpenDisplay(display_name)                       ) == NULL ||
        (msgtyp = XInternAtom(disp, VIDEOIPC_CLIENT_MESSAGE, False)) == None  )
    {
        errno = EIO;
        return FALSE;
    }

    rwin = DefaultRootWindow(disp);

    return TRUE;
}

static int send_notification(long mask)
{
    XEvent ev;

    memset(&ev, 0, sizeof(ev));
    ev.xclient.type = ClientMessage;
    ev.xclient.window = rwin;
    ev.xclient.message_type = msgtyp;
    ev.xclient.format = 32;
    ev.xclient.data.l[0] = mask;

    XSendEvent(disp, rwin, False, NoEventMask, &ev);

    XFlush(disp);

    return TRUE;
}

static int error_handler(Display *dsp, XErrorEvent *err)
{
    char errbuf[512];

    if ((XGetErrorText(dsp,err->error_code,errbuf,sizeof(errbuf))) > 0)
        print_error("X error: %s", errbuf);
    else
        print_error("X error");

    return 0;
}

#if 0
static const char *strstatus(Status st)
{
    switch (st) {
    case Success:            return "Success";
    case BadRequest:         return "BadRequest";
    case BadValue:           return "BadValue";
    case BadWindow:          return "BadWindow";
    case BadPixmap:          return "BadPixmap";
    case BadAtom:            return "BadAtom";
    case BadCursor:          return "BadCursor";
    case BadFont:            return "BadFont";
    case BadMatch:           return "BadMatch";
    case BadDrawable:        return "BadDrawable";
    case BadAccess:          return "BadAccess";
    case BadAlloc:           return "BadAlloc";
    case BadColor:           return "BadColor";
    case BadGC:              return "BadGC";
    case BadIDChoice:        return "BadIDChoice";
    case BadName:            return "BadName";
    case BadLength:          return "BadLength";
    case BadImplementation:  return "BadImplementation";
    default:                 return "<unknown>";
    }
}
#endif

static uint64_t current_time(void)
{
    uint64_t t;
    struct timeval tv;

    if (gettimeofday(&tv, NULL) < 0)
        t = 0ULL;
    else
        t = ((uint64_t)tv.tv_sec) * 1000000ULL  + (uint64_t)tv.tv_usec;

    return t;
}


static int parse_args(int argc, char **argv,
                      uint32_t *mask,
                      pid_t *pids, int *lenp)
{
    static uint32_t maxpid = (uint32_t)((1ULL << (sizeof(pid_t) * 8)) - 1);

    int len = *lenp;
    char *p, *e;
    uint32_t pid;
    int i;


    *lenp = 0;
    *mask = 0;

    if (argc == 2 && !strcmp(argv[1], "-h"))
        usage(0);

    if (argc < 3)
        usage(EINVAL);

    if (argc > len + 2) {
        print_error("pid list too long (max number of pids is %d)", len);
        exit(EINVAL);
    }

    if (!strcmp(argv[1], "xv")) {
        *mask = VIDEOIPC_XVIDEO_SECTION;
        if (len > VIDEOIPC_MAX_XV_USERS)
            len = VIDEOIPC_MAX_XV_USERS;
    }
    else {
        usage(EINVAL);
    }

    if (argc - 2 > len) {
        print_error("too long PID list. max allowed %d", len);
        exit(EINVAL);
    }

    for (i = 0;  i < argc-2;  i++) {
        p = argv[i+2];
        pid = strtoul(p, &e, 10);

        if (*e || p == e) {
            print_error("invalid PID '%s'", p);
            exit(EINVAL);
        }

        if (sizeof(pid_t) < sizeof(uint32_t) && pid > maxpid) {
            print_error("too large PID %s (maximum allowed %lu)",
                        p, (long unsigned int)maxpid);
            exit(EINVAL);
        }

        pids[i] = pid;
    }

    *lenp = i;

    return TRUE;
}

static void usage(int exit_code)
{
    fprintf(stderr,
            "Usage: %s {-h} | {<section> <pid> [pid [...]]}\n"
            "   where <section> is one of\n"
            "     xv\n",
            prognam);

    exit(exit_code);
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
