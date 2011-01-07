#ifndef __VIDEOIPC_H__
#define __VIDEOIPC_H__

#include <sys/types.h>
#include <stdint.h>

#define VIDEOIPC_SHARED_OBJECT       "/videoipc"
#define VIDEOIPC_CLIENT_MESSAGE      "_MEEGO_VIDEOIPC_UPDATE"

#define VIDEOIPC_MAJOR_VERSION       0
#define VIDEOIPC_MINOR_VERSION       1

#define VIDEOIPC_XVIDEO_SECTION      0x00000001
#define VIDEOIPC_XRANDR_SECTION      0x00000002

#define VIDEOIPC_MAX_XV_USERS        16

#define NOIPC                        (void *)-1


#define VIDEOIPC_VERSION                                                \
    struct {                                                            \
        uint16_t major;                                                 \
        uint16_t minor;                                                 \
    }              version

#define VIDEOIPC_USERS(class)                                           \
    struct {                                                            \
        int8_t     idx;         /* selects the set to be used */        \
        uint8_t    pad[3];                                              \
        struct {                                                        \
            uint64_t time;      /* time when this set last changed */   \
            int      npid;                                              \
            pid_t    pids[VIDEOIPC_MAX_ ##class##_USERS];               \
        }          set[2];                                              \
    } class##users

typedef struct {
    VIDEOIPC_VERSION;           /* version */
    VIDEOIPC_USERS(XV);         /* XVusers */
} videoipc_t;

typedef struct {
    uint64_t time;
    int      npid;
    pid_t    pids[0];
} videoipc_set_t;

#endif	/* __VIDEOIPC_H__ */

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
