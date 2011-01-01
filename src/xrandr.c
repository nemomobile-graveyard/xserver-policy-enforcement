#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "policy.h"
#include "xrandr.h"
#include "client.h"

#include <extnsionst.h>
#include <dixstruct.h>
#include <randrstr.h>

#include <X11/extensions/randr.h>

static const char *RequestName(unsigned short);


Bool
XrandrInit(void)
{
    return TRUE;
}

void
XrandrExit(void)
{
}

int
XrandrAuthorizeRequest(ClientPtr client, ExtensionEntry *ext)
{
    unsigned short  opcode = StandardMinorOpcode(client);
    ClientPolicyPtr policy = ClientGetPolicyRec(client);

    PolicyDebug("client %p (pid %u exe '%s') requested RandR %s",
                client, policy->pid, policy->exe, RequestName(opcode));

    return Success;
}


static const char *
RequestName(unsigned short opcode)
{
    switch (opcode) {
    case X_RRQueryVersion:               return "QueryVersion";
    case X_RRSetScreenConfig:            return "SetScreenConfig";
    case X_RRSelectInput:                return "SelectInput";
    case X_RRGetScreenInfo:              return "GetScreenInfo";
    case X_RRGetScreenSizeRange:         return "GetScreenSizeRange";
    case X_RRSetScreenSize:              return "SetScreenSize";
    case X_RRGetScreenResources:         return "GetScreenResources";
    case X_RRGetOutputInfo:              return "GetOutputInfo";
    case X_RRListOutputProperties:       return "ListOutputProperties";
    case X_RRQueryOutputProperty:        return "QueryOutputProperty";
    case X_RRConfigureOutputProperty:    return "ConfigureOutputProperty";
    case X_RRChangeOutputProperty:       return "ChangeOutputProperty";
    case X_RRDeleteOutputProperty:       return "DeleteOutputProperty";
    case X_RRGetOutputProperty:	         return "GetOutputProperty";
    case X_RRCreateMode:                 return "CreateMode";
    case X_RRDestroyMode:                return "DestroyMode";
    case X_RRAddOutputMode:              return "AddOutputMode";
    case X_RRDeleteOutputMode:           return "DeleteOutputMode";
    case X_RRGetCrtcInfo:                return "GetCrtcInfo";
    case X_RRSetCrtcConfig:              return "SetCrtcConfig";
    case X_RRGetCrtcGammaSize:           return "GetCrtcGammaSize";
    case X_RRGetCrtcGamma:               return "GetCrtcGamma";
    case X_RRSetCrtcGamma:               return "SetCrtcGamma";
    case X_RRGetScreenResourcesCurrent:  return "GetScreenResourcesCurrent";
    case X_RRSetCrtcTransform:           return "SetCrtcTransform";
    case X_RRGetCrtcTransform:           return "GetCrtcTransform";
    case X_RRGetPanning:                 return "GetPanning";
    case X_RRSetPanning:                 return "SetPanning";
    case X_RRSetOutputPrimary:           return "SetOutputPrimary";
    case X_RRGetOutputPrimary:           return "GetOutputPrimary";
    default:                             return "<unknown>";
    }
}




/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
