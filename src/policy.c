
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "policy.h"

#include <xf86Module.h>
#include <dix.h>
#include <dixstruct.h>
#include <os.h>

static pointer PolicyPlug(pointer module, pointer options, int *emaj,int *emin)
{
    LogMessage(X_INFO, "Policy bingo !\n");

    return module;
}

static void PolicyUnplug(pointer *p)
{
    (void)p;
}

static XF86ModuleVersionInfo PolicyVersionRec =
{
    "policy",
    "MeeGo",
    "policy enforcement point",
    "",
    XORG_VERSION_CURRENT,
    PACKAGE_VERSION_MAJOR, PACKAGE_VERSION_MINOR, PACKAGE_VERSION_PATCHLEVEL,
    ABI_CLASS_EXTENSION,
    ABI_EXTENSION_VERSION,
    MOD_CLASS_EXTENSION,
    {0, 0, 0, 0}
};


_X_EXPORT XF86ModuleData policyModuleData = {
    &PolicyVersionRec,
    PolicyPlug,
    PolicyUnplug
};

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
