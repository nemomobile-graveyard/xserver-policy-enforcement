#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "policy.h"
#include "client.h"
#include "xvideo.h"
#include "xrandr.h"

#include <xf86Module.h>




static pointer
PolicySetup(pointer  module,
            pointer  options,
            int     *emaj,
            int     *emin)
{
    Bool success;


    success  = ClientInit();
    success &= AuthorizeInit();
    success &= XvideoInit();
    success &= XrandrInit();


    if (success)
        PolicyInfo("Policy extension successfuly initilized");
    else
        PolicyError("Failed to initialize policy extension");

    return module;
}

static void
PolicyTeardown(pointer p)
{
    (void)p;

    XrandrExit();
    XvideoExit();
    AuthorizeExit();
    ClientExit();
}




static XF86ModuleVersionInfo PolicyVersionRec =
{
    "policy",
    "MeeGo",
    0x58504550,                      /* XPEP */
    0,
    XORG_VERSION_CURRENT,
    PACKAGE_VERSION_MAJOR, PACKAGE_VERSION_MINOR, PACKAGE_VERSION_PATCHLEVEL,
    ABI_CLASS_EXTENSION,
    ABI_EXTENSION_VERSION,
    MOD_CLASS_EXTENSION,
    {0, 0, 0, 0}
};


_X_EXPORT XF86ModuleData policyModuleData = {
    &PolicyVersionRec,
    PolicySetup,
    PolicyTeardown
};

/*
 * Local Variables:
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 *
 */
