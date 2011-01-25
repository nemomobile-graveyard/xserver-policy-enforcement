#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "policy.h"
#include "client.h"
#include "authorize.h"
#include "winprop.h"
#include "xvideo.h"
#include "xrandr.h"
#include "ipc.h"

#include <xf86Module.h>
#include <xf86Optrec.h>


typedef struct {
    const char        *name;
    PolicyParserFunc   parser;
} OptionRec;


static Bool ParseOptions(pointer);

static OptionRec   optdefs[] = {
    { XVIDEO_RESTRICT_XVATTR_ACCESS,   XvideoParseOption },
    {             NULL             ,         NULL        }
};


static pointer
PolicySetup(pointer  module,
            pointer  options,
            int     *emaj,
            int     *emin)
{
    Bool success;


    success  = ClientInit();
    success &= AuthorizeInit();
    success &= WinpropInit();
    success &= XvideoInit();
    success &= XrandrInit();
    success &= IpcInit();
    success &= ParseOptions(options);

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

    IpcExit();
    XrandrExit();
    XvideoExit();
    WinpropExit();
    AuthorizeExit();
    ClientExit();
}


static Bool
ParseOptions(pointer data)
{
    XF86OptionPtr  opt;
    Bool           success;
    char          *name;
    char          *value;
    OptionRec     *def;

    success = TRUE;

    for (opt = (XF86OptionPtr)data;  opt != NULL;  opt = xf86nextOption(opt)) {
        name  = xf86optionName(opt);
        value = xf86optionValue(opt);

        if (!name) {
            success = FALSE;
            continue;
        }

        for (def = optdefs;   def->parser != NULL;    def++) {
            if (!strcmp(name, def->name))
                break;
        }

        if (def->parser)
            success = def->parser(name, value);
        else {
            success = FALSE;
            PolicyError("unknown option '%s'", name);
        }
    }


    return success;
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
