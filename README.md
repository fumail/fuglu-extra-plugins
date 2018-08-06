!! **NOTE - fuglu-extra-plugins has moved to https://gitlab.com/fumail/fuglu-extra-plugins/ - This repository will no longer be updated and eventually deleted** !!


This repository contains additional plugins for the [FuGlu mail content scanner](https://github.com/gryphius/fuglu/)

These plugins can have varing degrees of usability/stability, anything from "just some tinkering" to "production ready".
if a plugin is stable and used widely enough it may be moved to the main FuGlu repository eventually.

Feel free to change/add new plugins via PR.

Each plugin should have its own directory and a little readme telling about its purpose and current status.


Installing a plugin
-------------------

 * copy the file to your `plugindir` (defined in fuglu.conf) - usually `/usr/local/fuglu/plugins`
 * load the plugin in fuglu.conf  - depending on the plugin type in `scanners=`, `prependers=`, `appenders=`. For example: scanners=[...], imapcopy.IMAPCopyPlugin
 * add a config section in fuglu.conf or a dedicated conf.d/[pluginname].conf according to the plugin's documentation
 * run `fuglu --lint` to test the config
 * reload or restart fuglu

