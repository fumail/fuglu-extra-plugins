Command Line AV
---------------

Some linux antivirus engines only provide a command line interface. This plugin tries to make them usable in a generic way.

The plugin **CMDLineAVGeneric** can be used for any currently unsupported/unknown antivirus engine.

The file also includes subclasses for specific engines, with the correct paths/regex already configured.

 * **ClamAV** (clamscan): CMDLineAVClam
 * **Sophos** (savscan): CMDLineAVSophos
 * **F-Prot** (fpscan): CMDLineAVFprot
 * **ESETS**  (esets_scan): CMDLineAVEsets

Status: beta, only tested using "plugdummy"
