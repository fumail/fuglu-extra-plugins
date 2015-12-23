from fuglu.shared import ScannerPlugin, string_to_actioncode, DEFER, DUNNO, actioncode_to_string,\
    DELETE, Suspect, apply_template

# do not use cStringIO - the python2.6 fix for opening some zipfiles does
# not work with cStringIO
from StringIO import StringIO
import zipfile
from email.header import decode_header
import sys
import os

RARFILE_AVAILABLE = 0
try:
    import rarfile
    RARFILE_AVAILABLE = 1
except ImportError:
    pass


YARA_AVAILABLE = 0
try:
    import yara
    YARA_AVAILABLE = 1
except ImportError:
    pass

class YARAPlugin(ScannerPlugin):
    """Flag messages as virus based on YARA rules
"""
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)

        self.requiredvars={
            'yararulesdir':{
                'default':'/etc/fuglu/yararules',
                'description':'Directory containing one or more YARA rule files',
            },
            'archivecontentmaxsize': {
                'default': '5000000',
                'description': 'only extract and examine files up to this amount of (uncompressed) bytes',
            },

            'virusaction': {
                'default': 'DEFAULTVIRUSACTION',
                'description': "action if infection is detected (DUNNO, REJECT, DELETE)",
            },

            'problemaction': {
                'default': 'DEFER',
                'description': "action if there is a problem (DUNNO, DEFER)",
            },

            'rejectmessage': {
                'default': 'threat detected in ${infectedfile}: ${virusname}',
                'description': "reject message template if running in pre-queue mode and virusaction=REJECT",
            },
        }
        self.filter=None
        self.logger=self._logger()
        self.lastreload=0
        self.compiled_rules=None

        # remember that the order is important here, if we support tar.gz and
        # gz in the future make sure tar.gz comes first!
        self.supported_archive_extensions = ['zip', ]
        if RARFILE_AVAILABLE:
            self.supported_archive_extensions.append('rar')


    def rulesdirchanged(self):
        rulesdir = self.config.get(self.section,'yararulesdir')
        if not os.path.isdir(rulesdir):
            return False
        statinfo = os.stat(rulesdir)
        ctime = statinfo.st_ctime
        if ctime > self.lastreload:
            return True
        return False

    def reload_if_necessary(self,warnings_as_errors=False):
        if not self.rulesdirchanged():
            return
        rulesdir = self.config.get(self.section,'yararulesdir')
        self.logger.info("Reloading YARA rules from %s"%rulesdir)
        filelist = os.listdir(rulesdir)

        yarafiles = [f for f in filelist if f.endswith('.yara')]
        dic = {}
        for yarafile in yarafiles:
            namespace = yarafile
            fullpath = os.path.join(rulesdir,yarafile)
            dic[namespace] = fullpath

        compiled_rules = yara.compile(filepaths = dic)
        self.compiled_rules = compiled_rules


    def examine(self,suspect):
        if not YARA_AVAILABLE:
            return

        self.reload_if_necessary()

        if not self.compiled_rules:
            return

        yarahits = None
        infectedfile = None

        m = suspect.get_message_rep()
        for i in m.walk():
            if i.is_multipart():
                continue
            att_name = i.get_filename(None)

            if att_name:
                # some filenames are encoded, try to decode
                try:
                    att_name = ''.join([x[0] for x in decode_header(att_name)])
                except:
                    pass
            else:
                att_name='message'

            payload = StringIO(i.get_payload(decode=True))
            yarahits = self.check_file(suspect,att_name, payload)
            if yarahits != None:
                infectedfile = att_name
                break

        if infectedfile and yarahits:
            self.logger.info(
                "YARA hit(s) in message from %s : %s" % (suspect.from_address, yarahits))
            suspect.tags['virus']['YARA'] = True
            suspect.tags['YARAPlugin.virus'] = yarahits[0].rule
            suspect.debug('YARA hit found in message : %s' % yarahits)

            virusaction = self.config.get(self.section, 'virusaction')
            actioncode = string_to_actioncode(virusaction, self.config)
            values = dict(
                infectedfile=infectedfile, virusname=yarahits[0].rule)
            message = apply_template(
                self.config.get(self.section, 'rejectmessage'), suspect, values)
            return actioncode, message
        else:
            suspect.tags['virus']['YARA'] = False
            return DUNNO


    def check_file(self, suspect, att_name, payload):
        archive_type = None
        for arext in self.supported_archive_extensions:
            if att_name.lower().endswith('.%s' % arext):
                archive_type = arext
                break

        if archive_type != None:
            try:
                archive_handle = self._archive_handle(archive_type, payload)
                namelist = self._archive_namelist(
                    archive_type, archive_handle)

                for name in namelist:
                    safename = self.asciionly(name)
                    extracted = self._archive_extract(
                        archive_type, archive_handle, name)
                    if extracted == None:
                        self._debuginfo(
                            suspect, '%s not extracted - too large' % (safename))
                        continue
                    return self.yara_hit(extracted)

            except Exception, e:
                self.logger.warning(
                    "archive scanning failed in attachment %s: %s" % (att_name, str(e)))
        else:
            return self.yara_hit(payload.getvalue())

    def _debug_callback(self,yaradict):
        self.logger.debug(yaradict)

    def yara_hit(self,payload):
        if not self.compiled_rules:
            return None
        matches = self.compiled_rules.match(data=payload,timeout=5) #pass callback=self._debug_callback here to debug
        if not matches:
            return None
        return matches

    #TODO: copy-pasted from attachment plugin -> consider moving this to a shared lib?

    def _fix_python26_zipfile_bug(self, zipFileContainer):
        "http://stackoverflow.com/questions/3083235/unzipping-file-results-in-badzipfile-file-is-not-a-zip-file/21996397#21996397"
        # HACK: See http://bugs.python.org/issue10694
        # The zip file generated is correct, but because of extra data after the 'central directory' section,
        # Some version of python (and some zip applications) can't read the file. By removing the extra data,
        # we ensure that all applications can read the zip without issue.
        # The ZIP format: http://www.pkware.com/documents/APPNOTE/APPNOTE-6.3.0.TXT
        # Finding the end of the central directory:
        #   http://stackoverflow.com/questions/8593904/how-to-find-the-position-of-central-directory-in-a-zip-file
        #   http://stackoverflow.com/questions/20276105/why-cant-python-execute-a-zip-archive-passed-via-stdin
        # This second link is only losely related, but echos the first,
        # "processing a ZIP archive often requires backwards seeking"

        content = zipFileContainer.read()
        # reverse find: this string of bytes is the end of the zip's central
        # directory.
        pos = content.rfind('\x50\x4b\x05\x06')
        if pos > 0:
            # +20: see secion V.I in 'ZIP format' link above.
            zipFileContainer.seek(pos + 20)
            zipFileContainer.truncate()
            # Zip file comment length: 0 byte length; tell zip applications to
            # stop reading.
            zipFileContainer.write('\x00\x00')
            zipFileContainer.seek(0)
        return zipFileContainer

    def _archive_handle(self, archive_type, payload):
        """get a handle for this archive type"""
        if archive_type == 'zip':
            if sys.version_info < (2, 7):
                payload = self._fix_python26_zipfile_bug(payload)
            return zipfile.ZipFile(payload)
        if archive_type == 'rar':
            return rarfile.RarFile(payload)

    def _archive_namelist(self, archive_type, handle):
        """returns a list of file paths within the archive"""
        # this works for zip and rar. if a future archive uses a different api,
        # add above
        return handle.namelist()

    def _archive_extract(self, archive_type, handle, path):
        """extract a file from the archive into memory
        returns the file content or None if the file would be larger than the setting archivecontentmaxsize
        """
        # this works for zip and rar. if a future archive uses a different api,
        # add above
        arinfo = handle.getinfo(path)
        if arinfo.file_size > self.config.getint(self.section, 'archivecontentmaxsize'):
            return None
        extracted = handle.read(path)
        return extracted

    def asciionly(self, stri):
        """return stri with all non-ascii chars removed"""
        return "".join([x for x in stri if ord(x) < 128])

    def lint(self):
        allok=(self.checkConfig() and self.lint_dependencies() and self.lint_rules())
        return allok

    def lint_dependencies(self):
        if not YARA_AVAILABLE:
            print "this plugin needs the yara python library"
            return False
        if not RARFILE_AVAILABLE:
            print "missing rarfile library, RAR unpacking disabled"
        return True

    def lint_rules(self):
        rulesdir = self.config.get(self.section,'yararulesdir')
        if not os.path.isdir(rulesdir):
            print "Yara rules directory %s not found"%rulesdir
            return False
        self.reload_if_necessary(warnings_as_errors=True)
        return True

    def __str__(self):
        return "YARA AV"