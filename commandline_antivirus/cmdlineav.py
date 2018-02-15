# -*- coding: UTF-8 -*-
#   Copyright 2009-2015 Oli Schacher
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from fuglu.shared import ScannerPlugin, DUNNO, DEFER, string_to_actioncode, apply_template
import re
import shlex
import subprocess
import threading
import traceback
from string import Template
import tempfile
import sys

if sys.version_info[0] >= 3:
    basestring = str


class Command(object):
    """
    adapted from https://gist.github.com/kirpit/1306188
    """
    command = None
    process = None
    status = None
    output, error = '', ''

    def __init__(self, command):
        if isinstance(command, basestring):
            command = shlex.split(command)
        self.command = command

    def run(self, timeout=None, **kwargs):
        """ Run a command then return: (status, output, error). """
        def target(**kwargs):
            try:
                self.process = subprocess.Popen(self.command, **kwargs)
                self.output, self.error = self.process.communicate()
                self.status = self.process.returncode
            except:
                self.error = traceback.format_exc()
                self.status = -1
        # default stdout and stderr
        if 'stdout' not in kwargs:
            kwargs['stdout'] = subprocess.PIPE
        if 'stderr' not in kwargs:
            kwargs['stderr'] = subprocess.PIPE
        # thread
        thread = threading.Thread(target=target, kwargs=kwargs)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            self.process.kill()
            thread.join()
            self.error = 'timed out'
            self.status=None
        return self.status, self.output, self.error


class CMDLineAVGeneric(ScannerPlugin):

    """ This plugin runs a command line AV scanner

Notes for developers:


Tags:

 * sets ``virus['identifier']`` (boolean)
 * sets ``identifier.virus`` (list of strings) - virus names found in message

(where identifier will be replaced with the identifier set in the config)

"""

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.logger=self._logger()
        self.requiredvars = {
            'identifier': {
                'default': 'CommandlineAV',
                'description': 'identifier used in the virus tag',
            },
            'exectemplate': {
                'default': '',
                'description': 'full path to the scan executable and arguments. ${suspectpath} will be replaced with the message file',
            },
            'timeout': {
                'default': '10',
                'description': "process timeout",
            },
            'viruspattern': {
                'default': '',
                'description': 'regular expression for infected messages. use virusname and filename groups',
            },
            'maxsize': {
                'default': '10485000',
                'description': "maximum message size to scan",
            },
            'virusaction': {
                'default': 'DEFAULTVIRUSACTION',
                'description': "plugin action if threat is detected",
            },
            'problemaction': {
                'default': 'DEFER',
                'description': "plugin action if scan fails",
            },
            'rejectmessage': {
                'default': 'threat detected: ${virusname}',
                'description': "reject message template if running in pre-queue mode and virusaction=REJECT",
            },
        }

    def _problemcode(self):
        retcode = string_to_actioncode(
            self.config.get(self.section, 'problemaction'), self.config)

        if retcode is None:
            # in case of invalid problem action
            return DEFER
        
        return retcode

    def examine(self, suspect):
        if suspect.size > self.config.getint(self.section, 'maxsize'):
            self._logger().info('Not scanning - message too big (message %s  bytes > config %s bytes )' %
                                (suspect.size, self.config.getint(self.section, 'maxsize')))
            return DUNNO

        try:
            viruses = self.scan_file(suspect.tempfile)

            if viruses is not None:
                self._logger().info("Virus found in message from %s : %s" %
                                    (suspect.from_address, viruses))
                suspect.tags['virus'][self.config.get(self.section,'identifier')] = True
                suspect.tags['%s.virus'%self.config.get(self.section,'identifier')] = viruses
                suspect.debug('Viruses found in message : %s' % viruses)
            else:
                suspect.tags['virus'][self.config.get(self.section,'identifier')] = False

            if viruses is not None:
                virusaction = self.config.get(self.section, 'virusaction')
                actioncode = string_to_actioncode(virusaction, self.config)
                firstinfected, firstvirusname = viruses.items()[0]

                values = dict(infectedfile=firstinfected, virusname=firstvirusname)

                message = apply_template(self.config.get(self.section, 'rejectmessage'), suspect, values)
                return actioncode, message
            else:
                return DUNNO
        except Exception as e:
            self._logger().warning("Error encountered while running cmdline av scan: %s" % str(e))

        return self._problemcode()

    def _parse_result(self, status, out, err):
        dr = {}
        pattern = self.config.get(self.section,'viruspattern')

        if pattern == '': #TODO: maybe in the future we need to support based on exit status
            return None

        for result in re.finditer(pattern, out, re.MULTILINE):
            gdic = result.groupdict()
            if 'filename' in gdic:
                filename = gdic['filename']
            else:
                filename = 'message'

            if 'virusname' in gdic:
                virusname = gdic['virusname']
            else:
                virusname = 'virus'

            dr[filename]=virusname

        if len(dr) == 0:
            return None

        return dr

    def scan_file(self, filename):
        template = Template(self.config.get(self.section,'exectemplate'))
        values = dict(suspectpath=filename)
        cmdline = template.safe_substitute(values)
        cmd = Command(cmdline)

        self.logger.info("Executing %s", cmdline)
        status, out, err = cmd.run(timeout=self.config.getint(self.section,'timeout'))

        if status is None: #timed out
            raise Exception("command %s timed out" % cmdline)

        if status == -1:
            raise Exception(err)

        self.logger.debug("Status: %s", status)
        self.logger.debug("Output: %s", out)

        if status == -1:
            self.logger.error('CMDLine Scan failed: %s'%err)
            return None

        return self._parse_result(status,out,err)

    def __str__(self):
        return 'Generic Commandline AV'

    def lint(self):
        allok = self.check_config() and self.lint_eicar()
        return allok

    def lint_eicar(self):
        stream = """Date: Mon, 08 Sep 2015 17:33:54 +0200
To: oli@unittests.fuglu.org
From: oli@unittests.fuglu.org
Subject: test eicar attachment
X-Mailer: swaks v20061116.0 jetmore.org/john/code/#swaks
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_12140"

------=_MIME_BOUNDARY_000_12140
Content-Type: text/plain

Eicar test
------=_MIME_BOUNDARY_000_12140
Content-Type: application/octet-stream
Content-Transfer-Encoding: BASE64
Content-Disposition: attachment

UEsDBAoAAAAAAGQ7WyUjS4psRgAAAEYAAAAJAAAAZWljYXIuY29tWDVPIVAlQEFQWzRcUFpYNTQo
UF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCoNClBLAQIU
AAoAAAAAAGQ7WyUjS4psRgAAAEYAAAAJAAAAAAAAAAEAIAD/gQAAAABlaWNhci5jb21QSwUGAAAA
AAEAAQA3AAAAbQAAAAAA

------=_MIME_BOUNDARY_000_12140--"""

        with tempfile.NamedTemporaryFile(suffix='fuglu-eicar') as eicar:
            eicar.write(stream)
            eicar.flush()
            result = self.scan_file(eicar.name)

        if result is None:
            print("EICAR Test virus not found!")
            return False

        print("%s found virus" % self.config.get(self.section, 'identifier'), result)
        return True


class CMDLineAVClam(CMDLineAVGeneric):
    """Implementation of Command Line ClamAV"""
    def __init__(self, config, section=None):
        CMDLineAVGeneric.__init__(self, config, section)
        self.logger=self._logger()
        self.requiredvars['identifier']={
                'default': 'ClamAV',
                'description': 'identifier used in the virus tag',
            }

        self.requiredvars['exectemplate']={
                'default': '/usr/bin/clamscan ${suspectpath}',
                'description': 'full path to the scan executable and arguments. ${suspectpath} will be replaced with the message file',
            }

        self.requiredvars['viruspattern']= {
                'default': r'^(?P<filename>[^\:]+)\: (?P<virusname>.+) FOUND$',
                'description': 'regular expression for infected messages. use virusname and filename groups',
            }

    def __str__(self):
        return 'Commandline ClamAV'


class CMDLineAVSophos(CMDLineAVGeneric):
    """Implementation of Command Line Sophos"""

    def __init__(self, config, section=None):
        CMDLineAVGeneric.__init__(self, config, section)
        self.logger=self._logger()
        self.requiredvars['identifier']={
                'default': 'Sophos',
                'description': 'identifier used in the virus tag',
            }

        self.requiredvars['exectemplate']={
                'default': '/usr/local/bin/savscan -mime -zip ${suspectpath}',
                'description': 'full path to the scan executable and arguments. ${suspectpath} will be replaced with the message file',
            }

        self.requiredvars['viruspattern']= {
                'default': r""">>> Virus '([^\']+)' found in file (?P<filename>.+)$""",
                'description': 'regular expression for infected messages. use virusname and filename groups',
            }

    def __str__(self):
        return 'Commandline Sophos'


class CMDLineAVFprot(CMDLineAVGeneric):
    """Implementation of F-Prot command line scanner"""
    
    def __init__(self, config, section=None):
        CMDLineAVGeneric.__init__(self, config, section)
        self.logger = self._logger()
        self.requiredvars['identifier'] = {
            'default': 'F-Prot',
            'description': 'identifier used in the virus tag',
        }
        
        self.requiredvars['exectemplate'] = {
            'default': '/opt/f-prot/fpscan --report --mount --adware --applications --nospin -s 4 -u 3 -z 10 ${suspectpath}',
            'description': 'full path to the scan executable and arguments. ${suspectpath} will be replaced with the message file',
        }
        
        self.requiredvars['viruspattern'] = {
            'default': r"""^\[Found\s+[^\]]*\]\s+<(?P<virusname>[^ \t(>]*)""",
            'description': 'regular expression for infected messages. use virusname and filename groups',
        }
    
    def __str__(self):
        return 'Commandline F-Prot'


class CMDLineAVEsets(CMDLineAVGeneric):
    """Implementation of ESETS command line scanner"""

    def __init__(self, config, section=None):
        CMDLineAVGeneric.__init__(self, config, section)
        self.logger = self._logger()
        self.requiredvars['identifier'] = {
            'default': 'ESETS',
            'description': 'identifier used in the virus tag',
        }

        self.requiredvars['exectemplate'] = {
            'default': '/opt/eset/esets/sbin/esets_scan --no-quarantine --clean-mode=none --ads --scan-timeout=10 --mail --adware --unsafe --unwanted --heur --adv-heur ${suspectpath}',
            'description': 'full path to the scan executable and arguments. ${suspectpath} will be replaced with the message file',
        }

        self.requiredvars['viruspattern'] = {
            'default': r"""^name="(?P<filename>[^"]+)", threat="(?P<virusname>.{2,30})", action=""",
            'description': 'regular expression for infected messages. use virusname and filename groups',
        }

    def __str__(self):
        return 'Commandline ESETS'

