# -*- coding: UTF-8 -*-
#   Copyright 2018 - by Tobi <jahlives@gmx.ch>
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
from fuglu.shared import ScannerPlugin, DUNNO
import re

class MakeVirus(ScannerPlugin):
    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.requiredvars = {
            'regex': {
                'default': '',
                'description': "regex to match",
            },

        }
	self.regex = None
        self.logger = self._logger()

    def examine(self, suspect):
        if self.config.get(self.section, 'regex') is not '':
            if self.regex is None:
                self.regex = re.compile(self.config.get(self.section, 'regex'))
            if suspect.get_tag('SAPlugin.report'):
                if re.search(self.regex, suspect.get_tag('SAPlugin.report')):
                    suspect.tags['virus']['make_virus'] = True
                    self.logger.info('Suspect %s marked as infected matching /%s/' % (suspect.id, self.regex.pattern) )
                else:
                    self.logger.debug('suspect %s not matched /%s/' % (suspect.id, self.regex.pattern))
            else:
                self.logger.info('suspect %s could not find SAPlugin.report' % suspect.id)
        else:
            self.logger.info('suspect %s could not find regex setting. Skip processing' % suspect.id)
        return DUNNO


