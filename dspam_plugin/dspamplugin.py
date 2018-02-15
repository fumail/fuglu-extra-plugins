# -*- coding: UTF-8 -*-


from fuglu.shared import ScannerPlugin, DUNNO, DEFER, string_to_actioncode, apply_template
from dspam.client import DspamClient, DspamClientError



GTUBE = """Date: Mon, 08 Sep 2008 17:33:54 +0200
To: oli@unittests.fuglu.org
From: oli@unittests.fuglu.org
Subject: test scanner

  XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X
"""



class DspamPlugin(ScannerPlugin):
    
    
    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.logger = self._logger()
        self.requiredvars = {
            'socket': {
                'default': 'inet:2424@localhost',
                'description': 'the socket dspam server listens to',
            },

            'username': {
                'default': 'user',
                'description': 'the authentication user name to connect to dspam',
            },

            'password': {
                'default': 'secretpass',
                'description': 'the authentication password to connect to dspam',
            },

            'scanoriginal': {
                'default': '1',
                'description': "should we scan the original message as retreived from postfix or scan the current state \nin fuglu (which might have been altered by previous plugins)\nonly set this to disabled if you have a custom plugin that adds special headers to the message that will be \nused in rspamd rules",
            },

            'spamaction': {
                'default': 'DEFAULTLOWSPAMACTION',
                'description': "what should we do with low spam (eg. detected as spam, but score not over highspamlevel)",
            },

            'problemaction': {
                'default': 'DEFER',
                'description': "action if there is a problem (DUNNO, DEFER)",
            },

            'rejectmessage': {
                'default': 'message identified as spam',
                'description': "reject message template if running in pre-queue mode",
            },
        }
    
    
    
    def __str__(self):
        return "Dspam"
    
    
    
    def lint(self):
        allok = self.check_config()
        self._lint_gtube()
        return allok
    
    
    
    def _lint_gtube(self):
        results = self._check_dspam(GTUBE, 'recipient@example.net')
        print('Classification results: ' + str(results))
        
        
        
    def _check_dspam(self, content, recipient):
        sock = self.config.get(self.section, 'socket')
        username = self.config.get(self.section, 'username')
        password = self.config.get(self.section, 'password')
        c = DspamClient(sock, username, password)
        results = c.process(content, recipient)
        return results
    
    
    
    def _is_spam(self, results):
        is_spam = False
        if results['class'] in ['Blacklisted', 'Blocklisted', 'Spam', 'Virus']:
            is_spam = True
        return is_spam
    
    
    
    def _report(self, results):
        report = []
        for key in ['result', 'class', 'probability', 'confidence', 'signature']:
            value = results.get(key)
            report.append(value)
        return '; '.join(report)
        
        
    def examine(self, suspect):
        if suspect.get_tag('Dspam.skip') is True:
            self.logger.debug('%s Skipping Dspam Plugin (requested by previous plugin)' % suspect.id)
            suspect.set_tag('Dspam.skipreason', 'requested by previous plugin')
            return DUNNO
        
        if self.config.getboolean(self.section, 'scanoriginal'):
            content = suspect.get_original_source()
        else:
            content = suspect.get_source()
            
        recipient = suspect.to_address
        try:
            results = self._check_dspam(content, recipient)
        except DspamClientError as e:
            self.logger.error('%s failed to process by dspam: %s' % (suspect.id, str(e)))
            return self._problemcode()
        
        action = DUNNO
        message = None
        isspam = self._is_spam(results)
        suspect.tags['spam']['Dspam'] = isspam
        suspect.tags['DSpam.report'] = self._report(results)
        if isspam:
            action = string_to_actioncode(self.config.get(self.section, 'spamaction'), self.config)
            message = apply_template(self.config.get(self.section, 'rejectmessage'), suspect, results)
        
        return action, message
    
    
    
    def _problemcode(self):
        retcode = string_to_actioncode(self.config.get(self.section, 'problemaction'), self.config)
        if retcode is not None:
            return retcode
        else:
            # in case of invalid problem action
            return DEFER
    
    