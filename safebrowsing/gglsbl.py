# -*- coding: UTF-8 -*-

"""
Google Safebrowsing Plugin
This plugin does not query Google Safebrowsing database directly.
Instead it depends on gglsbl-rest API service
https://github.com/mlsecproject/gglsbl-rest

Depending on what malware type hit, mail can be
- rejected
- tagged as virus, spam or blocked (needs custom evaluation plugin)
- tagged with a pseudo header for evaluation in plugins such as SpamAssassin.

SpamAssassin sample rule for tagged messages:
header          FUGLU_SAFEBROWSING_MALWARE        X-Safebrowsing =~ /^MALWARE$/
describe        FUGLU_SAFEBROWSING_MALWARE        URI detected by Google Safebrowsing
score           FUGLU_SAFEBROWSING_MALWARE        25.0
"""


from fuglu.shared import ScannerPlugin, DUNNO, REJECT, DEFER, string_to_actioncode, apply_template
import logging
import json
try:
    import urlparse
    from urllib import quote as urllib_quote
    from urllib2 import urlopen, HTTPError
except ImportError: #py3
    from urllib import parse as urlparse
    from urllib.parse import quote as urllib_quote
    from urllib.request import urlopen, HTTPError



BASE_PATH = u'gglsbl/v1/'
LOOKUP = u'lookup/'
STATUS = u'status'
SAMPLE_URL = 'http://testsafebrowsing.appspot.com/apiv4/LINUX/SOCIAL_ENGINEERING/URL/'



# https://developers.google.com/safe-browsing/v4/reference/rest/v4/ThreatType
TT_NA = u'THREAT_TYPE_UNSPECIFIED'
TT_MW = u'MALWARE'
TT_SE = u'SOCIAL_ENGINEERING'
TT_PUA = u'UNWANTED_SOFTWARE'
TT_PHA = u'POTENTIALLY_HARMFUL_APPLICATION'



class GGLSBLClient(object):
    
    def __init__(self, baseurl, timeout=3):
        self.baseurl = baseurl
        self.timeout=timeout
        self.logger = logging.getLogger('%s.safebrowseclient' % __package__)
    
    
    
    def _quote(self, url):
        return urllib_quote(url)
    
    
    
    def _query(self, url):
        data = ''
        code = 0
        try:
            fp = urlopen(url, timeout=self.timeout)
            data = fp.read()
            code = fp.getcode()
            fp.close()
        except HTTPError as e:
            code = e.code
            if code != 404:
                self.logger.debug('query failed with code %s: %s' % (code, str(e)))
        except Exception as e:
            self.logger.error('query failed: %s' % str(e))
        return data, code
    
    
    
    def _convert(self, jsondata):
        data = u''
        try:
            if isinstance(jsondata, bytes): # python3
                jsondata = jsondata.decode('utf-8')
            data = json.loads(jsondata)
        except Exception as e:
            self.logger.error('data conversion failed: %s' % str(e))
        return data
    
    
    
    def _urljoin(self, *parts):
        base = ''
        for part in parts:
            base = urlparse.urljoin(base, part)
        return base
    
    
    
    def status(self):
        queryurl = self._urljoin(self.baseurl, BASE_PATH, STATUS)
        jsondata, code = self._query(queryurl)
        if code == 200:
            data = self._convert(jsondata) # type: dict
        else:
            data = None
        return data
    
    
    
    def lookup(self, url):
        try:
            url = self._quote(url)
        except Exception as e:
            self.logger.error('Invalid URL %s : %s' % (url, str(e)))
            return None
        
        queryurl = self._urljoin(self.baseurl, BASE_PATH, LOOKUP, url)
        jsondata, code = self._query(queryurl)
        if code == 200:
            data = self._convert(jsondata) # type: dict
        elif code == 404:
            data = {}
        else:
            data = None
        return data
    
    
    
    def assemble(self, data):
        threat_types = []
        if data is None:
            return threat_types
        if 'matches' in data:
            for item in data['matches']:
                if 'threat' in item:
                    threat = item['threat']
                    if threat not in threat_types:
                        threat_types.append(threat)
        return threat_types
    
    
    
    def lint(self):
        success = False
        data = self.lookup(SAMPLE_URL)
        if data is None:
            print('query error')
        elif data == {}:
            print('no threat found')
        else:
            success = True
            print('sample threat found - your gglsbl-rest is up, running and reachable')
        return success



class Safebrowsing(ScannerPlugin):
    def __init__(self, section=None):
        ScannerPlugin.__init__(self, section)
        self.logger = self._logger()
        
        self.requiredvars = {
            'baseurl': {
                'default': 'http://127.0.0.1:5000/',
                'description': 'base URL of your gglsbl-rest instance',
            },
            
            'timeout': {
                'default': '3',
                'description': 'maximum REST API query time in seconds',
            },

            'problemaction': {
                'default': 'DEFER',
                'description': "action if there is a problem (DUNNO, DEFER)",
            },
            
            'maxlookups':{
                'default':'10',
                'description':'maximum number of URIs to check per message',
            },
            
            'stop_on_first_hit':{
                'default':'True',
                'description':'stop queries on first hit. else check up to maxlookups URIs',
            },
            
            'threats_reject':{
                'default':'',
                'description':'reject if at least one URL has one of these threat types (only use in prequeue mode)',
            },
            
            'threats_virus':{
                'default':'',
                'description':'tag as virus if at least one URL has one of these threat types',
            },
            
            'threats_block':{
                'default':'',
                'description':'tag as blocked if at least one URL has one of these threat types',
            },
            
            'threats_highspam':{
                'default':'',
                'description':'tag as spam if at least one URL has one of these threat types',
            },
            
            'threats_spam':{
                'default':'',
                'description':'tag as spam if at least one URL has one of these threat types',
            },
            
            'threats_tag':{
                'default':'THREAT_TYPE_UNSPECIFIED MALWARE SOCIAL_ENGINEERING UNWANTED_SOFTWARE POTENTIALLY_HARMFUL_APPLICATION',
                'description':'add a tag for SpamAssassin if at least one URL has one of these threat types',
            },
            
            'eval_order':{
                'default':'threats_reject threats_virus threats_block threats_highspam threats_spam threats_tag',
                'description':'in which order should above threat actions be applied',
            },

            'rejectmessage': {
                'default': 'message identified as containing ${threat}',
                'description': "reject message template if running in pre-queue mode",
            },

            'virusaction': {
                'default': 'DEFAULTVIRUSACTION',
                'description': "action if considered threats_virus (DUNNO, REJECT, DELETE)",
            },
            
            'max_tag_size': {
                'default': '256000',
                'description': "maximum size in bytes of messages to tag for spamassasin. should be equal to maxsize settings of spamassassin. larger messages will be marked as spam.",
            },
        
        }
        
        self.sbc = None
    
    
    
    def _init_sbc(self):
        if self.sbc is None:
            baseurl = self.config.get(self.section, 'baseurl')
            timeout = self.config.getint(self.section, 'timeout')
            self.sbc = GGLSBLClient(baseurl, timeout)
        
        
        
    def lint(self):
        allok = self.check_config()
        if self.config.getint(self.section, 'max_tag_size') > self.config.getint('SAPlugin', 'maxsize'):
            print('max_tag_size should not be larger than Spamassassin maxsize')
            allok = False
        
        if allok:
            self._init_sbc()
            allok = self.sbc.lint()
        return allok
    
    
    
    def examine(self, suspect):
        action = DUNNO
        message = None
        self._init_sbc()
        uris = suspect.get_tag('body.uris')
        if uris is None:
            return DUNNO
        
        maxlookups = self.config.getint(self.section, 'maxlookups')
        stop_on_first_hit = self.config.getboolean(self.section, 'stop_on_first_hit')
        
        error, threat_types = self._lookup(uris, maxlookups, stop_on_first_hit)
        if error and not threat_types:
            self.logger.error('failed to query gglsbl-rest server')
            action = self._problemcode()
            message = 'Internal error'
        elif threat_types:
            reject, virus, block, highspam, spam, tag = self._eval_threats(threat_types)
            self.logger.info('%s query result: reject=%s virus=%s block=%s highspam=%s spam=%s tag=%s' % (suspect.id, reject, virus, block, highspam, spam, tag))
            if reject is not None:
                action = REJECT
                message = self._rejectmessage(suspect, reject.get('threat'), reject.get('uri'))
                self.logger.info('%s do reject' % suspect.id)
            if virus:
                suspect.tags['virus']['safebrowsing'] = True
                suspect.tags['safebrowsing.result.virus'] = virus
                virusaction = self.config.get(self.section, 'virusaction')
                action = string_to_actioncode(virusaction, self.config)
                for threat in virus:
                    message = self._rejectmessage(suspect, threat, virus[threat][0])
                self.logger.info('%s mark as virus' % suspect.id)
            if block:
                suspect.tags['blocked']['safebrowsing'] = True
                suspect.set_tag('safebrowsing.blocked', True)
                suspect.tags['safebrowsing.result.blocked'] = block
                self.logger.info('%s mark as blocked' % suspect.id)
            if highspam:
                suspect.tags['highspam']['safebrowsing'] = True
                suspect.tags['safebrowsing.result.highspam'] = spam
                self.logger.info('%s mark as spam' % suspect.id)
            if spam or tag and suspect.size > self.config.get(self.section, 'max_tag_size'):
                suspect.tags['spam']['safebrowsing'] = True
                suspect.tags['safebrowsing.result.spam'] = spam
                self.logger.info('%s mark as spam' % suspect.id)
            if tag:
                for threat in tag:
                    self._writeheader(suspect, 'X-Safebrowsing', threat)
                self.logger.info('%s add tag' % suspect.id)
        #else:
        #    self.logger.info('%s no safebrowsing threat found' % suspect.id)
            
        return action, message
    
    
    
    def _rejectmessage(self, suspect, threat, uri):
        values = dict(threat=threat, uri=uri)
        message = apply_template(self.config.get(self.section, 'rejectmessage'), suspect, values)
        return message
    
    
    
    def _writeheader(self, suspect, header, value):
        hdr = "%s: %s" % (header, value)
        tag = suspect.get_tag('SAPlugin.tempheader')
        if isinstance(tag, list):
            tag.append(hdr)
        elif tag is None:
            tag = [hdr, ]
        else:  # str/unicode
            tag = "%s\r\n%s" % (tag, hdr)
        suspect.set_tag('SAPlugin.tempheader', tag)
    
    
    
    def _eval_threats(self, threat_types):
        reject = None
        virus = {}
        block = {}
        highspam = {}
        spam = {}
        tag = {}
        
        eval_order = [x.strip() for x in self.config.get(self.section, 'eval_order').replace(',', ' ').split()]
        for item in eval_order:
            threats = [x.strip() for x in self.config.get(self.section, item).replace(',', ' ').split()]
            for threat in threats:
                if threat in threat_types.keys():
                    uri = threat_types[threat][0]
                    if item == 'threats_reject':
                        reject = dict(threat=threat, uri=uri)
                    elif item == 'threats_virus':
                        if threat not in virus:
                            virus[threat] = []
                        virus[threat].append(uri)
                    elif item == 'threats_block':
                        if threat not in block:
                            block[threat] = []
                        block[threat].append(uri)
                    elif item == 'threats_highspam':
                        if threat not in highspam:
                            highspam[threat] = []
                        highspam[threat].append(uri)
                    elif item == 'threats_spam':
                        if threat not in spam:
                            spam[threat] = []
                        spam[threat].append(uri)
                    elif item == 'threats_tag':
                        if threat not in tag:
                            tag[threat] = []
                        tag[threat].append(uri)
                    break
            if reject or virus or block or spam or tag:
                break
        
        return reject, virus, block, highspam, spam, tag
    
    
    
    def _lookup(self, uris, maxlookups=10, stop_on_first_hit=True):
        error = False
        
        threat_types = {}
        for uri in uris[:maxlookups]:
            data = self.sbc.lookup(uri)
            if data is None: # lookup error
                error = True
                break
            threats = self.sbc.assemble(data)
            for threat in threats:
                if not threat in threat_types:
                    threat_types[threat] = []
                threat_types[threat].append(uri)
            if threat_types and stop_on_first_hit:
                break
        
        return error, threat_types
    
    
    
    def _problemcode(self):
        retcode = string_to_actioncode(
            self.config.get(self.section, 'problemaction'), self.config)
        if retcode is not None:
            return retcode
        else:
            # in case of invalid problem action
            return DEFER
    
    
    
    def __str__(self):
        return "GGLSBL Safebrowsing"
    
    
