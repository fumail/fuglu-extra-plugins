# -*- coding: utf-8 -*-
from fuglu.shared import ScannerPlugin,DUNNO,string_to_actioncode,apply_template,FileList
from fuglu.stringencode import force_uString
import os
try:
    #py2
    import ConfigParser
    # noinspection PyCompatibility
    from HTMLParser import HTMLParser
except ImportError:
    #py3
    # noinspection PyUnresolvedReferences
    import configparser as ConfigParser
    # noinspection PyCompatibility, PyUnresolvedReferences
    from html.parser import HTMLParser

try:
    from domainmagic.extractor import URIExtractor, fqdn_from_uri
    from domainmagic.rbl import RBLLookup
    from domainmagic.tld import TLDMagic
    DOMAINMAGIC_AVAILABLE = True
except ImportError:
    DOMAINMAGIC_AVAILABLE=False
    fqdn_from_uri = URIExtractor = RBLLookup = TLDMagic = None


class URIExtract(ScannerPlugin):
    """Extract URIs from message bodies and store them as list in tag body.uris"""
    
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger = self._logger()
        self.extractor=None
        self.htmlparser = HTMLParser()
                
        self.requiredvars = {
            'domainskiplist':{
                'default':'/etc/fuglu/extract-skip-domains.txt',
                'description':'Domain skip list',
            },
            'maxsize':{
                'default':'10485000',
                'description':'Maximum size of processed mails. Larger mail will be skipped.',
            },
            'loguris':{
                'default':'no',
                'description':'print extracted uris in fuglu log',
            },
        }
        
    
    def _prepare(self):
        if self.extractor is None:
            self.extractor = URIExtractor()
            skiplist=self.config.get(self.section,'domainskiplist')
            if skiplist!='':
                self.extractor.load_skiplist(skiplist)


    def _run(self,suspect):
        if not DOMAINMAGIC_AVAILABLE:
            self.logger.info('Not scanning - Domainmagic not available')
            return DUNNO
        
        maxsize = self.config.getint(self.section, 'maxsize')
        if suspect.size>maxsize:
            self.logger.info('Not scanning - message too big (message %s  bytes > config %s bytes )' % (suspect.size, maxsize))
            return DUNNO

        self._prepare()
        
        uris = []
        for content in self.get_decoded_textparts(suspect):
            try:
                parturis=self.extractor.extracturis(content)
                uris.extend(parturis)
            except Exception as e:
                self.logger.error('%s failed to extract URIs from msg part: %s' % (suspect.id, str(e)))
            
        if self.config.getboolean(self.section,'loguris'):
            self.logger.info('%s Extracted URIs: %s' % (suspect.id, uris))
        suspect.set_tag('body.uris',uris)
        return DUNNO
        

    def process(self, suspect, decision):
        self._run(suspect)
    
    
    def examine(self,suspect):
        return self._run(suspect)

    def get_decoded_textparts(self, suspect,bcompatible=True):
        """bcompatible True will work with FUGLU version before implementation of attachment manager in Suspect """
        textparts = []

        try:
            attMgr = suspect.attMgr
        except AttributeError:
            message = 'This version of URIextract is supposed to use a FUGLU version with Attachment Manager. \n' \
                      'Please update your FUGLU version'
            if bcompatible:
                self.logger.warning(message)
            else:
                raise AttributeError(message)
            return self.get_decoded_textparts_deprecated(suspect)

        for attObj in attMgr.get_objectlist():
            if attObj.content_fname_check(contenttype_start="text/") \
                    or attObj.content_fname_check(name_end=(".txt", ".html", ".htm")):
                decoded_payload = attObj.decoded_buffer_text

                if attObj.content_fname_check(contenttype_contains="html") \
                        or attObj.content_fname_check(name_contains=".htm"):
                    decoded_payload=decoded_payload.replace(u'\n', u'').replace(u'\r', u'')

                try:
                    decoded_payload = self.htmlparser.unescape(decoded_payload)
                except Exception:
                    self.logger.debug('%s failed to unescape html entities' % suspect.id)

                textparts.append(decoded_payload)

            if attObj.content_fname_check(contenttype="multipart/alternative"):
                textparts.append(attObj.decoded_buffer_text)
        return textparts

    def get_decoded_textparts_deprecated(self, suspect):
        """Returns a list of all text contents"""
        messagerep = suspect.get_message_rep()
        
        textparts=[]
        for part in messagerep.walk():
            if part.is_multipart():
                continue
            fname=part.get_filename(None)
            if fname is None:
                fname=""
            fname=fname.lower()
            contenttype=part.get_content_type()
            
            if contenttype.startswith('text/') or fname.endswith(".txt") or fname.endswith(".html") or fname.endswith(".htm"):
                payload=part.get_payload(None,True)
                if payload is not None:
                    # Try to decode using the given char set (or utf-8 by default)
                    charset = part.get_content_charset("utf-8")
                    payload = force_uString(payload,encodingGuess=charset)

                if 'html' in contenttype or '.htm' in fname: #remove newlines from html so we get uris spanning multiple lines
                    payload=payload.replace('\n', '').replace('\r', '')
                try:
                    payload = self.htmlparser.unescape(payload)
                except Exception:
                    self.logger.debug('%s failed to unescape html entities' % suspect.id)
                textparts.append(payload)
            
            if contenttype=='multipart/alternative':
                try:
                    payload = part.get_payload(None,True)

                    if payload is not None:
                        # Try to decode using the given char set
                        charset = part.get_content_charset("utf-8")
                        text = force_uString(payload,encodingGuess=charset)

                    textparts.append(text)
                except (UnicodeEncodeError, UnicodeDecodeError):
                    self.logger.debug('%s failed to convert alternative part to string' % suspect.id)
            
        return textparts
    
    
    def lint(self):
        allok = True
        if not DOMAINMAGIC_AVAILABLE:
            print("ERROR: domainmagic lib or one of its dependencies (dnspython/pygeoip) is not installed!")
            allok = False
        
        if allok:
            allok = self.check_config()
        
        return allok


class EmailExtract(URIExtract):
    def __init__(self,config,section=None):
        URIExtract.__init__(self,config,section)
        self.logger = self._logger()
        self.requiredvars = {
            'headers': {
                'default':'Return-Path,Reply-To,From,X-RocketYMMF,X-Original-Sender,Sender,X-Originating-Email,Envelope-From,Disposition-Notification-To', 
                'description':'comma separated list of headers to check for adresses to extract'
            },
            
            'skipheaders': {
                'default':'X-Original-To,Delivered-To,X-Delivered-To,Apparently-To,X-Apparently-To',
                'description':'comma separated list of headers with email adresses that should be skipped in body search'
            },
        }
    
    
    def _run(self,suspect):
        if not DOMAINMAGIC_AVAILABLE:
            self.logger.info('Not scanning - Domainmagic not available')
            return DUNNO
        
        maxsize = self.config.getint(self.section, 'maxsize')
        if suspect.size>maxsize:
            self.logger.info('Not scanning - message too big (message %s  bytes > config %s bytes )' % (suspect.size, maxsize))
            return DUNNO

        self._prepare()

        textparts=" ".join(self.get_decoded_textparts(suspect))
        for hdr in self.config.get(self.section,'headers').split(','):
            textparts+=" ".join(suspect.get_message_rep().get_all(hdr,""))

        foundemails=self.extractor.extractemails(textparts)

        ignoreemailtext=""
        for hdr in self.config.get(self.section,'skipheaders').split(','):
            ignoreemailtext+=" ".join(suspect.get_message_rep().get_all(hdr,""))
        ignoreemails=[x.lower() for x in self.extractor.extractemails(ignoreemailtext)]
        ignoreemails.extend(suspect.recipients)

        finalemails=[]
        for e in foundemails:
            if e.lower() not in ignoreemails:
                finalemails.append(e)

        suspect.set_tag('emails',finalemails)
        if self.config.getboolean(self.section,'loguris'):
            self.logger.info("Extracted emails: %s"%finalemails)
        return DUNNO


class DomainAction(ScannerPlugin):
    """Perform Action based on Domains in message body"""
    
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger = self._logger()
    
        self.requiredvars={       
            'blacklistconfig':{
                'default':'/etc/fuglu/rbl.conf',
                'description':'RBL Lookup config file',
            },
            'checksubdomains':{
                'default':'yes',
                'description':'check subdomains as well (from top to bottom, eg. example.com, bla.example.com, blubb.bla.example.com',
            },
            'action':{
                'default':'reject',
                'description':'action on hit (reject, delete, etc)',
            },
            'message':{
                'default':'5.7.1 black listed URL ${domain} by ${blacklist}',
                'description':'message template for rejects/ok messages',
            },
            'maxdomains':{
                'default':'10',
                'description':'maximum number of domains to check per message',
            },
            'extra_tld_file': {
                'default':'',
                'description':'directory containing files with extra TLDs (2TLD or inofficial TLDs)'
            },
        }
        
        self.rbllookup=None
        self.tldmagic=None
        self.extratlds=None
        self.lasttlds=None
        
        
    def _init_tldmagic(self):
        init_tldmagic = False
        extratlds = []
        
        if self.extratlds is None:
            extratldfile = self.config.get(self.section,'extra_tld_file')
            if extratldfile and os.path.exists(extratldfile):
                self.extratlds = FileList(extratldfile, lowercase=True)
                init_tldmagic = True
        
        if self.extratlds is not None:
            extratlds = self.extratlds.get_list()
            if self.lasttlds != extratlds: # extra tld file changed
                self.lasttlds = extratlds
                init_tldmagic = True
        
        if self.tldmagic is None or init_tldmagic:
            self.tldmagic = TLDMagic()
            for tld in extratlds: # add extra tlds to tldmagic
                self.tldmagic.add_tld(tld)
    
    
    def examine(self,suspect):
        if not DOMAINMAGIC_AVAILABLE:
            self.logger.info('Not scanning - Domainmagic not available')
            return DUNNO
        
        if self.rbllookup is None:
            self.rbllookup = RBLLookup()
            self.rbllookup.from_config(self.config.get(self.section,'blacklistconfig'))
        self._init_tldmagic()

        urls=suspect.get_tag('body.uris',defaultvalue=[])
        #self.logger.info("Body URIs to check: %s"%urls)
        domains=set(map(fqdn_from_uri,urls))
        
        counter=0
        for domain in domains:
            counter+=1
            if counter>self.config.getint(self.section,'maxdomains'):
                self.logger.info("maximum number of domains reached")
                break
            
            tldcount=self.tldmagic.get_tld_count(domain)
            parts=domain.split('.')
            
            if self.config.getboolean(self.section,'checksubdomains'):
                subrange=range(tldcount+1,len(parts)+1)
            else:
                subrange=[tldcount+1]
            
            for subindex in subrange:
                subdomain='.'.join(parts[-subindex:])

                listings=self.rbllookup.listings(subdomain)
                for identifier,humanreadable in iter(listings.items()):
                    self.logger.info("%s : url host %s flagged as %s because %s"%(suspect.id,domain,identifier,humanreadable))
                    return string_to_actioncode(self.config.get(self.section,'action'), self.config),apply_template(self.config.get(self.section,'message'), suspect, dict(domain=domain,blacklist=identifier))
    
        return DUNNO
    
    
    def lint(self):
        allok = True
        if not DOMAINMAGIC_AVAILABLE:
            print("ERROR: domainmagic lib or one of its dependencies (dnspython/pygeoip) is not installed!")
            allok = False
        
        if allok:
            allok = self.check_config()
        
        if allok:
            extratldfile = self.config.get(self.section,'extra_tld_file')
            if extratldfile and not os.path.exists(extratldfile):
                allok = False
                print('WARNING: invalid extra_tld_file %s specified' % extratldfile)
        
        return allok

