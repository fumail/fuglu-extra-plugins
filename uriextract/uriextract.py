# -*- coding: utf-8 -*-
from fuglu.shared import ScannerPlugin,DUNNO,string_to_actioncode,apply_template
import unittest
from ConfigParser import RawConfigParser
import logging

DOMAINMAGIC_AVAILABLE=False
try:
    import domainmagic
    import domainmagic.rbl
    import domainmagic.extractor
    import domainmagic.tld
    DOMAINMAGIC_AVAILABLE = True
except ImportError:
    pass


class URIExtract(ScannerPlugin):
    """Extract URIs from message bodies and store them as list in tag body.uris"""
    
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.extractor=None
        
        self.logger=logging.getLogger('fuglu.plugin.URIExtract')
                
        self.requiredvars={       
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
            self.extractor=domainmagic.extractor.URIExtractor()
            skiplist=self.config.get(self.section,'domainskiplist')
            if skiplist!='':
                self.extractor.load_skiplist(skiplist)


    def _run(self,suspect):
        maxsize = self.config.getint(self.section, 'maxsize')
        if suspect.size>maxsize:
            self.logger.info('Not scanning - message too big (message %s  bytes > config %s bytes )' % (suspect.size, maxsize))
            return DUNNO

        self._prepare()

        textparts=" ".join(self.get_decoded_textparts(suspect.get_message_rep()))
        uris=self.extractor.extracturis(textparts)
        if self.config.getboolean(self.section,'loguris'):
            self.logger.info('Extracted URIs: %s'%uris)
        suspect.set_tag('body.uris',uris)
        return DUNNO
        

    def process(self, suspect, decision):
        self._run(suspect)
    
    
    def examine(self,suspect):
        return self._run(suspect)
    
    
    def get_decoded_textparts(self,messagerep):
        """Returns a list of all text contents"""
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
                if 'html' in contenttype or '.htm' in fname: #remove newlines from html so we get uris spanning multiple lines
                    payload=payload.replace('\n', '').replace('\r', '')
                    
                textparts.append(payload)
            
            if contenttype=='multipart/alternative':
                try:
                    text=str(part.get_payload(None,True))
                    textparts.append(text)
                except (UnicodeEncodeError, UnicodeDecodeError):
                    pass
            
        return textparts
    
    
    def lint(self):
        if not DOMAINMAGIC_AVAILABLE:
            print "domainmagic lib or one of it's dependencies(dnspython/pygeoip) is not installed!"
            return False
        
        return self.checkConfig()


class EmailExtract(URIExtract):
    def __init__(self,config,section=None):
        URIExtract.__init__(self,config,section)
        self.logger=logging.getLogger('fuglu.plugin.EmailExtract')
        self.requiredvars['headers']={
                'default':'Return-Path,Reply-To,From,X-RocketYMMF,X-Original-Sender,Sender,X-Originating-Email,Envelope-From,Disposition-Notification-To', 
                'description':'comma separated list of headers to check for adresses to extract'
        }
        self.requiredvars['skipheaders']={
              'default':'X-Original-To,Delivered-To,X-Delivered-To,Apparently-To,X-Apparently-To',
              'description':'comma separated list of headers with email adresses that should be skipped in body search'             
        }
    
    
    def examine(self,suspect):
        maxsize = self.config.getint(self.section, 'maxsize')
        if suspect.size>maxsize:
            self.logger.info('Not scanning - message too big (message %s  bytes > config %s bytes )' % (suspect.size, maxsize))
            return DUNNO

        self._prepare()

        textparts=" ".join(self.get_decoded_textparts(suspect.get_message_rep()))
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
        self.logger=logging.getLogger('fuglu.plugin.DomainAction')
    
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
        }
        
        self.rbllookup=None
        self.tldmagic=None
    
    
    def examine(self,suspect):
        if self.rbllookup is None:
            self.rbllookup=domainmagic.rbl.RBLLookup()
            self.rbllookup.from_config(self.config.get(self.section,'blacklistconfig'))
        if self.tldmagic is None:
            self.tldmagic=domainmagic.tld.TLDMagic()

        urls=suspect.get_tag('body.uris',defaultvalue=[])
        #self.logger.info("Body URIs to check: %s"%urls)
        domains=set(map(domainmagic.extractor.domain_from_uri,urls))
        
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
                for identifier,humanreadable in listings.iteritems():
                    self.logger.info("%s : url host %s flagged as %s because %s"%(suspect.id,domain,identifier,humanreadable))
                    return string_to_actioncode(self.config.get(self.section,'action'), self.config),apply_template(self.config.get(self.section,'message'), suspect, dict(domain=domain,blacklist=identifier))
    
        return DUNNO
    
    
    def lint(self):
        if not DOMAINMAGIC_AVAILABLE:
            print "domainmagic lib or one of it's dependencies(dnspython/pygeoip) is not installed!"
            return False
        
        return self.checkConfig()        


######## TESTS ##############
class URIExtractTest(unittest.TestCase):
    def setUp(self):
        section="URIExtract"
        
        tlds="com net org\n .co.uk ch ru"
        open('/tmp/tld.txt','w').write(tlds)
        
        skiplist="skipme.com meetoo.com"
        open('/tmp/domainskiplist.txt','w').write(skiplist)
        
        
        config=RawConfigParser()
        config.add_section(section)
        config.set(section, 'tldfiles', "/tmp/tld.txt")
        config.set(section, 'domainskiplist', "/tmp/domainskiplist.txt")
        self.candidate=URIExtract(config,section)
        self.candidate._prepare()
        
    def tearDown(self):
        pass
    
    def test_simple_text(self):
        txt="""hello http://bla.com please click on <a href="www.co.uk">slashdot.org/?a=c&f=m</a> www.skipme.com www.skipmenot.com/ http://allinsurancematters.net/lurchwont/ muahahaha x.org"""
        
        uris=self.candidate.extractor.extracturis(txt)
        self.assertTrue('http://bla.com' in uris)
        self.assertTrue('www.co.uk' in uris)
        self.assertTrue('slashdot.org/?a=c&f=m' in uris)
        
        self.assertTrue('www.skipmenot.com/' in uris)
        #print " ".join(uris)
        self.assertTrue("skipme.com" not in " ".join(uris))
        
        self.assertTrue("http://allinsurancematters.net/lurchwont/" in uris)
        self.assertTrue("x.org" in uris,'rule at the end not found')
        
    def test_dotquad(self):
        txt="""click on 1.2.3.4 or http://62.2.17.61/ or https://8.8.8.8/bla.com """
        
        uris=self.candidate.extractor.extracturis(txt)
        self.assertTrue('1.2.3.4' in uris)
        self.assertTrue('http://62.2.17.61/' in uris)
        self.assertTrue('https://8.8.8.8/bla.com' in uris)
        
    def test_uppercase(self):
        txt="""hello http://BLa.com please click"""
        uris=self.candidate.extractor.extracturis(txt)
        self.assertTrue('http://bla.com' not in uris,'uris should not be lowercased')
        self.assertTrue('http://BLa.com' in uris,'uri with uppercase not found')
        
    def test_url_without_file(self):
        txt="""lol http://roasty.familyhealingassist.ru?coil&commission blubb"""
        uris=self.candidate.extractor.extracturis(txt)
        self.assertTrue('http://roasty.familyhealingassist.ru?coil&commission' in uris,'did not find uri, result was %s'%uris)
        
# TEST : postcat-eml.sh testdata/03E49500578 | plugdummy.py -p ~/workspace/fuglu-plugins-cm/extractors/ -e - uriextract.URIExtract uriextract.DomainAction 