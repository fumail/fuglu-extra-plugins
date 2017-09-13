# -*- coding: UTF-8 -*-


"""
SRS (Sender Rewriting Scheme) Plugin
This plugin encrypts envelope sender and decrypts bounce recpient addresses with SRS
As opposed to postsrsd it decides by RECIPIENT address whether sender address should be rewritten.
This plugin only works in after queue mode

Required dependencies:
    - pysrs
Recommended dependencies:
    - sqlalchemy
"""


from fuglu.shared import ScannerPlugin, DUNNO, get_default_cache
from fuglu.extensions.sql import get_session, ENABLED
import logging
try:
    import SRS
    HAVE_SRS=True
except ImportError:
    SRS=None
    HAVE_SRS=False



class SenderRewriteScheme(ScannerPlugin):

    def __init__(self, section=None):
        ScannerPlugin.__init__(self, section)
        self.logger = self._logger()

        self.requiredvars = {
            'dbconnection':{
                'default':"mysql://root@localhost/spfcheck?charset=utf8",
                'description':'SQLAlchemy Connection string. Leave empty to rewrite all senders',
            },
            
            'domain_sql_query':{
                'default':"SELECT use_srs from domain where domain_name=:domain",
                'description':'get from sql database :domain will be replaced with the actual domain name. must return field use_srs',
            },
            
            'forward_domain': {
                'default': 'example.com',
                'description': 'the new envelope sender domain',
            },
            
            'secret': {
                'default': '',
                'description': 'cryptographic secret. set the same random value on all your machines',
            },
            
            'maxage': {
                'default': '8',
                'description': 'maximum lifetime of bounces',
            },
            
            'hashlength': {
                'default': '8',
                'description': 'size of auth code',
            },
            
            'separator': {
                'default': '=',
                'description': 'SRS token separator',
            },
            
            'rewrite_header_to':{
                'default': 'True',
                'description': 'set True to rewrite address in To: header in bounce messages (reverse/decrypt mode)',
            },
        }
    
    
    
    def get_sql_setting(self, domain, dbconnection, sqlquery, cache, cachename, default_value=None, logger=None):
        if logger is None:
            logger = logging.getLogger()
        
        cachekey = '%s-%s' % (cachename, domain)
        cached = cache.get_cache(cachekey)
        if cached is not None:
            logger.debug("got cached settings for %s" % domain)
            return cached

        settings = default_value

        try:
            session = get_session(dbconnection)

            # get domain settings
            dom = session.execute(sqlquery, {'domain': domain}).fetchall()

            if not dom or not dom[0] or len(dom[0]) == 0:
                logger.debug(
                    "Can not load domain settings - domain %s not found. Using default settings." % domain)
            else:
                settings = dom[0][0]

            session.close()

        except Exception as e:
            self.logger.error("Exception while loading settings for %s : %s" % (domain, str(e)))

            cache.put_cache(cachekey, settings)
        logger.debug("refreshed settings for %s" % domain)
        return settings
    
    
    
    def should_we_rewrite_this_domain(self,suspect):
        forward_domain = self.config.get(self.section, 'forward_domain')
        if suspect.to_domain.lower() == forward_domain:
            return True # accept for decryption
        
        dbconnection = self.config.get(self.section, 'dbconnection')
        sqlquery = self.config.get(self.section, 'domain_sql_query')
               
        if dbconnection.strip()=='':
            return True # empty config -> rewrite all domains
        
        cache = get_default_cache()
        cachename = self.section
        setting = self.get_sql_setting(suspect.to_domain, dbconnection, sqlquery, cache, cachename, False, self.logger)
        return setting
    
    
    
    def _init_srs(self):
        secret = self.config.get(self.section, 'secret')
        maxage = self.config.getint(self.section, 'maxage')
        hashlength = self.config.getint(self.section, 'hashlength')
        separator = self.config.get(self.section, 'separator')
        srs = SRS.new(secret=secret, maxage=maxage, hashlength=hashlength, separator=separator, alwaysrewrite=True)
        return srs
    
    
    
    def _update_to_hdr(self, suspect, to_address):
        msgrep = suspect.getMessageRep()
        old_hdr = msgrep.get('To')
        if old_hdr and '<' in old_hdr:
            start = old_hdr.find('<')
            if start < 1:  # malformed header does not contain <> brackets
                start = old_hdr.find(':')  # start >= 0
            name = old_hdr[:start]
            new_hdr = '%s <%s>' % (name, to_address)
        else:
            new_hdr = '<%s>' % to_address
            
        msgrep['To'] = new_hdr
        suspect.set_message_rep(msgrep)
    
    
    
    def examine(self, suspect):
        if not HAVE_SRS:
            return DUNNO
        
        if not self.should_we_rewrite_this_domain(suspect):
            self.logger.info('SRS: ignoring mail to %s' % suspect.to_address)
            return DUNNO
        
        srs = self._init_srs()
        forward_domain = self.config.get(self.section, 'forward_domain').lower()
        if suspect.from_domain.lower() == forward_domain and suspect.from_address.lower().startswith('srs'):
            self.logger.info('SRS %s: skipping already signed address %s' % (suspect.id, suspect.from_address))
        elif suspect.to_domain.lower() == forward_domain and suspect.to_address.lower().startswith('srs'):
            orig_rcpt = suspect.to_address
            try:
                recipient = srs.reverse(orig_rcpt)
                suspect.to_address = recipient
                suspect.to_localpart, suspect.to_domain = recipient.split('@', 1)
                new_rcpts = [recipient if x==orig_rcpt else x for x in suspect.recipients]
                suspect.recipients = new_rcpts
                if self.config.getboolean(self.section, 'rewrite_header_to'):
                    self._update_to_hdr(suspect, recipient)
                self.logger.info('SRS: decrypted bounce address %s to %s' % (orig_rcpt, recipient))
            except Exception as e:
                self.logger.error('SRS: Failed to decrypt %s reason: %s' % (orig_rcpt, str(e)))
        else:
            orig_sender = suspect.from_address
            try:
                sender = srs.forward(orig_sender, forward_domain)
                suspect.from_address = sender
                suspect.from_localpart, suspect.from_domain = sender.split('@', 1)
                self.logger.info('SRS: signed %s to %s' % (orig_sender, sender))
            except Exception as e:
                self.logger.error('SRS: Failed to sign %s reason: %s' % (orig_sender, str(e)))
            
        del srs
        return DUNNO
    
    
    def __str__(self):
        return "Sender Rewrite Scheme"
    
    
    def lint(self):
        allok = self.checkConfig()
        if not HAVE_SRS:
            allok = False
            print 'SRS library not found'
            
        if self.config.get(self.section, 'secret') == '':
            allok = False
            print 'no secret set in config'
        
        if allok:
            srs = self._init_srs()
            forward_domain = self.config.get(self.section, 'forward_domain')
            srs.forward('foobar@example.com', forward_domain)
            
        sqlquery = self.config.get(self.section, 'domain_sql_query')
        if not sqlquery.lower().startswith('select '):
            allok = False
            print 'SQL statement must be a SELECT query'
        if not ENABLED:
            allok = False
            print 'SQLAlchemy not available, cannot use SQL backend'
        if allok:
            dbconnection = self.config.get(self.section, 'dbconnection')
            if dbconnection.strip() == '':
                print 'No DB connection defined. Disabling SQL backend, all addresses will be rewritten.'
            else:
                try:
                    conn=get_session(dbconnection)
                    conn.execute(sqlquery, {'domain':'example.com'})
                except Exception as e:
                    allok = False
                    print str(e)
            
        return allok