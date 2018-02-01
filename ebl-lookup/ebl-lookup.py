# -*- coding: UTF-8 -*-
from fuglu.shared import ScannerPlugin, DUNNO, string_to_actioncode, apply_template, FileList
from fuglu.extensions.dnsquery import lookup, HAVE_DNS
import re
import hashlib



class EBLLookup(ScannerPlugin):
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()
        
        self.whitelist = None
        
        self.requiredvars={
            'whitelist_file':{
                'default':'/etc/fuglu/conf.d/ebl-whitelist.txt',
                'description':'path to file containing whitelisted sender domains',
            },
            'dnszone':{
                'default':'ebl.msbl.org',
                'description':'the DNS zone to query. defaults to ebl.msbl.org',
            },
            'hash': {
                'default':'sha1',
                'description':'hash function used by DNS zone. Use one of md5, sha1, sha224, sha256, sha384, sha512'
            },
            'response':{
                'default':'127.0.0.2',
                'description':'expected response of zone query',
            },
            'action':{
                'default':'dunno',
                'description':'action on hit (dunno, reject, defer, delete). if set to dunno will tag as spam. do not use reject/defer in after queue mode',
            },
            'messagetemplate':{
                'default':'${sender} listed by ${dnszone} : ${message}',
                'description':'reject message template',
            },
            'maxlookups':{
                'default':'10',
                'description':'maximum number of email addresses to check per message',
            },
            'check_always':{
                'default':'False',
                'description':'set to True to check every suspect. set to False to only check mail that has not yet been classified as spam or virus',
            },
        }


    
    def _is_whitelisted(self, from_domain):
        whitelist_file = self.config.get(self.section,'whitelist_file')
        if whitelist_file == '':
            return False
        
        if self.whitelist is None:
            self.whitelist = FileList(whitelist_file,lowercase=True)
        
        whitelisted = False
        if from_domain in self.whitelist.get_list():
            whitelisted = True
            
        return whitelisted
        
        
        
    def _email_normalise(self, address):
        if not '@' in address:
            self.logger.error('Not an email address: %s' % address)
            return address
        
        address = address.lower()
        
        lhs, domain = address.split('@',1)
        domainparts = domain.split('.')
        
        if 'googlemail' in domainparts: # replace googlemail with gmail
            tld = domainparts.split('.', 1)
            domainparts = 'gmail.%s' % tld
        
        if '+' in lhs: # strip all '+' tags
            lhs = lhs.split('+')[0]
            
        if 'gmail' in domainparts: # discard periods in gmail
            lhs = lhs.replace('.', '')
            
        if 'yahoo' in domainparts or 'ymail' in domainparts: # strip - tags from yahoo
            lhs = lhs.split('-')[0]
            
        lhs = re.sub('^(envelope-from|id|r|receiver)=', '', lhs) # strip mail log prefixes
            
        return '%s@%s' % (lhs, domain)
    
    
    
    def _create_hash(self, value):
        hashtype = self.config.get(self.section,'hash').lower()
        if hashtype in hashlib.algorithms:
            hasher = getattr(hashlib, hashtype)
            myhash = hasher(value).hexdigest()
        else:
            myhash = ''
        return myhash
    
    
    
    def _ebl_lookup(self, addr_hash):
        listed = False
        message = None
        
        dnszone = self.config.get(self.section,'dnszone')
        response = self.config.get(self.section,'response')
        query = '%s.%s' % (addr_hash, dnszone)
        result = lookup(query)
        if result is not None:
            for rec in result:
                if rec == response:
                    listed = True
                    result = lookup(query, qtype='TXT')
                    if result:
                        message = result[0]
                    break
                
        return listed, message
    
    
    
    def examine(self, suspect):
        if not HAVE_DNS:
            return DUNNO
        
        if not self.config.getboolean(self.section,'check_always'):
            # save the lookup if mail is already tagged as virus or spam
            if suspect.is_virus() or suspect.is_spam() or suspect.is_blocked():
                return DUNNO
        
        maxlookups = self.config.getint(self.section, 'maxlookups')
        emails = suspect.get_tag('emails',defaultvalue=[])[:maxlookups]
        emails = [self._email_normalise(email) for email in emails]
        emails = list(set(emails))
        
        #if emails:
        #    self.logger.debug('%s EBL checking addresses %s' % (suspect.id, ', '.join(emails)))
        
        listed = False
        action = DUNNO
        message = None
        email = None
        for email in emails:
            addr_hash = self._create_hash(email)
            listed, message = self._ebl_lookup(addr_hash)
            if listed:
                break

        suspect.tags['spam']['EBL'] = listed
        
        if listed:
            self.logger.debug('%s EBL hit for %s' % (suspect.id, email))
            action = string_to_actioncode(self.config.get(self.section, 'action'))
            suspect.tags['EBL.email'] = email
            suspect.tags['EBL.reason'] = message
            if action != DUNNO:
                values = {
                    'dnszone': self.config.get(self.section,'dnszone'),
                    'message': message,
                }
                message = apply_template(self.config.get(self.section,'messagetemplate'),suspect, values)
        
        return action, message
    
    
    
    def lint(self):
        dnszone = self.config.get(self.section,'dnszone')
        print('querying zone %s' % dnszone)
        
        lint_ok = True
        if not self.checkConfig():
            print('Error checking config')
            lint_ok = False
            
        if not HAVE_DNS:
            print("no DNS resolver library available - this plugin will do nothing")
            lint_ok = False
            
        hashtype = self.config.get(self.section,'hash').lower()
        if hashtype not in hashlib.algorithms:
            lint_ok = False
            print('unsupported hash type %s' % hashtype)
            
        if lint_ok:
            addr_hash = self._create_hash('noemail@example.com')
            listed, message = self._ebl_lookup(addr_hash)
            if not listed:
                lint_ok = False
                print('test entry not found in dns zone')
            else:
                print('test entry found in dns zone: %s' % message)
            
        if lint_ok:
            whitelist_file = self.config.get(self.section,'whitelist_file')
            if whitelist_file.strip() == '':
                print('No whitelist defined')
                
        return lint_ok