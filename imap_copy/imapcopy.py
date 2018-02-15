# -*- coding: UTF-8 -*-
from fuglu.shared import ScannerPlugin,DUNNO,SuspectFilter
import os
import sys
import imaplib

if sys.version_info[0] == 2:
    from urlparse import urlparse
if sys.version_info[0] >= 3:
    from urllib import parse as urlparse


#TODO: reuse imap connections
#TODO: starttls support. (if port=143 and imaps)
#TODO: 'problemaction', retries
#TODO: appender

class IMAPCopyPlugin(ScannerPlugin):
    """This plugins stores a copy of the message to an IMAP mailbox if it matches certain criteria (Suspect Filter).
The rulefile works similar to the archive plugin. As third column you have to provide imap account data in the form:

<protocol>://<username>:<password>@<servernameorip>[:port]/<mailbox>

<protocol> is either imap or imaps


"""
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        
        self.requiredvars={
            'imapcopyrules':{
                'default':'/etc/fuglu/imapcopy.regex',
                'description':'IMAP copy suspectFilter File',
            },
            'storeoriginal':{
                'default':'1',
                'description':"if true/1/yes: store original message\nif false/0/no: store message probably altered by previous plugins, eg with spamassassin headers",
            }
        }
        self.filter=None
        self.logger=self._logger()

        
    def examine(self,suspect):
        imapcopyrules=self.config.get(self.section, 'imapcopyrules')
        if imapcopyrules is None or imapcopyrules=="":
            return DUNNO
        
        if not os.path.exists(imapcopyrules):
            self._logger().error('IMAP copy rules file does not exist : %s'%imapcopyrules)
            return DUNNO
        
        if self.filter is None:
            self.filter=SuspectFilter(imapcopyrules)
        
        (match,info)=self.filter.matches(suspect,extended=True)
        if match:
            field,matchedvalue,arg,regex=info
            if arg is not None and arg.lower()=='no':
                suspect.debug("Suspect matches imap copy exception rule")
                self.logger.info("""%s: Header %s matches imap copy exception rule '%s' """%(suspect.id,field,regex))
            else:
                if arg is None or (not arg.lower().startswith('imap')):
                    self.logger.error("Unknown target format '%s' should be 'imap(s)://user:pass@host/folder'"%arg)
                    
                else:
                    self.logger.info("""%s: Header %s matches imap copy rule '%s' """%(suspect.id,field,regex))
                    if suspect.get_tag('debug'):
                        suspect.debug("Suspect matches imap copy rule (I would  copy it if we weren't in debug mode)")
                    else:
                        self.storeimap(suspect,arg)
        else:
            suspect.debug("No imap copy rule/exception rule applies to this message")

    
    def imapconnect(self,imapurl,lintmode=False):
        p=urlparse(imapurl)
        scheme=p.scheme.lower()
        host=p.hostname
        port=p.port
        username=p.username
        password=p.password
        folder=p.path[1:]
        
        if scheme=='imaps':
            ssl=True
        else:
            ssl=False
        
        
        if port is None:
            if ssl:
                port=imaplib.IMAP4_SSL_PORT
            else:
                port=imaplib.IMAP4_PORT
        try:
            if ssl:
                imap=imaplib.IMAP4_SSL(host=host,port=port)
            else:
                imap=imaplib.IMAP4(host=host,port=port)
        except Exception,e:
            ltype='IMAP'
            if ssl:
                ltype='IMAP-SSL'
            msg="%s Connection to server %s failed: %s"%(ltype,host,str(e))
            if lintmode:
                print(msg)
            else:
                self.logger.error(msg)
            return None
        
        try:
            imap.login(username,password)
        except Exception,e:
            msg="Login to server %s failed: %s"%(host,str(e))
            if lintmode:
                print(msg)
            else:
                self.logger.error(msg)
            return None
        
        mtype, count = imap.select(folder)
        if mtype=='NO':
            msg="Could not select folder %s"%folder
            if lintmode:
                print(msg)
            else:
                self.logger.error(msg )
            return None
        return imap
        
    
    def storeimap(self,suspect,imapurl):
        imap=self.imapconnect(imapurl)
        if not imap:
            return
        #imap.debug=4
        p=urlparse(imapurl)
        folder=p.path[1:]
        
        if self.config.getboolean(self.section,'storeoriginal'):
            src=suspect.get_original_source()
        else:
            src=suspect.get_source()

        mtype, data = imap.append(folder,None,None,src)
        if mtype!='OK':
            self.logger.error('Could put store in IMAP. APPEND command failed: %s'%data)
        imap.logout()



    def lint(self):
        allok=(self.check_config() and self.lint_imap())
        return allok

    def lint_imap(self):
        #read file, check for all imap accounts
        imapcopyrules=self.config.get(self.section, 'imapcopyrules')
        if imapcopyrules!='' and not os.path.exists(imapcopyrules):
            print("Imap copy rules file does not exist : %s"%imapcopyrules)
            return False
        sfilter=SuspectFilter(imapcopyrules)

        accounts=[]
        for tup in sfilter.patterns:
            headername,pattern,arg = tup
            if arg not in accounts:
                if arg is None:
                    print("Rule %s %s has no imap copy target"%(headername,pattern.pattern))
                    return False
                if arg.lower()=='no':
                    continue
                accounts.append(arg)

        for acc in accounts:
            p=urlparse(acc)
            host=p.hostname
            username=p.username
            folder=p.path[1:]
            print("Checking %s@%s/%s"%(username,host,folder))
            imap=self.imapconnect(acc,lintmode=True)
            if not imap:
                print("Lint failed for this account")
                return False

        return True