from fuglu.shared import Suspect,ScannerPlugin,actioncode_to_string,apply_template, DEFER,DUNNO,SuspectFilter

import time
import os
import mailbox

class LDAPlugin(ScannerPlugin):
    """Deliver message to maildir / mbox"""
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        
        self.requiredvars={
            'path':{
                'default':'/usr/local/fuglu/deliver/${to_address}',
                'description':'Path to maildir / mbox file, supports templates',
            },
            #maybe we need to support our own locking later, for now we use python's built-ins
            #'locktype':{ 
            #    'default':'',
            #    'description':"flock, ...",
            #},
            'boxtype':{
                'default':'mbox',
                'description':"mbox, maildir",
            },
            #maybe we need to support various mbox types later, for now we use python's built-in module
            #'subtype':{
            #    'default':'',
            #    'description':"what type of mbox... ",
            #},
            'filterfile':{
                'default':'',
                'description':"only store messages which use filter...",
            },
                           
        }
        self.logger=self._logger()
        self.filter=None
        
        self.boxtypemap={
         'mbox':self.deliver_mbox,
         'maildir':self.deliver_maildir,               
        }
        
    def lint(self):
        allok=self.checkConfig()
        
        filterfile=self.config.get(self.section, 'filterfile','').strip()
        
        if filterfile!='' and not os.path.exists(filterfile):
            print 'LDA filter rules file does not exist : %s'%filterfile
            allok=False
        
        boxtype=self.config.get(self.section, 'boxtype')
        if boxtype not in self.boxtypemap:
            print "Unsupported boxtype: %s"%boxtype
            allok=False
        
        return allok

        
    def examine(self,suspect):
        starttime=time.time()
        
        filterfile=self.config.get(self.section, 'filterfile','').strip()
        
        if self.filter==None:
            if filterfile!='': 
                if not os.path.exists(filterfile):
                    self._logger().warning('LDA filter rules file does not exist : %s'%filterfile)
                    return DEFER
                self.filter=SuspectFilter(filterfile)
        
        if self.filter!=None:
            match=self.filter.matches(suspect)
            if not match:
                return DUNNO
        
        self.boxtypemap[self.config.get(self.section, 'boxtype')](suspect)
        
        #For debugging, its good to know how long each plugin took
        endtime=time.time()
        difftime=endtime-starttime
        suspect.tags['LDAPlugin.time']="%.4f"%difftime

    def deliver_mbox(self,suspect):
        mbox_msg=mailbox.mboxMessage(suspect.get_message_rep())
        mbox_path=apply_template(self.config.get(self.section,'path'), suspect)
        mbox=mailbox.mbox( mbox_path)
        try:
            mbox.lock()
            mbox.add(mbox_msg)
            mbox.flush()
        except Exception,e:
            self.logger.error("Could not store message %s to %s: %s"%(suspect.id,mbox_path,str(e)))
        finally:
            mbox.unlock()
    
    def deliver_maildir(self,suspect):
        md_msg=mailbox.MaildirMessage(suspect.get_message_rep())
        md_path=apply_template(self.config.get(self.section,'path'), suspect)
        if os.path.isfile(md_path):
            self.logger.error("%s seems to be a file - can not use as maildir"%md_path)
            return
        
        maildir=mailbox.Maildir(md_path)
        try:
            maildir.lock()
            maildir.add(md_msg)
            maildir.flush()
        except Exception,e:
            self.logger.error("Could not store message %s to %s: %s"%(suspect.id,md_path,str(e)))
        finally:
            maildir.unlock()
    
        