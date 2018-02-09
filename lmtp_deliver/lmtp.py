# -*- coding: UTF-8 -*-

from fuglu.shared import ScannerPlugin, DEFER,DUNNO, string_to_actioncode
import os
import smtplib


class LMTPPlugin(ScannerPlugin):
    
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        
        self.requiredvars={
            'host':{
                'default':'localhost',
                'description':'LMTP target hostname',
            },
            'port':{
                'default':'24',
                'description':'LMTP target port',
            },
            'user':{
                'default':'',
                'description':'LMTP auth user. leave empty if no authentication is needed',
            },
            'password':{
                'default':'',
                'description':'LMTP auth password. leave empty if no authentication is needed',
            },
            'lmtpfrom':{
                'default':'user@localhost',
                'description':'LMTP envelope sender. Leave empty for original SMTP envelope sender',
            },
            'sendoriginal': {
                'default': '0',
                'description': """should we store the original message as retreived from postfix or store the
                                    current state in fuglu (which might have been altered by previous plugins)""",
            },
            'successaction':{
                'default':'DUNNO',
                'description':'what action to return after successful transfor to LMTP? DELETE or DUNNO',
            },
            
        }
        self.logger=self._logger()
    
    
    def __init_socket(self):
        host = self.config.get(self.section, 'host')
        
        if host.startswith('/'): # unix socket
            port = None
            if not os.path.exists(host):
                raise Exception("unix socket %s not found" % host)
        else: # tcp port
            try:
                port = int(self.config.get(self.section, 'port'))
            except ValueError:
                port = None # use default port
            
        s = smtplib.LMTP(host, port)
        return s
    
    
    
    def __auth(self, lmtp):
        user = self.config.get(self.section, 'user')
        password = self.config.get(self.section, 'password')
        if user and password:
            lmtp.login(user, password)
        
        
        
    def examine(self, suspect):
        if suspect.get_tag('send_lmtp') is not True:
            return DUNNO
        
        lmtpfrom = self.config.get(self.section, 'lmtpfrom')
        if not lmtpfrom:
            lmtpfrom = suspect.from_address
        
        if self.config.getboolean(self.section, 'sendoriginal'):
            content = suspect.get_original_source()
        else:
            content = suspect.get_source()
            
        try:
            lmtp = self.__init_socket()
        except Exception as e:
            self.logger.error('%s could not connect to LMTP server: %s' % (suspect.id, str(e)))
            return DEFER, 'could not connect to LMTP server'
        
        try:
            self.__auth(lmtp)
        except Exception as e:
            self.logger.error('%s could not authenticate to LMTP server: %s' % (suspect.id, str(e)))
            return DEFER, 'could not authenticate to LMTP server'
        
        try:
            errors = lmtp.sendmail(lmtpfrom, suspect.to_address, content)
            for rcpt in errors:
                self.logger.error('%s could not deliver to LMTP server for %s: %s' % (suspect.id, rcpt, errors[rcpt]))
        except Exception as e:
            self.logger.error('%s could not deliver to LMTP server: %s' % (suspect.id, str(e)))
            return DEFER, 'could not deliver to LMTP server'
        finally:
            lmtp.quit()
            
        successaction = string_to_actioncode(self.config.get(self.section, 'successaction'))
        return successaction
    
    
    
    def lint(self):
        success = self.check_config()
        
        if success:
            try:
                lmtp = self.__init_socket()
                helo = lmtp.docmd('LHLO', 'example.com')
                print('LMTP server sez: %s %s' % (helo[0], helo[1]))
                self.__auth(lmtp)
                lmtp.quit()
            except Exception as e:
                print('LMTP connection error: %s' % str(e))
                success = False
                
        return success
        
        
        
        
        