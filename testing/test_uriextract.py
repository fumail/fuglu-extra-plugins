# -*- coding: utf-8 -*-

import unittest
import logging
import sys
from io import BytesIO

from uriextract.uriextract import URIExtract, EmailExtract
from testing.storedmails import mail_html, mail_base64
from fuglu.shared import Suspect
import email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

try:
    from unittest.mock import patch, mock_open
    from unittest.mock import MagicMock
except ImportError:
    from mock import patch, mock_open
    from mock import MagicMock

try:
    #py2
    import ConfigParser
except ImportError:
    #py3
    import configparser as ConfigParser

def setup_module():
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)


class URIExtractTest(unittest.TestCase):
    def setUp(self):
        section="URIExtract"
        
        tlds="com net org\n .co.uk ch ru"
        open('/tmp/tld.txt','w').write(tlds)
        
        skiplist="skipme.com meetoo.com"
        open('/tmp/domainskiplist.txt','w').write(skiplist)
        
        
        config=ConfigParser.RawConfigParser()
        config.add_section(section)
        config.set(section, 'tldfiles', "/tmp/tld.txt")
        config.set(section, 'domainskiplist', "/tmp/domainskiplist.txt")
        config.set(section, 'maxsize', 10485000)
        config.set(section, 'loguris', 'no')
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
        #print(" ".join(uris))
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

    def test_withSuspect_TE(self):
        """Test using suspect, link is in the base64 transfer encoded part"""
        myclass = self.__class__.__name__
        functionNameAsString = sys._getframe().f_code.co_name
        loggername = "%s.%s" % (myclass,functionNameAsString)
        logger = logging.getLogger(loggername)

        logger.debug("Read file content")
        filecontent = BytesIO(mail_base64).read()

        logger.debug("Create suspect")
        suspect = Suspect("auth@aaaaaa.aa","rec@aaaaaaa.aa","/dev/null")
        suspect.set_source(filecontent)

        logger.debug("examine suspect")
        self.candidate.examine(suspect)

        uris = suspect.get_tag('body.uris')
        logger.debug('uris: '+",".join(uris))

        self.assertTrue('www.co.uk' in uris)

    def test_unquoted_link(self):
        """Test unquoted href attribute"""
        txt="""hello  <a href=www.co.uk>slashdot.org/?a=c&f=m</a> """

        uris=self.candidate.extractor.extracturis(txt)
        self.assertTrue('www.co.uk' in uris)
        self.assertTrue('slashdot.org/?a=c&f=m' in uris)

    def test_withSuspect(self):
        """Test unquoted href attribute in html part of mail"""
        myclass = self.__class__.__name__
        functionNameAsString = sys._getframe().f_code.co_name
        loggername = "%s.%s" % (myclass,functionNameAsString)
        logger = logging.getLogger(loggername)

        logger.debug("Read file content")
        filecontent = BytesIO(mail_html).read()

        logger.debug("Create suspect")
        suspect = Suspect("auth@aaaaaa.aa","rec@aaaaaaa.aa","/dev/null")
        suspect.set_source(filecontent)

        logger.debug("examine suspect")
        self.candidate.examine(suspect)

        uris = suspect.get_tag('body.uris')
        logger.debug('uris: '+",".join(uris))
        self.assertTrue( "http://toBeDetected.com.br/Jul2018/En/Statement/Invoice-DDDDDDDDD-DDDDDD/" in uris)


    def test_withSuspect_newDecode(self):
        """Test if new version of URIExtract gives same result as old one"""
        myclass = self.__class__.__name__
        functionNameAsString = sys._getframe().f_code.co_name
        loggername = "%s.%s" % (myclass,functionNameAsString)
        logger = logging.getLogger(loggername)

        logger.debug("Read file content")
        filecontent = BytesIO(mail_html).read()

        logger.debug("Create suspect")
        suspect = Suspect("auth@aaaaaa.aa","rec@aaaaaaa.aa","/dev/null")
        suspect.set_source(filecontent)

        textparts_deprecated = self.candidate.get_decoded_textparts_deprecated(suspect)
        textparts            = self.candidate.get_decoded_textparts(suspect,bcompatible=False)

        self.assertEqual(textparts_deprecated,textparts)

class EmailExtractTest(unittest.TestCase):
    """Test email address extraction"""

    def setUp(self):
        section="EmailExtract"

        tlds="com net org\n .co.uk ch ru"
        open('/tmp/tld.txt','w').write(tlds)

        skiplist="skipme.com meetoo.com"
        open('/tmp/domainskiplist.txt','w').write(skiplist)


        config=ConfigParser.RawConfigParser()
        config.add_section(section)
        config.set(section, 'tldfiles', "/tmp/tld.txt")
        config.set(section, 'domainskiplist', "/tmp/domainskiplist.txt")
        config.set(section, 'maxsize', 10485000)
        config.set(section, 'loguris', 'no')

        config.set(section, 'headers', 'Return-Path,Reply-To,From,X-RocketYMMF,X-Original-Sender,Sender,X-Originating-Email,Envelope-From,Disposition-Notification-To')
        config.set(section, 'skipheaders', 'X-Original-To,Delivered-To,X-Delivered-To,Apparently-To,X-Apparently-To')

        self.candidate=EmailExtract(config,section)
        self.candidate._prepare()

    def test_withSuspect(self):
        """Test email address extraction"""

        # for testing, collect all addresses that should be found
        address2befound = []

        # me == my email address
        # you == recipient's email address
        me = "my@tobefound.com"
        address2befound.append(me)

        you = "your@tobeskipped.com"

        # Create message container - the correct MIME type is multipart/alternative.
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "mail address"
        msg['From'] = me
        msg['To'] = you

        # Create the body of the message (a plain-text and an HTML version).
        addr = "webmaster@findmeintext.com"
        address2befound.append(addr)
        text = "Hi!\nHow are you?\nHere is the link you wanted:\n" \
               "https://www.python.org\nAnd here's the address:\n%s."%addr

        addr = "webmaster@findmeinhtml.com"
        html = u"""\                                                                                     
        <html>                                                                                           
          <head></head>                                                                                  
          <body>                                                                                         
            <p>Hi!<br>                                                                                   
               How are you?<br>                                                                          
               Here is the <a href="https://www.python.org">link</a> you wanted.<br>       
               And here's the <a href="mailto:%s"> mail address</a>.<br>
            </p>                                                                                         
          </body>                                                                                        
        </html>                                                                                          
        """%addr
        address2befound.append(addr)

        # Record the MIME types of both parts - text/plain and text/html.
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html',_charset="UTF-8")

        msg.attach(part1)
        msg.attach(part2)

        headerlist = ['Return-Path', 'Reply-To', 'From', 'X-RocketYMMF', 'X-Original-Sender', 'Sender',
                      'X-Originating-Email', 'Envelope-From', 'Disposition-Notification-To']
        for hdr in headerlist:
            addr = hdr.lower()+"@tobefound.com"
            msg[hdr] = addr
            address2befound.append(addr)
            print("New/changed header to be found %s: %s"%(hdr,msg[hdr]))

        skipheaderlist = ['X-Original-To', 'Delivered-To', 'X-Delivered-To,' 'Apparently-To', 'X-Apparently-To']
        for hdr in skipheaderlist:
            msg[hdr] = hdr.lower()+"@tobeskipped.com"
            print("New/changed header to be skipped %s: %s"%(hdr,msg[hdr]))

        print("Create suspect")
        suspect = Suspect("auth@aaaaaa.aa","rec@aaaaaaa.aa","/dev/null")

        try:
            suspect.set_source(msg.as_bytes())
        except AttributeError:
            suspect.set_source(msg.as_string())

        print("Examine suspect")
        self.candidate.examine(suspect)

        emailaddresses = suspect.get_tag('emails')
        print('email addresses found: '+",".join(emailaddresses))

        missing = []
        for addr in address2befound:
            if addr in emailaddresses:
                print("Found: %s"%addr)
            else:
                print("DID NOT FIND: %s"%addr)
                missing.append(addr)

        over = []
        for addr in emailaddresses:
            if addr not in address2befound:
                print("DID FIND ADDRESS WHICH SHOULD NOT BE FOUND: %s"%addr)
                over.append(addr)

        self.assertEqual(0,len(missing),"Not all mail addresses detected! Missing:\n[%s]\n\n"%", ".join(missing))
        self.assertEqual(0,len(over),"Found addresses that should be skipped! List is:\n[%s]\n\n"%", ".join(over))

