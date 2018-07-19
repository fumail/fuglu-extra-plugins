# -*- coding: utf-8 -*-

import unittest
import logging
import sys
from io import BytesIO

from uriextract.uriextract import URIExtract
from testing.storedmails import mail_html, mail_base64
from fuglu.shared import Suspect

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

    #--                                        --#
    #- CURRENTLY FAILING BACAUSE OF DOMAINMAGIC -#
    #--                                        --#

    # def test_unquoted_link(self):
    #     """Test unquoted href attribute"""
    #     txt="""hello  <a href=www.co.uk>slashdot.org/?a=c&f=m</a> """
    #
    #     uris=self.candidate.extractor.extracturis(txt)
    #     self.assertTrue('www.co.uk' in uris)
    #     self.assertTrue('slashdot.org/?a=c&f=m' in uris)
    #
    # def test_withSuspect(self):
    #     """Test unquoted href attribute in html part of mail"""
    #     myclass = self.__class__.__name__
    #     functionNameAsString = sys._getframe().f_code.co_name
    #     loggername = "%s.%s" % (myclass,functionNameAsString)
    #     logger = logging.getLogger(loggername)
    #
    #     logger.debug("Read file content")
    #     filecontent = BytesIO(mail_html).read()
    #
    #     logger.debug("Create suspect")
    #     suspect = Suspect("auth@aaaaaa.aa","rec@aaaaaaa.aa","/dev/null")
    #     suspect.set_source(filecontent)
    #
    #     logger.debug("examine suspect")
    #     self.candidate.examine(suspect)
    #
    #     uris = suspect.get_tag('body.uris')
    #     logger.debug('uris: '+",".join(uris))
    #

