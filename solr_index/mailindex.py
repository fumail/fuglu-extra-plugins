#   Copyright 2015 Oli Schacher
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from fuglu.shared import AppenderPlugin,DELETE,DUNNO,DEFER,string_to_actioncode,apply_template

from email.Header import decode_header
import pysolr
from email.utils import getaddresses,parsedate
import datetime
import time
#we can't use cStringIO since pysolr wants a filename attribute set on while extracting which
#we can't set on cStringIO
import StringIO as strio

class MailIndex(AppenderPlugin):
    """ Extract Mail fields and pass to SOLR
"""
    def __init__(self,config,section=None):
        AppenderPlugin.__init__(self,config,section)
        self.logger=self._logger()
        self.requiredvars={
            'solrhost':{
                'default':'localhost'
            },
            'solrport':{
                'default':'8983',
            },
            'solrcollection':{
                'default':'mailarchive',
            },
            'solrtimeout':{
                'default':'10',
            },
            'solrttl':{
                'default':'',
                'description':'ttl as lucene date math expression, for example +5MONTHS , see http://lucene.apache.org/solr/4_8_0/solr-core/org/apache/solr/util/DateMathParser.html',
            },
            'index_content':{
                'default':'0',
                'description':'extract content and attachments using apache tikka',
            },
            'index_headers':{
                'default':'1',
                'description':'add the full header section to the index',
            }
        }
        self.solr=None

    def init_solr(self):
        if self.solr==None:
            url='http://%s:%s/solr/'%(self.config.get(self.section,'solrhost'),self.config.getint(self.section,'solrport'))
            collection=self.config.get(self.section,'solrcollection')
            if collection!=None and collection!='':
                url=url+collection+'/'
            self.solr = pysolr.Solr(url, timeout=self.config.getint(self.section,'solrtimeout'))



    def process(self,suspect,decisions):
        self.logger.info('analyzing...')
        msginfo=self.analyze_suspect(suspect)
        prnt=msginfo.copy()
        prnt['content_t']=prnt['content_t'][:20]+'...'
        self.logger.info('result: %s'%prnt)
        self.logger.info('Uploading...')
        result=self.store_solr(msginfo)
        self.logger.info(result)
        self.logger.info('done')
        return DUNNO


    def store_solr(self,msginfo):
        self.init_solr()
        ttl=self.config.get(self.section,'solrttl')
        if ttl!=None and ttl!='':
            msginfo['_ttl_s']=ttl
        return self.solr.add([msginfo,],commit=True)

    def analyze_suspect(self,suspect):
        self.init_solr()
        messagedata={
            'message_id_s':set(),
            'sender_ss':set(),
            'recipient_ss':set(),
            'sender_domain_ss':set(),
            'recipient_domain_ss':set(),
            'attachment_name_ss':set(),
            'subject_s':None,
            'headers_t':None,
            'content_t':None,
            'storage_id_s':suspect.id,
            'size_i':suspect.size,
            'archive_date_dt':datetime.datetime.now(),
            'send_date_dt':None,
        }


        messagedata['sender_ss'].add(suspect.from_address)
        if not suspect.from_address:
            messagedata['sender_ss'].add('<>')

        messagedata['recipient_ss'].update(suspect.recipients)
        messagedata['recipient_domain_ss'].update([self.extract_domain(e) for e in suspect.recipients])

        msgrep=suspect.get_message_rep()
        messagedata['subject_s']=self.decoded_header(msgrep,'subject')
        messagedata['message_id_s']=msgrep.get('message-id')

        messagedata['send_date_dt']=datetime.datetime.fromtimestamp(time.mktime(parsedate(msgrep.get('date'))))


        for part in msgrep.walk():
            if part.is_multipart():
                continue
            name=part.get_filename()
            if name!=None:
                messagedata['attachment_name_ss'].add(name)


        snd_headers=['from','sender','resent-from','return-path','reply-to']
        all_hdrs=set()
        for hdr in snd_headers:
            all=msgrep.get_all(hdr)
            if all!=None:
                all_hdrs.update(msgrep.get_all(hdr))
        for realname,email in getaddresses(all_hdrs):
            if realname!='':
                messagedata['sender_ss'].add(realname)
            if email!='':
                messagedata['sender_ss'].add(email)
                messagedata['sender_domain_ss'].add(self.extract_domain(email))

        all_hdrs=set()
        rec_headers=['to','cc','bcc','resent-to','resent-cc','delivered-to','envelope-to']
        for hdr in rec_headers:
            all=msgrep.get_all(hdr)
            if all!=None:
                all_hdrs.update(msgrep.get_all(hdr))
        for realname,email in getaddresses(all_hdrs):
            if realname!='':
                messagedata['recipient_ss'].add(realname)
            if email!='':
                messagedata['recipient_ss'].add(email)
                messagedata['recipient_domain_ss'].add(self.extract_domain(email))


        if self.config.getboolean(self.section,'index_headers'):
            messagedata['headers_t']=suspect.get_headers()

        if self.config.getboolean(self.section,'index_content'):
            msgcontent=strio.StringIO(suspect.get_source())
            msgcontent.name='%s.eml'%(suspect.id)
            messagedata['content_t']=self.solr.extract(msgcontent)['contents']

        return messagedata

    def decoded_header(self,msgrep,header):
        if msgrep[header] is None:
            return None
        decodefrag = decode_header(msgrep[header])
        fragments = []
        for s , enc in decodefrag:
            if enc:
                s = unicode(s , enc).encode('utf8','replace')
            fragments.append(s)
        return ''.join(fragments)


    def extract_domain(self,email):
        try:
            return email[email.rfind('@')+1:].lower()
        except:
            return None