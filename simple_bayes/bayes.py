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
#
from fuglu.shared import ScannerPlugin, AppenderPlugin, SuspectFilter
import time
import math
from itertools import chain
import random
import thread

from hashlib import sha1
REDIS_AVAILABLE=0
try:
    from redis import StrictRedis
    REDIS_AVAILABLE=1
except ImportError:
    pass

SUPPORTED_BACKENDS={}

class TokenStoreBase(object):
    """
    Simple memory based tokenstore
    The real implementation should overwrite all methods
    """
    def __init__(self,configstring):
        self.ham_count=0
        self.spam_count=0

        self.ham_tokens=[]
        self.spam_tokens=[]
        self.configstring=configstring


    def get_ham_count(self,token):
        """
        :param token: the token to check
        :return: the number of ham messages this token as found in
        """
        return self.ham_tokens.count(token)

    def get_spam_count(self,token):
        """
        :param token: the token to check
        :return: the number of spam messages this token as found in
        """
        return self.spam_tokens.count(token)

    def get_total_ham_count(self):
        """get the number of known ham messages"""
        return self.ham_count

    def get_total_spam_count(self):
        """get the number of known spam messages"""
        return self.spam_count

    def learn_ham(self,tokens):
        for t in set(tokens):
            self.ham_tokens.append(t)
        self.ham_count+=1

    def learn_spam(self,tokens):
        for t in set(tokens):
            self.spam_tokens.append(t)
        self.spam_count+=1

if REDIS_AVAILABLE:
    class RedisTokenStore(TokenStoreBase):

        def __init__(self,configstring):
            if configstring=='':
                self.redis=StrictRedis()
            else:
                host,port,db=configstring.split(':')
                self.redis=StrictRedis(host=host,port=port,db=int(db))
            self.token_prefix='bayes_token_'
            self.total_key='bayes_total'
            self.seen_prefix='bayes_seen_'
            self.expiration=7*24*3600 # one week
            self.recalc_totals_interval=24*3600 # once per day
            self.labels=['spam','ham']

        def recalc_totals(self):
            """from time to time we need to reduce the totals from expired messages"""
            for label in self.labels:
                kset=set()
                pattern=self.seen_prefix+label+'*'
                start,values=self.redis.scan(0,match=pattern)
                while True:
                    start,values=self.redis.scan(start,match=pattern)
                    for v in values:
                        kset.add(v)
                    if start=='0':
                        break

                oldval=self.redis.hget(self.total_key,label)
                newval=len(kset)
                self.redis.hset(self.total_key,label,newval)
                #print "%s changed from %s to %s"%(label,oldval,newval)

        def background_recalc(self):
            #maybe another host/thread already did the recalc, sleep a while before we do it ourselves
            now=int(time.time()+random.randint(1,20))
            self.redis.hset(self.total_key,'last_recalc',now)
            time.sleep(1)

            if self.redis.hget(self.total_key,'last_recalc')==now:
                self.recalc_totals()

        def get_(self,token,what):
            assert what in self.labels
            keyname=self.token_prefix+token
            count=self.redis.hget(keyname,what)
            try:
                return int(self.redis.hget(keyname,what))
            except:
                return 0

        def get_ham_count(self,token):
            return self.get_(token,'ham')

        def get_spam_count(self,token):
            return self.get_(token,'spam')

        def get_total_ham_count(self):
            """get the number of known ham messages"""
            try:
                return int(self.redis.hget(self.total_key,'ham'))
            except:
                return 0

        def get_total_spam_count(self):
            """get the number of known spam messages"""
            try:
                return int(self.redis.hget(self.total_key,'spam'))
            except:
                return 0

        def learn_(self,tokens,aswhat):
            assert aswhat in self.labels
            digest=sha1()
            pipeline=self.redis.pipeline()
            for t in set(tokens):
                keyname=self.token_prefix+t
                curcount=pipeline.hincrby(keyname,aswhat,1)
                if curcount==1: #only expire on first insert to make sure
                    pipeline.expire(keyname,self.expiration)
                digest.update(t.encode('utf-8','ignore'))
            pipeline.hincrby(self.total_key,aswhat,1)
            pipeline.set(self.seen_prefix+aswhat+'_'+digest.hexdigest(),1)
            pipeline.execute()
            if self.recalc_necessary():
                thread.start_new_thread(self.background_recalc,())

        def recalc_necessary(self):
            last_recalc=self.redis.hget(self.total_key,'last_recalc')
            if last_recalc==None:
                last_recalc=0
            last_recalc=int(last_recalc)
            return time.time()-last_recalc>self.recalc_totals_interval

        def learn_ham(self,tokens):
            self.learn_(tokens,'ham')

        def learn_spam(self,tokens):
            self.learn_(tokens,'spam')

    SUPPORTED_BACKENDS['redis']=RedisTokenStore



class BayesPlugin(object):
    def __init__(self):
        self.requiredvars = {
            'backendtype':{
                'default':'redis',
                'description': 'Token store backend type. Allowed values are: sqlalchemy , redis',
            },
            'backendconfig':{
                'default':'',
                'description': 'Backend configuration. Depends on backendtype, eg. sqlalchemy url, redis host:port:db',
            },
            'spambias':{
                'default':'0.5',
                'description': 'overall spam bias. 0.5=no bias. 0.8=around 80% of scanned mail traffic is spam',
            },
            'minimum-token-occurence':{
                'default':'3',
                'description': "don't make assumptions on tokens seen less than this amount",
            },
            'maximum-tokens-per-message':{
                'default':'5000',
                'description': 'stop tokenizing after x tokens',
            },
            'minimum-ham':{
                'default':'10',
                'description': "minimum known hams for classification",
            },
            'minimum-spam':{
                'default':'10',
                'description': "minimum known spams for classification",
            },
        }
        self.tokenstore=None
        self.calc_minimum=0.00000001 # work around division by zero etc

        self.logger=self._logger()
        self.filter=SuspectFilter(None)

    def init_backend(self):
        if self.tokenstore!=None:
            return
        backendtype=self.config.get(self.section,'backendtype')
        if backendtype not in SUPPORTED_BACKENDS:
            self.logger.error("Bayes tokenstore %s not supported, maybe misspelled or missing dependency"%backendtype)

        backend=SUPPORTED_BACKENDS[backendtype](self.config.get(self.section,'backendconfig'))
        self.tokenstore=backend


    def single_token_spam_probability(self,token):
        """Compute the probability that a message containing a given token is spam
        ( "spamicity of a word" )
        """
        total_spam=self.tokenstore.get_total_spam_count()
        if total_spam<self.config.getint(self.section,'minimum-spam'):
            self.logger.warning("Not enough known spams for bayes classification")
            return 0.5

        total_ham=self.tokenstore.get_total_ham_count()
        if total_ham<self.config.getint(self.section,'minimum-ham'):
            self.logger.warning("Not enough known hams for bayes classification")
            return 0.5

        pr_s = self.config.getfloat(self.section,'spambias') # probability that any given message is spam
        pr_h = 1-pr_s # probability that any given message is ham

        spam_count = self.tokenstore.get_spam_count(token) # number of known spams containing this token
        ham_count = self.tokenstore.get_ham_count(token) # number of known hams containing this token

        # "Dealing with rare words"
        if spam_count + ham_count<self.config.get(self.section,'minimum-token-occurence'):
            pr_s_w=0.5
        else:
            pr_w_s = float(spam_count) / total_spam #  the probability that the token appears in spam messages
            pr_w_h = float(ham_count) / total_ham #   the probability that the token appears in ham messages
            divisor=(pr_w_s *  pr_s  + pr_w_h * pr_h)
            if divisor<self.calc_minimum:
                divisor=self.calc_minimum
            pr_s_w =  pr_w_s * pr_s / divisor
        #self.logger.info("Token '%s' : seen in %s spams, %s hams => spamicity= %.4f"%(token,spam_count,ham_count,pr_s_w))
        return pr_s_w

    def spam_probability(self,suspect):
        """
        :param text:
        :return: the probability that the given text is spam. float value between 0.0 and 1.0
        """
        tokens=self.tokenize(suspect)
        self.logger.debug("Got %s tokens"%len(tokens))
        total=0
        for t in tokens:
            spamicity = self.single_token_spam_probability(t)
            if spamicity<self.calc_minimum:
                spamicity=self.calc_minimum

            #make sure we get at least a very small amount
            x=1-spamicity
            if x<self.calc_minimum:
                x=self.calc_minimum
            n = math.log(x) - math.log(spamicity)
            total+=n
        try:
            probability=1.0/(1+math.pow(math.e,total))
        except OverflowError:
            return 0.0

        return round(probability,4)

    def ngrams(self,sequence,n=3,maxnumber=None):
        sequence = list(sequence)
        count = max(0, len(sequence) - n + 1)
        if maxnumber==None:
            maxnumber=count
        return ["".join(sequence[i:i+n]) for i in range(min(count,maxnumber))]

    def tokenize(self,suspect):
        visible_texts=self.filter.get_field(suspect,'body:stripped')
        stripped=" ".join([t.strip() for t in visible_texts if t.strip()!=''])
        maxtokens=self.config.getint(self.section,'maximum-tokens-per-message')
        if maxtokens==0:
            maxtokens=None
        tokens=self.ngrams(stripped,n=3,maxnumber=maxtokens)
        #self.logger.debug(tokens)
        return tokens

class BayesClassify(ScannerPlugin,BayesPlugin
):

    """Bayes Classifier - adds tag bayes.spamprobability tag"""

    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        BayesPlugin.__init__(self)

    def examine(self, suspect):
        starttime = time.time()
        self.init_backend()
        if self.tokenstore==None:
            self.logger.warn("Token backend not initialized")
            return
        probability=self.spam_probability(suspect)
        suspect.set_tag('bayes.spamprobability',probability)
        self.logger.info("%s: bayes spam probability is %s%%"%(suspect.id,probability*100))

class SAScoreBayesLearner(AppenderPlugin,BayesPlugin
):
    """Train our bayes filter based on SA score"""

    def __init__(self, config, section=None):
        AppenderPlugin.__init__(self, config, section)
        BayesPlugin.__init__(self)
        self.requiredvars['hamthreshold']={
         'default':'-1',
         'description':'messages with score below this value will be learned as ham'
        }
        self.requiredvars['spamthreshold']={
         'default':'5',
         'description':'messages with score above this value will be learned as spam'
        }


    def process(self, suspect,decisions):
        self.init_backend()
        if self.tokenstore==None:
            self.logger.warn("Token backend not initialized")
            return

        sascore=suspect.get_tag('SAPlugin.spamscore')
        if sascore==None:
            return

        sascore=float(sascore)
        hamthreshold=self.config.getfloat(self.section,'hamthreshold')
        spamthreshold=self.config.getfloat(self.section,'spamthreshold')

        if sascore<hamthreshold:
            tokens=self.tokenize(suspect)
            self.tokenstore.learn_ham(tokens)
            self.logger.info("%s: bayes: learned message as ham"%suspect.id)

        if sascore>spamthreshold:
            tokens=self.tokenize(suspect)
            self.tokenstore.learn_spam(tokens)
            self.logger.info("%s: bayes: learned message as spam"%suspect.id)
