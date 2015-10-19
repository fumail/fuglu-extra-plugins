import time
from threading import Lock
from fuglu.shared import ScannerPlugin,REJECT, DUNNO,DEFER, string_to_actioncode, SuspectFilter, apply_template
from fuglu.extensions.sql import ENABLED as SQLALCHEMY_AVAILABLE, get_session
import re
import os
from hashlib import md5
REDIS_AVAILABLE =  0
try:
    import redis
    REDIS_AVAILABLE = 1
except ImportError:
    pass


AVAILABLE_RATELIMIT_BACKENDS={}

class RollingWindowBackend(object):
    def __init__(self,backendconfig):
        self._real_init(backendconfig)

    def check_count(self,eventname,timediff):
        """record a event. Returns the current count"""
        now=self.add(eventname)
        then=now-timediff
        self.clear(eventname,then)
        count = self.count(eventname)
        return count

    def check_allowed(self,eventname,timediff,limit):
        count = self.check_count(eventname,timediff)
        return count<=limit

    def add(self,eventname):
        """add a tick to the event and return its timestamp"""
        now=time.time()
        self._real_add(eventname,now)
        return now

    def clear(self,eventname,abstime=None):
        """clear events before abstime in secs. if abstime is not provided, clears the whole queue"""
        if abstime==None:
            abstime=int(time.time())
        self._real_clear(eventname,abstime)

    def count(self,eventname):
        """return the current number of events in the queue"""
        return self._real_count(eventname)

    ## -- override these in other backends

    def _real_init(self,config):
        self.memdict={}
        self.lock = Lock()

    def _real_add(self,eventname,timestamp): #override this!
        self.lock.acquire()
        if eventname in self.memdict:
            self.memdict[eventname].append(timestamp)
        else:
            self.memdict[eventname]=[timestamp,]
        self.lock.release()

    def _real_clear(self,eventname,abstime):
        if eventname not in self.memdict:
            return
        self.lock.acquire()
        try:
            while self.memdict[eventname][0]<abstime:
                del self.memdict[eventname][0]
        except IndexError: #empty list, remove
            del self.memdict[eventname]

        self.lock.release()

    def _real_count(self,eventname):
        self.lock.acquire()
        try:
            count = len(self.memdict[eventname])
        except KeyError:
            count = 0
        self.lock.release()
        return count

AVAILABLE_RATELIMIT_BACKENDS['memory']=RollingWindowBackend

if REDIS_AVAILABLE:
    class RedisBackend(RollingWindowBackend): # TODO
        def _fix_eventname(self,eventname):
            if len(eventname)>255:
                eventname = md5(eventname).hexdigest()
            return eventname

        def _real_init(self,backendconfig):
            parts = backendconfig.split(':')
            host = parts[0]
            if len(parts)>1:
                port = int(parts[1])
            else:
                port = 6379
            if len(parts)>2:
                db = int(parts[2])
            else:
                db = 0
            self.redis = redis.StrictRedis(host=host,port=port,db=db)

        def _real_add(self,eventname,timestamp):
            self.redis.zadd(self._fix_eventname(eventname), timestamp, timestamp)

        def _real_clear(self,eventname,abstime):
            self.redis.zremrangebyscore(self._fix_eventname(eventname), '-inf', abstime)

        def _real_count(self,eventname):
            return self.redis.zcard(self._fix_eventname(eventname))

    AVAILABLE_RATELIMIT_BACKENDS['redis']=RedisBackend

if SQLALCHEMY_AVAILABLE:
    from sqlalchemy import Table, Column, TEXT, TIMESTAMP, Integer, String, MetaData, ForeignKey, Unicode, Boolean, DateTime, select,BigInteger, Index
    from sqlalchemy.sql import and_
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import mapper, relation, column_property, object_session
    DeclarativeBase = declarative_base()
    metadata = DeclarativeBase.metadata

    class Event(object):
        def __init__(self):
            self.eventname = None
            self.occurence = None

    ratelimit_table = Table("fuglu_ratelimit", metadata,
                           Column('id', BigInteger, primary_key=True),
                           Column('eventname', Unicode(255), nullable=False),
                           Column('occurence', Integer, nullable=False),
                            Index('udx_ev_oc', 'eventname', 'occurence'),
                           )
    ratelimit_mapper = mapper(Event, ratelimit_table)



    class SQLAlchemyBackend(RollingWindowBackend):
        def _fix_eventname(self,eventname):
            if type(eventname)!=unicode:
                eventname=unicode(eventname)
            if len(eventname)>255:
                eventname = unicode(md5(eventname).hexdigest())
            return eventname

        def _real_init(self,backendconfig):
            self.session = get_session(backendconfig)
            metadata.create_all(bind=self.session.bind)

        def _real_add(self,eventname,timestamp):
            ev = Event()
            ev.eventname = self._fix_eventname(eventname)
            ev.occurence = int(timestamp)
            self.session.add(ev)
            self.session.flush()

        def _real_clear(self,eventname,abstime):
            eventname = self._fix_eventname(eventname)
            self.session.query(Event).filter(and_(Event.eventname==eventname, Event.occurence < abstime)).delete()
            self.session.flush()

        def _real_count(self,eventname):
            eventname = self._fix_eventname(eventname)
            result = self.session.query(Event).filter(Event.eventname == eventname).count()
            return result

    AVAILABLE_RATELIMIT_BACKENDS['sqlalchemy']=SQLAlchemyBackend

class Limiter(object):
    def __init__(self):
        self.name = None
        self.max = -1 # negative value: no limit
        self.timespan = 1
        self.fields=[]
        self.regex = None
        self.skip = None
        self.action = DUNNO
        self.message = 'Limit exceeded'


class RateLimitPlugin(ScannerPlugin):
    def __init__(self, config, section=None):
        ScannerPlugin.__init__(self, config, section)
        self.requiredvars = {

            'limiterfile': {
                'default': '/etc/fuglu/ratelimit.conf',
                'description': 'file based rate limits',
            },

            'backendtype':{
                'default': 'memory',
                'description': 'type of backend where the events are stored. memory is only recommended for low traffic standalone systems. alternatives are: redis, sqlalchemy'
            },

            'backendconfig':{
                'default': '',
                'description': 'backend specific configuration. sqlalchemy: the database url, redis: hostname:port:db'
            }

        }

        self.logger = self._logger()
        self.backend_instance = None
        self.limiters = None
        self.filter = SuspectFilter(None)

    #TODO: make action and message optional
    def load_limiter_config(self,text):
        patt = re.compile(r'^limit\s+name=(?P<name>[^\s]+)\s+rate=(?P<max>\-?\d+)\/(?P<time>\d+)\s+fields=(?P<fieldlist>[^\s]+)(\s+match=\/(?P<matchregex>.+)\/(\s+skip=(?P<skiplist>[^\s]+))?)?\s+action=(?P<action>[^\s]+)\s+message=(?P<message>.*)$')
        limiters = []
        lineno=0
        for line in text.split('\n'):
            lineno+=1
            line=line.strip()
            if line.startswith('#') or line.strip()=='':
                continue
            match= patt.match(line)
            if match == None:
                self.logger.error('cannot parse limiter config line %s'%lineno)
                continue
            gdict = match.groupdict()
            limiter = Limiter()
            limiter.name = gdict['name']
            limiter.max = int(gdict['max'])
            limiter.timespan = int(gdict['time'])
            limiter.fields = gdict['fieldlist'].split(',')
            limiter.regex = gdict['matchregex']
            if gdict['skiplist']!=None:
                limiter.skip = gdict['skiplist'].split(',')
            action = string_to_actioncode(gdict['action'])
            if action == None:
                self.logger.error("Limiter config line %s : invalid action %s"%(lineno,gdict['action']))
            limiter.action=action
            limiter.message=gdict['message']
            limiters.append(limiter)
        return limiters


    def examine(self,suspect):
        if self.limiters==None:
            filename=self.config.get(self.section,'limiterfile')
            if not os.path.exists(filename):
                self.logger.error("Limiter config file %s not found"%filename)
                return
            limiterconfig = open(filename,'r').read()
            limiters = self.load_limiter_config(limiterconfig)
            self.limiters = limiters
            self.logger.info("Found %s limiter configurations"%(len(limiters)))

        if self.backend_instance == None:
            btype = self.config.get(self.section,'backendtype')
            if btype not in AVAILABLE_RATELIMIT_BACKENDS:
                self.logger.error('ratelimit backend %s not available'%(btype))
                return
            self.backend_instance = AVAILABLE_RATELIMIT_BACKENDS[btype](self.config.get(self.section,'backendconfig'))


        skiplist = []
        for limiter in self.limiters:
            if limiter.name in skiplist: # check if this limiter is skipped by a previous one
                self.logger.debug('filter %s skipped due to previous match'%limiter.name)
                continue

            #get field values
            allfieldsavailable=True
            fieldvalues=[]
            for fieldname in limiter.fields:
                values = self.filter.get_field(suspect,fieldname)
                if len(values)<1:
                    allfieldsavailable = False
                    self.logger.debug('Skipping limiter %s - field %s not available'%(limiter.name,fieldname))
                    break
                fieldvalues.append(values[0])
            if not allfieldsavailable: #rate limit can not be applied
                continue

            checkval = ','.join(fieldvalues)
            if limiter.regex != None:
                if re.match(limiter.regex,checkval):
                    if limiter.skip != None:
                        skiplist.extend(limiter.skip)
                else: #no match, skip this limiter
                    self.logger.debug('Skipping limiter %s - regex does not match'%(limiter.name))
                    continue

            eventname = limiter.name+checkval
            timespan = limiter.timespan
            max = limiter.max
            if max < 0: #no limit
                continue
            event_count = self.backend_instance.check_count(eventname,timespan)
            self.logger.debug("Limiter event %s  count: %s"%(eventname,event_count))
            if event_count>max:
                return limiter.action, apply_template( limiter.message, suspect)

