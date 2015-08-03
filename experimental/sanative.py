#!/usr/bin/python
# let's see how far we get in implementing Spamassassin stuff in python
import logging
import os
from pyparsing import infixNotation, opAssoc, Keyword, Word, alphas,ParseException,\
    Literal, ParseResults,Regex, oneOf, OneOrMore, ZeroOrMore
import string
import threading
import email
import re
import operator

threadlocal = threading.local()
threadlocal.evalfunc=lambda x:eval(x)

class SARuleBoolOperand(object):
    def __init__(self,t):
        self.label = t[0]
        self.hit = threadlocal.evalfunc(t[0])

    def __bool__(self):
        return self.hit
    def __str__(self):
        return str(self.label)
    def __int__(self):
        return self.intvalue
    
    __repr__ = __str__
    __nonzero__ = __bool__


class BoolBinOp(object):
    def __init__(self,t):
        self.args = t[0][0::2]
    def __str__(self):
        sep = " %s " % self.reprsymbol
        return "(" + sep.join(map(str,self.args)) + ")"
    def __bool__(self):
        return self.evalop(bool(a) for a in self.args)
    __nonzero__ = __bool__
    __repr__ = __str__

class BoolAnd(BoolBinOp):
    reprsymbol = '&&'
    evalop = all

class BoolOr(BoolBinOp):
    reprsymbol = '||'
    evalop = any

        
class BoolNot(object):
    def __init__(self,t):
        self.arg = t[0][1]
    def __bool__(self):
        v = bool(self.arg)
        return not v
    def __str__(self):
        return "!" + str(self.arg)
    __repr__ = __str__
    __nonzero__ = __bool__


class AddConstructBoolOperand(object):
    def __init__(self,t):
        self.tokens=t[0]
        self.rulenames=t[:-2]
        self.operator=t[-2]
        self.operand=t[-1]
        #print "rules=%s op=%s int=%s"%(self.rulenames,self.operator,self.operand)

    def __bool__(self):
        funcmap={
         '>=':operator.ge,
         '>':operator.gt,
        }
        hitcount=0
        for rulename in self.rulenames:
            if threadlocal.evalfunc(str(rulename)):
                hitcount+=1
                #print "rulehit for %s - hitcount is now %s"%(rulename,hitcount)
        
        return funcmap[self.operator](hitcount,int(self.operand))
    
    def __str__(self):
        return "".join(str(self.tokens))
    
    __repr__ = __str__
    __nonzero__ = __bool__

sarule = Regex('[A-Z_][A-Z_0-9]+')
sarule.setParseAction(SARuleBoolOperand)


plus=Literal('+').suppress()
greater_greaterequal=oneOf("> >=")
number=Regex('[1-9][0-9]*')
lparen=Literal('(').suppress()
rparen=Literal(')').suppress()
addconstruct_outterparen = lparen+sarule + ZeroOrMore(plus + sarule) + greater_greaterequal  + number +rparen
addconstruct_innerparen = lparen+sarule + ZeroOrMore(plus + sarule)+  rparen + greater_greaterequal  + number
addconstruct = addconstruct_outterparen |addconstruct_innerparen 
addconstruct.setParseAction(AddConstructBoolOperand)

boolOperand = sarule | addconstruct


boolExpr = infixNotation( boolOperand,
    [  
       ("!", 1, opAssoc.RIGHT, BoolNot),
    ("&&", 2, opAssoc.LEFT,  BoolAnd),
    ("||",  2, opAssoc.LEFT,  BoolOr),
    ])
boolExpr.ignore(Literal('#'))


class SARuleEvaluator(object):    
    def __init__(self,rules,msgrep):
        self.rules=rules
        self.msgrep=msgrep
        self.hitcache={}
        self.logger=logging.getLogger('pythonsa.ruleeval')
        self.metaparser=boolExpr
        
        
    def eval_real(self,rulename):
        #print "EVAL REAL: %s"%rulename
        if rulename not in self.rules:
            #self.logger.warn("""referenced rule '%s' not found""",rulename)
            return False
        return self.eval(self.rules[rulename])
    
    def run(self):
        threadlocal.evalfunc=self.eval_real
        
        for rulename,rule in self.rules.iteritems():  #TODO: rule priority und so
            result=self.eval(rule)
            
    
    def eval(self,rule):
        rulename=rule.name
        if rulename in self.hitcache:
            return self.hitcache[rulename]
        
        if rule.scores[0]==0:
            self.hitcache[rulename]=False
            return False
        
        #self.logger.debug("Eval rule: %s:%s"%(rulename,rule))
        if not hasattr(self,'_eval_%s'%rule.type):
            #self.logger.warn("unknown rule type %s"%rule.type)
            result=False
        else:
            result=getattr(self,'_eval_%s'%rule.type)(rule)
        self.hitcache[rulename]=result
        return result
    
    
    def compile_regex(self,regex):
        separator=regex[0]
        endindex=regex.rfind(separator)
        pattern=regex[1:endindex]
        flags=regex[endindex+1:]
        reflags=0
        for flag in flags:
            flag=flag.lower()
            if flag=='i':
                reflags|=re.I
            if flag=='m':
                reflags|=re.M
        return re.compile(pattern, reflags)

    def re_match(self,headername,arg):
        try:
            regex=self.compile_regex(arg)
            headervalues=self.msgrep.get_all(headername)
            if headervalues==None:
                return False
            for headervalue in headervalues:
                if re.match(regex,headervalue)!=None:
                    return True
            return False
        except Exception,e:
            self.logger.error("Could not compile regex %s: %s"%(arg,str(e)))
            return False
    
    def _eval_header(self,rule):
        #self.logger.info(rule)
        tokens=rule.definition.split(None,1)
        first=tokens[0]
        if ':' in first: #we have a special
            pass
        else:
            #headername=first
            headername,operator,arg=rule.definition.split(None,2)
            if operator=='=~':
                return self.re_match(headername, arg)
            elif operator=='!~':
                return not self.re_match(headername, arg)
            else:
                self.logger.warn("unimplemented operator :%s"%operator)
                
    def _eval_meta(self,rule):
        #print "EVAL META: %s"%rule
        try:
            res = self.metaparser.parseString(rule.definition)[0]
        except ParseException,p:
            self.logger.warn("Did not understand meta rule %s : %s"%(rule.definition,str(p)))
            return False
        #print res

class SARule(object):
    def __init__(self,name):
        self.type=None
        self.name=name
        self.tflags=[]
        self.priority=0
        self.scores=(1,1,1,1)
        if self.name.startswith('T_'):
            self.scores=(0.01,0.01,0.01,0.01)
        self.shortcircuit=None
        self.description=None
        self.definition=None

    def __repr__(self):
        return "%s %s score=%s tflags=%s"%(self.type,self.definition,self.scores,self.tflags)
        

class RuleConfig(object):
    def __init__(self):
        self.rules={}
        self.logger=logging.getLogger('pythonsa.ruleconfig')
        self.current_root='.'
        self.files_loaded=[]
        self.ifstack=[]

    def load_plugin(self,pluginname):
        pass
    
    def load_pre(self,filename):
        pass
    

    def get_rule(self,name):
        if name not in self.rules:
            return None
        return self.rules[name]
    
    def make_rule(self,name):
        rule=SARule(name)
        self.rules[name]=rule
        return rule        
    
    def load_cf(self,filename):
        if filename in self.files_loaded:
            self.logger.warn("Circular file inclusion: %s"%filename)
            return
        self.files_loaded.append(filename)
        
        lines=open(filename,'r').readlines()
        for line in lines:
            line=line.strip()
            if line.startswith('#') or line=='':
                continue
            
            sp=line.split(None,1)
            if len(sp)==2:
                command,rest=sp
            else:
                command=sp[0]
                rest=''
            
            command=command.lower()
            if hasattr(self, '_load_handle_%s'%command):
                getattr(self, '_load_handle_%s'%command)(rest)
            else:
                if not self.line_disabled():
                    self.logger.debug("not implemented: %s"%command)
    
    def load(self,dirs=None):
        if dirs==None:
            dirs=['/var/lib/spamassassin/3.004000','/etc/mail/spamassassin']
        
        for d in dirs:
            absdir=os.path.abspath(d)
            self.current_root=absdir
            files_folders=os.listdir(absdir)
            files=[f for f in files_folders if os.path.isfile(os.path.join(absdir,f))]
            
            pre_files=sorted([os.path.abspath(os.path.join(absdir,f)) for f in files if f.lower().endswith('.pre')])
            cf_files=sorted([os.path.abspath(os.path.join(absdir,f)) for f in files if f.lower().endswith('.cf')])
            
            for cf_file in cf_files:
                self.load_cf(cf_file)


    def _load_handle_include(self,filename):
        if self.line_disabled():
            return
        abspath=os.path.abspath(os.path.join(self.current_root,filename))
        self.load_cf(abspath)
        
    def _load_handle_ifplugin(self,plugin):
        self.ifstack.append(False) # TODO: if plugin loaded, append True
    
    def _load_handle_if(self,definition):
        #TODO: implement if
        #self.logger.warn("if not supported yet: %s"%definition)
        self.ifstack.append(False)
    
    def _load_handle_endif(self,rest):
        try:
            p=self.ifstack.pop()
        except IndexError:
            self.logger.warn("endif without if in line: ...%s"%(rest))

    def line_disabled(self):
        for x in self.ifstack:
            if not x:
                return True
        return False
    
    def _ruledef(self,rest,type):
        if self.line_disabled():
            return
        rulename,definition=rest.split(None,1)
        rule=self.make_rule(rulename)
        rule.type=type
        rule.definition=definition
        return rule
    
    def _load_handle_header(self,rest):
        self._ruledef(rest, 'header')
    def _load_handle_body(self,rest):
        self._ruledef(rest, 'body')
    def _load_handle_rawbody(self,rest):
        self._ruledef(rest, 'rawbody')
    def _load_handle_full(self,rest):
        self._ruledef(rest, 'full')
    def _load_handle_meta(self,rest):
        self._ruledef(rest, 'meta')
    def _load_handle_uri(self,rest):
        self._ruledef(rest, 'uri')
    def _load_handle_mimeheader(self,rest):
        self._ruledef(rest, 'mimeheader')
    def _load_handle_require_version(self,rest):
        pass
    def _load_handle_score(self,rest):
        if self.line_disabled():
            return
        rulename,scores=rest.split(None,1)
        scores=scores.split()    
        rule=self.get_rule(rulename)
        if rule==None:
            #self.logger.warn("Trying to score unknown rule %s"%rulename)
            return
        
        if len(scores)==4:
            rule.scores=map(float,scores)
        else:
            fscore=float(scores[0])
            rule.scores=(fscore,fscore,fscore,fscore)
    def _load_handle_tflags(self,rest):
        if self.line_disabled():
            return
        rulename,flags=rest.split(None,1)
        rule=self.get_rule(rulename)
        if rule==None:
            #self.logger.warn("Trying to flag unknown rule %s"%rulename)
            return
        flags=flags.split()
        for flag in flags:
            if flag.startswith('#'):
                return
            rule.tflags.extend(flag)
        
    def _load_handle_describe(self,rest):
        if self.line_disabled():
            return
        rulename,description=rest.split(None,1)
        rule=self.get_rule(rulename)
        if rule==None:
            #self.logger.warn("Trying to describe unknown rule %s"%rulename)
            return
        rule.description=description
    def _load_handle_priority(self,rest):
        if self.line_disabled():
            return
        rulename,priority=rest.split(None,1)
        rule=self.get_rule(rulename)
        if rule==None:
            #self.logger.warn("Trying to set priority for unknown rule %s"%rulename)
            return
        rule.priority=float(priority)

    #UNIMPLEMENTED STUFF
    def _load_handle_redirector_pattern(self,rest):
        return #TODO: implement redirector pattern
    def _load_handle_lang(self,rest):
        return #TODO: implement lang
    def _load_handle_util_rb_2tld(self,rest):
        return
    def _load_handle_reuse(self,rest):
        return
    def _load_handle_report(self,rest):
        return
    def _load_handle_report_contact(self,rest):
        return
    def _load_handle_clear_report_template(self,rest):
        return
    def _load_handle_clear_unsafe_report_template(self,rest):
        return
    def _load_handle_unsafe_report(self,rest):
        return
    def _load_handle_clear_headers(self,rest):
        return
    def _load_handle_add_header(self,rest):
        return
    def _load_handle_required_score(self,rest):
        return
    def _load_handle_ok_locales(self,rest):
        return
    def _load_handle_bayes_auto_learn(self,rest):
        return
    def _load_handle_test(self,definition):
        pass

    def _load_handle_report_safe(self,definition):
        if self.line_disabled():
            return
        pass

        
        

class PythonSA(object):
    def __init__(self):
        self.logger=logging.getLogger('pythonsa')
        self.ruleconfig=None
    
    def load_config(self):
        config=RuleConfig()
        config.load()
        self.ruleconfig=config
        
    
    def run_check(self,msgrep):
        """run a check and return the result"""
        evalrun=SARuleEvaluator(self.ruleconfig.rules, msgrep)
        evalrun.run()
        
        print ""
        totalscore=0
        for rulename,hit in evalrun.hitcache.iteritems():
            if hit:
                rule=self.ruleconfig.get_rule(rulename)
                if rulename.startswith('__'):
                    print "meta part hit: %s"%(rulename)
                    score=0
                else: 
                    score=rule.scores[0]
                    print "rule hit: %s -> %s"%(rulename,score)
                totalscore+=score
        
        print "Total Score: %s"%totalscore
                
                    
    
    


from fuglu.shared import ScannerPlugin,DUNNO
class SANativePlugin(ScannerPlugin):
    def __init__(self,config):
        ScannerPlugin.__init__(self,config)
        self.logger=self._logger()
        self.spamassassin=PythonSA()
        self.spamassassin.load_config()
    
    def examine(self,suspect):
        msgrep=suspect.get_message_rep()
        self.spamassassin.run_check(msgrep)
        return DUNNO

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    psa=PythonSA()
    psa.load_config()
    #print 'LOTS_OF_MONEY' in psa.ruleconfig.rules
    #for k,v in psa.ruleconfig.rules.iteritems():
    #1    print "%s -> %s"%(k,v)
    psa.run_check(email.message_from_file(open('/home/gryphius/a812de9bd07c6009a3b5c4b50c8b041d.eml','r')))
    
    class RuleEngineMock(object):
        def __init__(self):
            self.knownrules={
                '__BLA':True,
                '__BLUBB':True,
                '__BLOING':False,
            }
            
        def get_rule_hit(self,rulename):
            if rulename not in self.knownrules:
                print "warning: unknown rule reference: '%s' "%rulename
                return False
            return self.knownrules[rulename]
    
    ruleengine=RuleEngineMock()
    
    #set the function that actually evaluates a rule hit
    threadlocal.evalfunc = ruleengine.get_rule_hit
    
    tests=[
           ("(__BLA + __BLUBB >1)",True),
            ("(__BLA + __BLUBB >3)",False),
           ("(__BLA + __BLUBB + __BLOING >=2)",True),
    ]
    for t,expected in tests:
        print "Testing: %s"%t
        res = boolExpr.parseString(t)[0]
        success = "PASS" if bool(res) == expected else "FAIL"
        print t,'\n', res, '=', bool(res),'\n', success, '\n'
    
    