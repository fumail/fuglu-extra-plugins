
from fuglu.shared import ScannerPlugin,DUNNO,SuspectFilter, apply_template
import time
import os


class HeaderwriterPlugin(ScannerPlugin):
    """
    Writes custom log based on suspect filter rules
    
    eg. if you put this into headerwriter.regex:
    From: (microsoft\.com|yahoo\.com|gmail\.com) ${id} claims to be from ${matchedvalue}
    
    fuglu would write a log with fuglu-id's whose from-domain is microsoft.com,yahoo.com or gmail.com
    """

    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        
        self.requiredvars={
            'filterfile':{
                'default':'/etc/fuglu/headerwriter.regex',
                'description':'Suspectfilter File',
            },
                           
            'outputfile':{
                'default':'',
                'description':'Output File',
            },
                           
            'defaultlinetemplate':{
                 'default':'${fieldname}: ${matchedvalue}',
                'description':'Default line output template if nothing is specified in filter config',                  
            }
            
        }
        self.filter=None

    def examine(self,suspect):
        starttime=time.time()
        if self.filter==None:
            self.filter=SuspectFilter(self.config.get(self.section,'filterfile'))
        
            
        hits=self.filter.get_args(suspect,extended=True)
        if len(hits)==0:
            return DUNNO
            
        #open file
        ofile=self.config.get(self.section,'outputfile')
        if ofile.strip()=='':
            self._logger().error("No output file specified for headerwriter")
            return DUNNO
            
        fh=open(ofile,'a')
        for hit in hits:
            (fieldname, matchedvalue, arg, regex)=hit
            if arg==None or arg=='':
                arg=self.config.get(self.section,'defaultlinetemplate')
            
            addvalues=dict(fieldname=fieldname,matchedvalue=matchedvalue,regex=regex)
            outputline=apply_template(arg, suspect, addvalues)
            fh.write(outputline)
            fh.write('\n')
            
        fh.close()
        
    def lint(self):
        filterfile=self.config.get(self.section,'filterfile')
        if not os.path.exists(filterfile):
            print "file not found: %s"%filterfile
            return False
        
        if self.config.get(self.section,'outputfile').strip()=='':
            print "No outputfile configured"
            return False
        
        return True  
