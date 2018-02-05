from fuglu.shared import AppenderPlugin,actioncode_to_string,apply_template
from fuglu.extensions.sql import SQL_EXTENSION_ENABLED, get_session
import re
import string

class SQLRunner(AppenderPlugin):
    """Run SQL statements after message scan is complete"""
    
    def __init__(self,config,section):
        AppenderPlugin.__init__(self,config,section)
        self.logger=self._logger()
        
        self.requiredvars={
            'dbconnectstring':{
                'default':'mysql://root@localhost/test',
                'description':'sqlalchemy connectstring',
            },              
            
            'statementseparator':{
                'default':';',
                'description':'Separator used to separate mutliple statements',
            },
                           
            'statements':{
                'description':"""SQL statements to run, can containt standard variables as described in http://gryphius.github.io/fuglu/plugins-index.html#template-variables
                \n ${action} contains the action as string, eg. DUNNO """,
                'default':"",
            },
        }
    
    
    def sqlfix(self,values):
        for k,v in iter(values.copy().items()):
            if isinstance(v, str):
                values[k]=re.sub("""['";]""", "", v)
        return values
        
    def process(self,suspect,decision):
        if not SQL_EXTENSION_ENABLED:
            self.logger.error("Fuglu SQL Extensions not enabled")
            return
        
        connstring=self.config.get(self.section,'dbconnectstring')
        session=get_session(connstring)
        if session is None:
            self.logger.error("Could not create database session")
            return
        
        try:
            conn=session.connection()
            conn.connect()
        except Exception as e:
            self.logger.error( "Database Connection failed: %s"%e)
            return
        
        
        statementlist=self.get_statements()
        for statement in statementlist:
            self.logger.debug("Template: %s"%statement)
            addvalues={'action':actioncode_to_string(decision),}
            from_header=suspect.get_message_rep()['from']
            try:
                addvalues['header_from']=self.stripAddress(from_header)
            except Exception:
                #use full from header
                addvalues['header_from']=from_header
            
            
            replaced=apply_template(statement, suspect, values=addvalues,valuesfunction=self.sqlfix)
            self.logger.debug("Statement: %s"%replaced)
            try:
                result=session.execute(replaced)
            except Exception as e:
                self.logger.error("Statement failed: statement=%s , error=%s"%(replaced,str(e)))
        session.remove()


    def stripAddress(self,address):
        """
        Strip the leading & trailing <> from an address.  Handy for
        getting FROM: addresses.
        """
        start = address.find('<') + 1
        if start<1:
            start=address.find(':')+1
        if start<1:
            raise ValueError("Could not parse address %s"%address)
        end = string.find(address, '>')
        if end<0:
            end=len(address)
        retaddr=address[start:end]
        retaddr=retaddr.strip()
        return retaddr

    def get_statements(self):
        return self.config.get(self.section,'statements').split(self.config.get(self.section,'statementseparator'))
    
    
    
    def lint(self):
        
        if not SQL_EXTENSION_ENABLED:
            print( "Fuglu SQL Extensions not enabled")
            return False
        
        connstring=self.config.get(self.section,'dbconnectstring')
        session=get_session(connstring)
        if session is None:
            print("Could not create database session")
            return False
        
        try:
            conn=session.connection()
            conn.connect()
        except Exception as e:
            print("Database Connection failed: %s"%e)
            return False
        
        session.remove()
        return True    