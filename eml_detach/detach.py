from fuglu.shared import ScannerPlugin,DUNNO

class AttachmentForwarder(ScannerPlugin):
    """Searches for a attached rfc822 (eml) message and replaces the current message with this one."""
    
    def __init__(self,config,section=None):
        ScannerPlugin.__init__(self,config,section)
        self.logger=self._logger()

    def examine(self,suspect):
        m=suspect.getMessageRep()
        for i in m.walk():
            contenttype_mime=i.get_content_type()
            if contenttype_mime is not None and contenttype_mime.lower() in ['message/rfc822',]:
                if i.is_multipart():
                    payload=i.get_payload(0).as_string()
                else:
                    payload=i.get_payload(0)
                if 'Received' in payload[:10000]:
                    suspect.set_source(payload)
                    break
        return DUNNO
