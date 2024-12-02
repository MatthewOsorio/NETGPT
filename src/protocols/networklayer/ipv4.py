class ipv4:
    def __init__(self):
        self.source_ip_addr= None
        self.dest_ip_addr= None
        self.ttl= None

    def setSourceIPAddr(self, addr):
        self.source_ip_addr= addr
    
    def setDestIPAddr(self, addr):
        self.dest_ip_addr= addr

    def setTTL(self, ttl):
        self.ttl= ttl
    
    def getSourceIPAddr(self):
        return self.source_ip_addr
    
    def getDestIPAddr(self):
        return self.dest_ip_addr

    def getTTL(self):
        return self.ttl