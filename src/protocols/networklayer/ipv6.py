
class ipv6:
    def __init__(self):
        self.source_ip_addr= None
        self.dest_ip_addr= None
        self.traffic_class= None

    def setSourceIPAddr(self, addr):
        self.source_ip_addr= addr
    
    def setDestIPAddr(self, addr):
        self.dest_ip_addr= addr

    def setTrafficClass(self, tclass):
        self.traffic_class= tclass

    def getSourceIPAddr(self):
        return self.source_ip_addr
    
    def getDestIPAddr(self):
        return self.dest_ip_addr

    def getTrafficClass(self):
        return self.traffic_class