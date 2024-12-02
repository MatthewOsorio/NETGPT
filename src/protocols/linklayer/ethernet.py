class ethernet:
    def __init__(self):
        self.mac_addr_source= None
        self.mac_addr_destination= None
        self.ethertype= None
        self.arp= None 

    def setSourceMacAddr(self, source_addr):
        self.mac_addr_source= source_addr

    def setDestMacAddr(self, dest_addr):
        self.mac_addr_destination= dest_addr

    def setEtherType(self, ethertype):
        self.ethertype= ethertype

    def setARP(self, arp):
        self.arp= arp
    
    def hasARP(self):
        if self.arp == None:
            return False
        return True
    
    def getSourceMacAddr(self):
        return self.mac_addr_source

    def getDestMacAddr(self):
        return self.mac_addr_destination

    def getEtherType(self):
        return self.ethertype

    def getARP(self):
        return self.arp
