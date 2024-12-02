class udp:
    def __init__(self):
        self.src_port= None
        self.dst_port= None
        self.length= None
        self.checksum= None

    def setSrcPort(self, port):
        self.src_port= port
    
    def setDstPort(self, port):
        self.dst_port= port

    def setLength(self, length):
        self.length= length

    def setChecksum(self, checksum):
        self.checksum= checksum
        
    def getSrcPort(self):
        return self.src_port
    
    def getDstPort(self):
        return self.dst_port

    def getLength(self):
        return self.length

    def getChecksum(self):
        return self.checksum