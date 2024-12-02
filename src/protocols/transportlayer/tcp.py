class tcp:
    def __init__(self):
        self.src_port= None
        self.dst_port=None
        self.flags= None
        self.seq_num= None
        self.ack_num= None

    def setSrcPort(self, port):
        self.src_port= port

    def setDSTPort(self, port):
        self.dst_port= port

    def setFlags(self, flags):
        self.flags= flags

    def setSeqNum(self, num):
        self.seq_num= num

    def setAckNum(self, num):
        self.ack_num= num

    def getSrcPort(self):
        return self.src_port

    def getDSTPort(self):
        return self.dst_port

    def getFlags(self):
        return self.flags

    def getSeqNum(self):
        return self.seq_num

    def getAckNum(self):
        return self.ack_num

