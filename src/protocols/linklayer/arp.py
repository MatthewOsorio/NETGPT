class arp:
    def __init__(self) :
        self.opcode = None
        self.sender_ip_addr= None
        self.sender_mac_addr= None
        self.target_ip_addr= None
        self.target_mac_addr= None

    def setOPCode(self, opcode):
        self.opcode= opcode
    
    def setSenderIPAddr(self, addr):
        self.sender_ip_addr= addr
    
    def setSenderMacAddr(self, addr):
        self.sender_mac_addr= addr

    def setTargetIPAddr(self, addr):
        self.target_ip_addr= addr

    def setTargetMacAddr(self, addr):
        self.target_mac_addr= addr

    def getOPCode(self):
        return self.opcode
    
    def getSenderIPAddr(self):
        return self.sender_ip_addr
    
    def getSenderMacAddr(self):
        return self.sender_mac_addr

    def getTargetIPAddr(self):
        return self.target_ip_addr

    def getTargetMacAddr(self):
        return self.target_mac_addr
