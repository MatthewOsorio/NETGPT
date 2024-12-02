class packet:
    def __init__(self) -> None:
        self.packet_num= None
        self.packetsize= None
        self.link_layer= None
        self.link_layer_protocol= None
        self.network_layer = None
        self.network_layer_protocol= None
        self.transport_layer = None
        self.transport_layer_protocol= None
        self.application_layer= None
        self.application_layer_protocol= None
        self.highest_layer= None

    def setPacketNum(self, num):
        self.packet_num= num

    def setPacketSize(self, size):
        self.packetsize= size

    def setLinkLayer(self, protocol):
        self.link_layer= protocol
        
    def setNetLayer(self, protocol):
        self.network_layer= protocol

    def setTranLayer(self, protocol):
        self.transport_layer= protocol

    def setAppLayer(self, protocol):
        self.application_layer= protocol

    def setLLProtocol(self, protocol):
        self.link_layer_protocol= protocol 

    def setNLProtocol(self, protocol):
        self.network_layer_protocol= protocol

    def setTLProtocol(self, protocol):
        self.transport_layer_protocol= protocol

    def setALProtocol(self, protocol):
        self.application_layer_protocol= protocol

    def getPacketNum(self):
        return self.packet_num

    def getPacketSize(self):
        return self.packetsize

    def getLinkLayer(self):
        return self.link_layer
        
    def getNetLayer(self):
        return self.network_layer

    def getTranLayer(self):
        return self.transport_layer

    def getAppLayer(self):
        return self.application_layer

    def getLLProtocol(self):
        return self.link_layer_protocol 

    def getNLProtocol(self):
        return self.network_layer_protocol

    def getTLProtocol(self):
        return self.transport_layer_protocol

    def getALProtocol(self):
        return self.application_layer_protocol

    def getHighestLayer(self):
        return self.highest_layer
    
    def isEmpty(self):
        if self.link_layer == None and self.network_layer == None and self.transport_layer == None and self.application_layer == None:
            return True
        return False
    
    def setHighestLayer(self):
        if self.link_layer != None and self.network_layer == None and self.transport_layer == None and self.application_layer == None:
            self.highest_layer= 'link'
        elif self.link_layer != None and self.network_layer != None and self.transport_layer == None and self.application_layer == None:
            self.highest_layer= 'network'
        elif self.link_layer != None and self.network_layer != None and self.transport_layer != None and self.application_layer == None:
            self.highest_layer= 'transport'
        else:
            self.highest_layer= 'application'