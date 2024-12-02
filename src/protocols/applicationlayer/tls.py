class tls:
    def __init__(self):
        self.verison= None
        self.hs_type= None
        self.cipher_suite= None

    def setVersion(self, version):
        self.verison= version
    
    def setHSType(self, hs):
        self.hs_type= hs

    def setCipherSuite(self, cs):
        self.cipher_suite= cs

    def getVersion(self):
        return self.verison
    
    def getHSType(self):
        return self.hs_type

    def getCipherSuite(self):
        return self.cipher_suite