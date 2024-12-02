class dns_response:
    def __init__(self):
        self.id= None
        self.rcode= None
        self.answer= None

    def setID(self, id):
        self.id= id
    
    def setRCode(self, rcode):
        self.rcode= rcode

    def setAnswers(self, answer):
        self.answer = answer

    def getID(self):
        return self.id
    
    def getRCode(self):
        return self.rcode

    def getAnswers(self):
        return self.answer

