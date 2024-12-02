class dns_query:
    def __init__(self):
        self.id= None
        self.name= None
        self.type= None

    def setID(self, id):
        self.id= id
    
    def setName(self, name):
        self.name= name

    def setType(self, type):
        self.type= type

    def getID(self):
        return self.id
    
    def getName(self):
        return self.name

    def getType(self):
        return self.type