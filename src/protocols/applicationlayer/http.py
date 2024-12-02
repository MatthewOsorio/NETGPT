class http:
    def __init__(self):
        self.request_method= None
        self.host= None
        self.url=None
        self.user_agent= None
        self.status_code= None
        self.server=None

    def setRequestMethod(self, method):
        self.request_method= method

    def setHost(self, host):
        self.host= host
    
    def setURL(self, url):
        self.url= url

    def setUserAgent(self, user):
        self.user_agent= user

    def setStatusCode(self, user):
        self.status_code= user
    
    def setServer(self, server):
        self.server= server
    
    def getRequestMethod(self):
        return self.request_method

    def getHost(self):
        return self.host
    
    def getURL(self):
        return self.url

    def getUserAgent(self):
        return self.user_agent

    def getStatusCode(self):
        return self.status_code
    
    def getServer(self):
        return self.server
    
    def isRequest(self):
        if self.request_method != None:
            return True
        return False
        