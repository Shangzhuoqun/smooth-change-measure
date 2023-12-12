import yaml
class Config:
    def __init__():
        pass
    
    def LoadConf(self, file):
        config = yaml.load(open(file), Loader=yaml.SafeLoader)
        self.DomainFile = config["Measure"]["domain-file"]
        self.TimeZone = config["Measure"]["time-zone"]
        self.LogPath = config["Measure"]["log-path"]
        self.MaxTTL = int(config["Measure"]["max-ttl"])
        self.MinTTL = int(config["Measure"]["min-ttl"])
        self.ThreadNum = int(config["Measure"]["thread-num"])
        self.MaxTimes = int(config["Measure"]["max-times"])

        self.loadDomainList(self.DomainFile)
    
    def loadDomainList(self, file):
        f = open(file, 'r')
        line = f.readline().rstrip()
        self.DomainList = []
        while line:
            if len(line) != 0:
                if line[-1] != '.':
                    line += '.' 
                self.DomainList.append(line)
            line = f.readline().rstrip()
        self.DomainList.sort()


Conf = Config()