class Record:
    def __init__(self, line: str):
        line = line.strip().lower().split()
        self.Name = line[0]
        self.TTL = int(line[1])
        self.Class = line[2]
        self.Type = line[3]
        self.Rdata = line[4]

    def __eq__(self, __o: object) -> bool:
        return self.Name == __o.Name and self.Rdata == __o.Rdata and self.Type == __o.Type and self.Class == __o.Class