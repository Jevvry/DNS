import datetime


class Record:
    def __init__(self, name, data, ttl, type, pkt):
        self.name = name
        self.data = data
        self.ttl = ttl
        self.type = type
        self.pkt = pkt
        self.del_time = datetime.datetime.now() + datetime.timedelta(seconds=ttl)
