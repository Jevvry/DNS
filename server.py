from scapy.layers.dns import *
import socket
import jsonpickle
import datetime
from record import Record


class CacheDNS:
    HOST = "127.0.0.1"
    PORT = 53

    def __init__(self):
        self.types = {2: "NS", 1: "A", 12: "PTR", 28: "AAAA"}
        self.cache = []
        self.host = self.HOST
        self.port = self.PORT
        self.init_cache()

    def start(self):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind((self.host, self.port))
        upd_request = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while True:
            data, addr = udp.recvfrom(65535)
            request = DNS(_pkt=data)
            qname = request.qd.qname.decode()
            qtype = self.types[request.qd.qtype]
            self.update_cache()
            record = self.find_record(qname, qtype)
            if record is None:
                upd_request.sendto(data, ("8.8.8.8", 53))
                response = upd_request.recv(65535)
                out = DNS(_pkt=response)
                udp.sendto(response, addr)
                self.parse_package(out)
            else:
                udp.sendto(jsonpickle.encode(record).pkt, addr)

    def find_record(self, qname, qtype):
        for record in self.cache:
            if record.name == qname and record.type == qtype:
                return record

    def parse_package(self, package):
        an_count = package.ancount - 1
        if package.an is None:
            return
        record = self.build_record(package.an, package)
        self.cache.append(record)
        package = package.an
        for _ in range(an_count):
            record = self.build_record(package.payload, package)
            self.cache.append(record)
            print(len(server.cache), record.ttl, record.name, record.data, sep=' ')
            package = package.payload

    def update_cache(self):
        time = datetime.datetime.now()
        updated_cache = []
        for record in self.cache:
            if time < record.del_time:
                updated_cache.append(record)
        self.cache = updated_cache
        self.save_records()

    def add_ttl(self, ttl):
        return datetime.datetime.now() + datetime.timedelta(seconds=ttl)

    def build_package(self, name, qtype):
        if qtype == "PTR":
            splited = name.split('.')
            splited.reverse()
            name = '.'.join(splited) + ".in-addr.arpa"
        dns = DNSQR(qname=name, qtype=qtype)
        return DNS(qd=dns).build()

    def build_record(self, answer, pkt):
        name = answer.rrname.decode()
        qtype = self.types[answer.type]
        ttl = answer.ttl
        data = answer.rdata
        if type(data) is not str:
            data = data.decode()
        return Record(name, data, ttl, qtype, pkt)

    def save_records(self):
        with open("cache.txt", mode="w") as file:
            for record in self.cache:
                file.write(jsonpickle.encode(record) + "\n")

    def init_cache(self):
        with open("cache.txt", mode="r") as file:
            lines = file.readlines()
            for record in lines:
                self.cache.append(jsonpickle.decode(record))


if __name__ == '__main__':
    server = CacheDNS()
    server.start()
