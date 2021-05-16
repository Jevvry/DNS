import socket
import jsonpickle
from server import CacheDNS

host = CacheDNS.HOST
port = CacheDNS.PORT


def main():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        user_request = input()
        udp.sendto(user_request.encode(), (host, port))
        response = udp.recv(65535)
        record = jsonpickle.decode(response.decode())
        print(record.data)


if __name__ == '__main__':
    main()
