import sys
import socket
import time


def main():

    hostname = "cribl.maejer.lab"
    port = 8991

    content = "test=test"

    # create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((hostname, port))

    for x in range(20):
        content = "test=test-%s\n" % str(x)
        print(content)
        sock.sendall(content.encode())
        #time.sleep(0.5)

    sock.shutdown(socket.SHUT_WR)

    res = ""
    while True:
        data = sock.recv(1024)
        if (not data):
            break
        res += data.decode()
    
    print(res)

    print("Connection closed.")
    sock.close()

if __name__ == "__main__":
    main()