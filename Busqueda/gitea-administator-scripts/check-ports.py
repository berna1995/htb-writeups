#!/bin/bash
import errno, sys
from socket import *


if (len(sys.argv) > 1):
    remote_host = sys.argv[1]
    server_port = int(sys.argv[2])

    portconn = socket(AF_INET, SOCK_STREAM)
    try:
        portconn.connect((remote_host, server_port))
        portconn.shutdown(2)

        print("Success. Connected to " + remote_host + " on port: " + str(server_port))
    except:
        print("Failure. Cannot connect to " + remote_host + " on port: " + str(server_port))
        sys.exit(errno.EPERM)
    portconn.close()
else:
    print(f"Usage : python {sys.argv[0]} <host> <port>")
