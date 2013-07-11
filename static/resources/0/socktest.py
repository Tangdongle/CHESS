import socket

host = '127.0.0.1'
port = 2000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect((host, port))
    s.shutdown(2)
    print "Success connecting to "
    print host + " on port: " + str(port)
    s.send("Coolibah!")
except:
    print "Cannot connect to "
    print host + " on port: " + str(port)

