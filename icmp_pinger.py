import os
import sys
import socket
import struct
import time
import select
import argparse
import statistics
import threading
import tkinter as tk
from typing import Optional

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

class Term:
    ENABLE = sys.stdout.isatty()
    @staticmethod
    def green(s):
        return s if not Term.ENABLE else f"\033[92m{s}\033[0m"
    @staticmethod
    def red(s):
        return s if not Term.ENABLE else f"\033[91m{s}\033[0m"
    @staticmethod
    def yellow(s):
        return s if not Term.ENABLE else f"\033[93m{s}\033[0m"


def checksum(source_bytes: bytes) -> int:
    count_to = (len(source_bytes) // 2) * 2
    sum = 0
    count = 0
    while count < count_to:
        this_val = source_bytes[count + 1] * 256 + source_bytes[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2
    if count_to < len(source_bytes):
        sum = sum + source_bytes[-1]
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_packet(id: int, seq: int, payload_size: int = 56) -> bytes:
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, seq)
    data = (192 - seq) * b'Q'[:1] + (payload_size - 1) * b'Q'
    timestamp = struct.pack('d', time.time())
    data = timestamp + data[len(timestamp):]
    chksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, socket.htons(chksum), id, seq)
    return header + data

def parse_reply(packet: bytes) -> Optional[dict]:
    ip_header = packet[:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    ihl = iph[0] & 0x0F
    ip_header_len = ihl * 4
    icmp_header = packet[ip_header_len:ip_header_len + 8]
    if len(icmp_header) < 8:
        return None
    type, code, chksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
    payload = packet[ip_header_len + 8:]
    ts = None
    try:
        if len(payload) >= 8:
            ts = struct.unpack('d', payload[:8])[0]
    except:
        ts = None
    return {
        'type': type,
        'code': code,
        'id': p_id,
        'sequence': sequence,
        'timestamp': ts,
        'src_ip': socket.inet_ntoa(iph[8]),
        'dst_ip': socket.inet_ntoa(iph[9])
    }


def send_one_ping(sock, addr, id, seq, payload_size=56):
    packet = create_packet(id, seq, payload_size)
    sock.sendto(packet, (addr, 1))

def receive_one_ping(sock, id, timeout):
    time_left = timeout
    while True:
        start_select = time.time()
        ready = select.select([sock], [], [], time_left)
        how_long_in_select = (time.time() - start_select)
        if not ready[0]:
            return None
        time_received = time.time()
        rec_packet, addr = sock.recvfrom(1024)
        parsed = parse_reply(rec_packet)
        if parsed is None:
            return None
        if parsed.get('id') == id and parsed.get('type') == ICMP_ECHO_REPLY:
            rtt = (time_received - parsed.get('timestamp')) * 1000 if parsed.get('timestamp') else None
            parsed['rtt'] = rtt
            parsed['recv_time'] = time_received
            parsed['addr'] = addr[0]
            return parsed
        time_left = time_left - how_long_in_select
        if time_left <= 0:
            return None

def ping_host(host: str, count: int = 4, timeout: float = 1.0, interval: float = 1.0):
    try:
        dest = socket.gethostbyname(host)
    except socket.gaierror:
        print(Term.red(f"Cannot resolve {host}"))
        return
    print(f"\nPING {host} ({dest}):")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print(Term.red("Root privileges required!"))
        return
    id = os.getpid() & 0xFFFF
    rtts = []
    transmitted = 0
    received = 0
    for seq in range(1, count+1):
        transmitted +=1
        send_one_ping(sock, dest, id, seq)
        reply = receive_one_ping(sock, id, timeout)
        if reply:
            received +=1
            rtt = reply.get('rtt')
            rtts.append(rtt)
            print(Term.green(f"Reply from {reply['addr']}: seq={seq} time={rtt:.2f} ms"))
        else:
            print(Term.red(f"Request timed out for seq={seq}"))
        time.sleep(interval)
    loss = ((transmitted - received)/transmitted)*100
    print(f"--- {host} ping statistics ---")
    print(f"{transmitted} packets transmitted, {received} received, {loss:.1f}% packet loss")
    if rtts:
        print(f"rtt min/avg/max/std = {min(rtts):.2f}/{statistics.mean(rtts):.2f}/{max(rtts):.2f}/{statistics.pstdev(rtts):.2f} ms")


def start_ping_gui(host):
    threading.Thread(target=ping_host, args=(host,), daemon=True).start()

def gui():
    root = tk.Tk()
    root.title("ICMP Pinger Lab GUI")
    tk.Label(root, text="Host/IP:").pack()
    host_entry = tk.Entry(root)
    host_entry.pack()
    tk.Button(root, text="Start Ping", command=lambda: start_ping_gui(host_entry.get())).pack()
    tk.Label(root, text="Output will be shown in console").pack()
    root.mainloop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ICMP Pinger Lab Client (Windows-friendly)")
    parser.add_argument('-host', help="Ping host")
    parser.add_argument('-gui', action='store_true', help="Run GUI")
    args = parser.parse_args()

    if args.gui:
        gui()
    elif args.host:
        ping_host(args.host)
    else:
        print("Use -host <hostname> or -gui")
