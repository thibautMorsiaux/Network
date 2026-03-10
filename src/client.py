import struct
import zlib
import socket
import sys
import argparse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

PTYPE_DATA = 1
PTYPE_ACK = 2
PTYPE_SACK = 3

MAX_WINDOW = 63
MAX_SEQNUM = 2047
MAX_LENGTH = 1024
HEADER_LEN = 12

DEFAULT_LOCATION = "./llm.model"

class DecodeError(Exception):
    pass

@dataclass
class Segment:
    ptype: int
    window: int
    length: int
    seqnum: int
    timestamp: int
    payload: bytes

def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xffffffff

def decode_segment(raw: bytes) -> Segment: 
    if len(raw) < HEADER_LEN:
        raise DecodeError("Segment too short")
    
    word = int.from_bytes(raw[0:4], byteorder='big')
    ptype = (word >> 30) & 0x3
    window = (word >> 24) & 0x3f
    length = (word >> 11) & 0x1fff
    seqnum = word & 0x7ff

    if ptype not in (PTYPE_DATA, PTYPE_ACK, PTYPE_SACK):
        raise DecodeError(f"Invalid packet type: {ptype}")
    if not (0 <= window <= MAX_WINDOW):
        raise DecodeError(f"Invalid window size: {window}")
    if not (0 <= seqnum <= MAX_SEQNUM):
        raise DecodeError(f"Invalid seqnum: {seqnum}")
    if not (0 <= length <= MAX_LENGTH):
        raise DecodeError(f"Invalid length: {length}")
    
    timestamp = int.from_bytes(raw[4:8], byteorder='big')

    crc1_recv = int.from_bytes(raw[8:12], byteorder='big')
    crc1_calc = crc32(raw[0:8])
    if crc1_recv != crc1_calc:
        raise DecodeError("CRC1 mismatch")
    
    payload = b""
    offset = HEADER_LEN

    if length == 0:
        if len(raw) != HEADER_LEN:
            raise DecodeError("Extra bytes in zero-length packet")
        return Segment(ptype, window, length, seqnum, timestamp, payload)
    
    expected_total = HEADER_LEN + length + 4
    if len(raw) < expected_total:
        raise DecodeError("Truncated data packet")
    
    payload = raw[offset:offset+length]
    crc2_recv = int.from_bytes(raw[offset+length:offset+length+4], byteorder='big')
    crc2_calc = crc32(payload)
    if crc2_recv != crc2_calc:
        raise DecodeError("CRC2 mismatch")
    return Segment(ptype, window, length, seqnum, timestamp, payload)

def connect_client(server_name: str):
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        server_list = server_name.split('//')
        hostname_port_path = server_list[1]
        
        # Séparer host:port du path
        if '/' in hostname_port_path:
            host_port, path = hostname_port_path.split('/', 1)
            path = '/' + path
        else:
            host_port = hostname_port_path
            path = ''
        
        # Parser hostname:port (gère IPv6 [::1] et IPv4)
        if host_port.startswith('[') and ']:' in host_port:
            bracket_end = host_port.find(']:')
            hostname = host_port[:bracket_end+1]  # Garde [::1]
            port_str = host_port[bracket_end+2:]
        else:
            hostname, port_str = host_port.rsplit(':', 1)
        
        port = int(port_str)

        if hostname.startswith('[') and hostname.endswith(']'):
            hostname = hostname[1:-1]  # [::1] → ::1

        sock.connect((hostname, port))
        print(f"Connecté à {hostname}:{port}, fichier: {path}", file=sys.stderr)
        return sock, path
    except Exception as err:
        print(f"Erreur connexion: {err}", file=sys.stderr)
        return None, None
    
def encode_ack(next_seqnum: int, timestamp: int) -> bytes:
    ptype = PTYPE_ACK  
    window = MAX_WINDOW  
    length = 0  #contient pas de données car juste un ACK
    
    word = ((ptype << 30) | (window << 24) | (length << 11) | next_seqnum) & 0xffffffff
    header_bytes = struct.pack('!II', word, timestamp & 0xffffffff)
    
    crc1_calc = crc32(header_bytes)
    crc1 = struct.pack('!I', crc1_calc)
    
    #le paquet ACK fait 12 octets, header + crc1
    return header_bytes + crc1

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--save", '-s',
        default=DEFAULT_LOCATION,
        help=f"Location corresponds to the path and name of the file where to store the data received (default : {DEFAULT_LOCATION})"
    )

    parser.add_argument(
        'servername',
        help= "Servername has the form http://hostname:port/path /to/file, where hostname and port have the same meaning as for the server, and path/to/file is the relative path of the file to be retrieved"
    )

    args = parser.parse_args()
    
    save_path = args.save
    sock, path = connect_client(args.servername)
    if sock is None:
        sys.exit(1)
    
    try:
        # Envoyer le path au serveur
        sock.send(f"GET {path}\r\n".encode('ascii'))
        sock.settimeout(2.0)
        recieved = {}
        expected_seqnum = 0
        eof_seqnum = None
        try:
            sock.settimeout(10.0)
            while True:
                try :
                    raw = sock.recv(2048)
                    print(f"Reçu {len(raw)} bytes", file=sys.stderr)  # Debug
                    segment = decode_segment(raw)
                    print(f"Seq {segment.seqnum} len {segment.length}", file=sys.stderr)  # Debug
                    recieved[segment.seqnum] = segment

                    if not segment.payload:
                        eof_seqnum = segment.seqnum

                    while expected_seqnum in recieved:
                        expected_seqnum = (expected_seqnum + 1) % 2048
                    
                    #envoi d'ack avec le prochain num attendu
                    ack_packet = encode_ack(expected_seqnum, segment.timestamp)
                    sock.send(ack_packet)
                    print(f"ACK envoyé, attend le seq {expected_seqnum}", file=sys.stderr)

                    if eof_seqnum is not None and expected_seqnum == (eof_seqnum + 1) % 2048:
                        break
                except DecodeError as e:
                    print(f"Erreur décodage: {e} (paquet: {len(raw)}B)", file=sys.stderr) 
        except socket.timeout:
            print("Timeout", file=sys.stderr)
            
        sorted_recieved = sorted(recieved.items())
        total_length = 0
        with open(save_path, 'wb') as f:
            # Écrire le payload
            for sequence, segment in sorted_recieved:
                f.write(segment.payload)
                total_length += segment.length
        print(f"Fichier reçu ({total_length} bytes) -> {save_path}", file=sys.stderr)
            
    except Exception as e:
        print(f"Erreur transfert: {e}", file=sys.stderr)
    finally:
        sock.close()