import struct
import zlib
import socket
import sys
import getopt
import time
import os
import argparse

PTYPE_DATA = 1
PTYPE_ACK = 2
PTYPE_SACK = 3

MAX_WINDOW = 63
MAX_SEQNUM = 2047
MAX_LENGTH = 1024

DEFAULT_DIRECTORY = '.'

def create_server(server_addr: str, port: int, directory: str):
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.bind((server_addr, port))
        print(f"Serveur UDP IPv6 écoute sur {server_addr}:{port} ...", file=sys.stderr)

        while True:
            raw_request, client_addr = sock.recvfrom(2048)
            request_str = raw_request.decode('ascii').strip()   

            # Si c'est le bon format on recoit la requete sous le format: 
            # "GET /llmsmall\r\n" de la part du client.

            if request_str.startswith('GET '):  #si ca commence bien par "GET " alors c'est bien une requete HTTP 0.9
                path = request_str[4:].rstrip('\r\n')
                file_path = os.path.join(directory, path.lstrip("/"))
                try:
                    with open(file_path, 'rb') as f: #read binary
                        payload = f.read()
                except FileNotFoundError:
                    print("File not found")
                    payload = b""
            else:
                print("Request is not in the valid format.")
                

            timestamp = int(time.time() * 1000) & 0xffffffff  # Masque 32-bit
            seqnum = 0
            if len(payload) > 1024:
                seq_payloads = [payload[i:i+1024] for i in range(0, len(payload), 1024)]
            else:
                seq_payloads = [payload]

            for elements in seq_payloads:
                segment = encode(type_str="PTYPE_DATA", window=0, seqnum=seqnum, timestamp=timestamp, payload=elements)
                sock.sendto(segment, client_addr)
                print(f"Segment DATA envoyé ({len(elements)} bytes)", file=sys.stderr)
                seqnum += 1
            sock.sendto(encode(type_str="PTYPE_DATA", window=0, seqnum=seqnum, timestamp=timestamp, payload=b""), client_addr) #Envoi du dernier bit qui indique la fin au client.
            print(f"Dernier segment DATA envoyé (0 bytes)", file=sys.stderr)
            print(f"Fichier envoyé pour un total de {len(payload)} bits")
        print("out of while True loop")
    except socket.error as err:
        print(f'Erreur socket: {err}', file=sys.stderr)
        return -1
    except Exception as e:
        print(f'Erreur inattendue: {e}', file=sys.stderr)
        return -1
    return 0

def encode(type_str, window, seqnum, timestamp, payload):
    match type_str:
        case "PTYPE_DATA": type_bits = 1
        case "PTYPE_ACK": type_bits = 2
        case "PTYPE_SACK": type_bits = 3
        case _: type_bits = 0

    length = len(payload)

    # MASQUE 32-bit pour éviter overflow struct 'I'
    word = ((type_bits << 30) | (window << 24) | (length << 11) | seqnum) & 0xffffffff

    # Header 8 bytes
    header_bytes = struct.pack('!II', word, timestamp & 0xffffffff)
    
    # CRC1 sur header 8 bytes
    crc1_calc = zlib.crc32(header_bytes) & 0xffffffff
    crc1 = struct.pack('>I', crc1_calc)

    message = [header_bytes, crc1]
    if payload:
        message.append(payload)
        crc2_calc = zlib.crc32(payload) & 0xffffffff
        crc2 = struct.pack('>I', crc2_calc)
        message.append(crc2)
    
    return b''.join(message)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--root", '-r',
        default=DEFAULT_DIRECTORY,
        help=f"Directory is the root folder from which the server retrieves the file requested by the client (default : {DEFAULT_DIRECTORY})"
    )

    parser.add_argument(
        'hostname',
        help= "Hostname being the name of the domain or IPv6 address on which the server listens to incoming client requests"
    )

    parser.add_argument(
        'port',
        type=int,
        help="Port being the UDP port number to which the server attaches"
    )

    args = parser.parse_args()
    
    result = create_server(args.hostname, args.port, args.root)
    
    if result != 0:
        sys.exit(1)