from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime    import datetime
import os
import base64
import json
import socket
import threading
import socket
import time
import random

# pip install cryptodomex
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2

# TODO remove
from sys import getsizeof
HOST         = "0.0.0.0"
BGCOLOR      = "black"
color        = "red"
temperature  = "--"
last_data_ts = datetime.now().timestamp()

PASSWORD             = os.getenv("PASSWORD")
ALGORITHM_NONCE_SIZE = int(os.getenv("ALGORITHM_NONCE_SIZE"))
ALGORITHM_TAG_SIZE   = int(os.getenv("ALGORITHM_TAG_SIZE"))
ALGORITHM_KEY_SIZE   = int(os.getenv("ALGORITHM_KEY_SIZE"))
PBKDF2_SALT_SIZE     = int(os.getenv("PBKDF2_SALT_SIZE"))
PBKDF2_ITERATIONS    = int(os.getenv("PBKDF2_ITERATIONS"))
HTTP_PORT            = int(os.getenv("HTTP_PORT"))
TCP_PORT             = int(os.getenv("TCP_PORT"))
ENCRYPTED_STRING_SIZE= int(os.getenv("ENCRYPTED_STRING_SIZE"))

PBKDF2_LAMBDA = lambda x, y: HMAC.new(x, y, SHA256).digest()

def decryptString(base64CiphertextAndNonceAndSalt, PASSWORD):
    # Decode the base64.
    ciphertextAndNonceAndSalt = base64.b64decode(base64CiphertextAndNonceAndSalt)

    # Get the salt and ciphertextAndNonce.
    salt = ciphertextAndNonceAndSalt[:PBKDF2_SALT_SIZE]
    ciphertextAndNonce = ciphertextAndNonceAndSalt[PBKDF2_SALT_SIZE:]

    # Derive the key using PBKDF2.
    key = PBKDF2(PASSWORD, salt, ALGORITHM_KEY_SIZE, PBKDF2_ITERATIONS, PBKDF2_LAMBDA)

    # Decrypt and return result.
    plaintext = decrypt(ciphertextAndNonce, key)

    return plaintext.decode('utf-8')

def decrypt(ciphertextAndNonce, key):
    # Get the nonce, ciphertext and tag.
    nonce = ciphertextAndNonce[:ALGORITHM_NONCE_SIZE]
    ciphertext = ciphertextAndNonce[ALGORITHM_NONCE_SIZE:len(ciphertextAndNonce) - ALGORITHM_TAG_SIZE]
    tag = ciphertextAndNonce[len(ciphertextAndNonce) - ALGORITHM_TAG_SIZE:]

    # Create the cipher.
    cipher = AES.new(key, AES.MODE_GCM, nonce)

    # Decrypt and return result.
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def my_tcp_server():
    global temperature, color, last_data_ts

    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    serverSocket.bind((HOST, TCP_PORT));
    serverSocket.listen();
    while True:
        (clientConnected, clientAddress) = serverSocket.accept();

        dataFromClient = clientConnected.recv(1024)
        encrypted_data = dataFromClient.decode()
        if int(getsizeof(encrypted_data)) == ENCRYPTED_STRING_SIZE:
            decrypted_data=decryptString(encrypted_data, PASSWORD)
            y=json.loads(decrypted_data)

            temperature=int(y["temperature"])
            if temperature < 20:
                color = "chartreuse"
            elif temperature < 27:
                color = "yellow"
            else:
                color = "red"
            print("Accepted a connection request from %s:%s, t=%d"%(clientAddress[0], clientAddress[1], temperature));
            last_data_ts=datetime.now().timestamp()
        else:
            print("Skipped a connection request from %s:%s, size=%d"%(clientAddress[0], clientAddress[1], int(getsizeof(encrypted_data))));
        # conn.close()

class Dashboard(BaseHTTPRequestHandler):

    def do_GET(self):
        global temperature, color, last_data_ts
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        curr_ts = datetime.now().timestamp()
        if int(curr_ts-last_data_ts) > 90:
            temperature="--"
            color="red"

        self.wfile.write(bytes(
            "<html>\
                <body BGCOLOR=\"" + BGCOLOR + "\">\
                    <style>\
                        .header{\
                            font-size: 300px;\
                            line-height: 550px;\
                            color: " + color + ";\
                            text-align: center;\
                        }\
                    </style>\
                    <div class=\"header\">\
                        <h1>" + str(temperature) + "</h1>\
                    </div>\
                </body>\
            </html>",
            "utf-8"))

def my_page():
    server = HTTPServer((HOST, HTTP_PORT), Dashboard)
    print("Running")
    print(PASSWORD)
    print(ALGORITHM_NONCE_SIZE)
    print(ALGORITHM_TAG_SIZE)
    print(ALGORITHM_KEY_SIZE)
    print(PBKDF2_SALT_SIZE)
    print(PBKDF2_ITERATIONS)
    print(HTTP_PORT)
    print(TCP_PORT)
    server.serve_forever()
    server.server_close()

def main():
    thr = threading.Thread(target=my_tcp_server)
    thr.daemon = True
    thr.start()
    my_page()

if __name__ == '__main__':
    main()