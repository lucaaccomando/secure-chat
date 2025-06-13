import socket
import threading
import json
import time
import sys
from crypto_utils import (
    generate_rsa_keypair,
    serialize_public_key,
    deserialize_public_key,
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    encrypt_key_with_rsa,
    decrypt_key_with_rsa,
)

HOST = '127.0.0.1'
PORT = 65432

public_key_registry = {}
recipient_name = None
recipient_lock = threading.Lock()
keys_received_event = threading.Event()
user_exiting = threading.Event()

def graceful_exit(client_socket=None, receiver_thread=None):
    if user_exiting.is_set():
        return  
    user_exiting.set()
    print("\n[*] Disconnecting...")
    try:
        if client_socket:
            client_socket.close()
    except:
        pass
    if receiver_thread and receiver_thread.is_alive():
        receiver_thread.join(timeout=1)
    print("[*] Disconnected.")
    sys.exit(0)

def print_available_recipients():
    with recipient_lock:
        return bool(public_key_registry)

def receive_messages(client_socket):
    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                if not user_exiting.is_set():
                    print("\n[!] Disconnected from server.")
                graceful_exit(client_socket)

            decoded = data.decode('utf-8', errors='ignore').strip()
            if decoded.startswith('{') and decoded.endswith('}'):
                try:
                    payload = json.loads(decoded)

                    if payload.get("type") == "key_sync":
                        new_keys = payload.get("keys", {})
                        with recipient_lock:
                            public_key_registry.clear()
                            for user, key_pem in new_keys.items():
                                public_key_registry[user] = deserialize_public_key(key_pem.encode('utf-8'))
                        keys_received_event.set()
                        continue

                    elif payload.get("type") == "error":
                        print(f"\n[!] Server error: {payload.get('message')}")
                        with recipient_lock:
                            global recipient_name
                            recipient_name = None
                        continue

                    sender = payload['from']
                    encrypted_key = bytes.fromhex(payload['aes_key'])
                    encrypted_msg = bytes.fromhex(payload['message'])

                    aes_key = decrypt_key_with_rsa(encrypted_key, private_key)
                    plaintext = aes_decrypt(encrypted_msg, aes_key)

                    print(f"\r{sender}: {plaintext}\nYou: ", end='', flush=True)

                except Exception as e:
                    print(f"\n[!] Error decrypting message: {e}")
            else:
                if "has left the chat" in decoded:
                    left_user = decoded.split(" has left")[0]
                    with recipient_lock:
                        if recipient_name == left_user:
                            recipient_name = None
                            print(f"\n[!] Your recipient ({left_user}) has disconnected.")
                        if left_user in public_key_registry:
                            del public_key_registry[left_user]
                
                print(f"\r{decoded}\nYou: ", end='', flush=True)

    except (ConnectionResetError, ConnectionAbortedError, OSError):
        if not user_exiting.is_set():
            print("\n[!] Server connection lost.")
        graceful_exit()
    except Exception as e:
        if not user_exiting.is_set():
            print(f"\n[!] Unexpected error: {e}")
        graceful_exit()

def main():
    global private_key, public_key, recipient_name

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("[!] Could not connect to the server.")
        return

    private_key, public_key = generate_rsa_keypair()
    public_key_bytes = serialize_public_key(public_key)

    try:
        name = input("Enter your name: ")
    except KeyboardInterrupt:
        graceful_exit()

    client.sendall(f"REGISTER::{name}".encode('utf-8'))
    client.sendall(public_key_bytes)

    print("Connected. Type messages and hit Enter to send.")
    print("Press Ctrl+C to disconnect at any time.")

    receiver_thread = threading.Thread(target=receive_messages, args=(client,))
    receiver_thread.start()

    try:
        while not keys_received_event.wait(0.5):
            if user_exiting.is_set():
                graceful_exit(client, receiver_thread)
    except KeyboardInterrupt:
        graceful_exit(client, receiver_thread)

    # Initial recipient selection
    notified_waiting = False
    while True:
        try:
            if not print_available_recipients():
                if not notified_waiting:
                    print("[!] No users available to message. Waiting for others to join...")
                    notified_waiting = True
                time.sleep(1)
                continue

            notified_waiting = False
            with recipient_lock:
                print("Available recipients:", ', '.join(public_key_registry.keys()))
                recipient_input = input("Who do you want to message? ").strip()
                if recipient_input in public_key_registry:
                    recipient_name = recipient_input
                    break
                else:
                    print(f"[!] '{recipient_input}' is not a valid user.")
        except KeyboardInterrupt:
            graceful_exit(client, receiver_thread)

    try:
        notified_no_users = False

        while True:
            # === STATE CHECK & RECIPIENT SELECTION ===
            with recipient_lock:
                if recipient_name is None or recipient_name not in public_key_registry:
                    print("\n[!] No recipient selected or your recipient has disconnected.")
                    while True:
                        has_users = print_available_recipients()
                        if has_users:
                            if notified_no_users:
                                print("Available recipients:", ', '.join(public_key_registry.keys()))
                            notified_no_users = False
                            try:
                                recipient_input = input("Who do you want to message? ").strip()
                                if recipient_input in public_key_registry:
                                    recipient_name = recipient_input
                                    print(f"You are now chatting with {recipient_name}.")
                                    break
                                else:
                                    print(f"[!] '{recipient_input}' is not a valid user.")
                            except KeyboardInterrupt:
                                graceful_exit(client, receiver_thread)
                        else:
                            if not notified_no_users:
                                print("[!] No users available to message. Waiting for others to join...")
                                notified_no_users = True
                            time.sleep(1)
                    continue

            # === MESSAGE SENDING ===
            # Capture recipient state BEFORE blocking for input
            with recipient_lock:
                current_recipient_for_msg = recipient_name
                recipient_public_key = public_key_registry.get(current_recipient_for_msg)

            try:
                msg = input("You: ")
            except KeyboardInterrupt:
                graceful_exit(client, receiver_thread)

            # CRITICAL: Re-check state AFTER blocking to prevent race condition
            with recipient_lock:
                if recipient_name != current_recipient_for_msg:
                    print(f"\n[!] Message not sent. {current_recipient_for_msg} disconnected while you were typing.")
                    continue

            if not recipient_public_key:
                print(f"[!] No public key for {current_recipient_for_msg}. Message not sent.")
                continue

            aes_key = generate_aes_key()
            ciphertext = aes_encrypt(msg, aes_key)
            encrypted_key = encrypt_key_with_rsa(aes_key, recipient_public_key)

            message_package = {
                "from": name,
                "to": current_recipient_for_msg,
                "aes_key": encrypted_key.hex(),
                "message": ciphertext.hex()
            }

            client.sendall(json.dumps(message_package).encode('utf-8'))

    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
        if not user_exiting.is_set():
            print("\n[!] Server connection lost.")
    finally:
        graceful_exit(client, receiver_thread)

if __name__ == "__main__":
    main()