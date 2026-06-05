import socket
import threading
import json
import time
import sys
from crypto_utils import (
    generate_rsa_keypair,
    serialize_public_key,
    deserialize_public_key,
    generate_ecdh_keypair,
    serialize_ecdh_public_key,
    deserialize_ecdh_public_key,
    derive_shared_key,
    aes_encrypt,
    aes_decrypt,
    sign_message,
    verify_signature,
    key_fingerprint,
)
import queue
from prompt_toolkit import print_formatted_text


HOST = '127.0.0.1'
PORT = 65432
input_queue = queue.Queue()
public_key_registry = {}
ecdh_key_registry = {}
recipient_name = None
recipient_lock = threading.Lock()
keys_received_event = threading.Event()
user_exiting = threading.Event()
prompt_should_abort = threading.Event()
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

def receive_messages(client_socket, client_name):
    global recipient_name
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
                            ecdh_key_registry.clear()
                            for user, key_data in new_keys.items():
                                if user != client_name:
                                    public_key_registry[user] = deserialize_public_key(key_data['rsa'].encode('utf-8'))
                                    ecdh_key_registry[user] = deserialize_ecdh_public_key(key_data['ecdh'].encode('utf-8'))
                            for user, pubkey in public_key_registry.items():
                                fp = key_fingerprint(pubkey)
                                print_formatted_text(f"\n[key] {user}: {fp}")
                        keys_received_event.set()
                        continue

                    elif payload.get("type") == "error":
                        print_formatted_text(f"\n[!] Server error: {payload.get('message')}")
                        with recipient_lock:
                            recipient_name = None
                        continue

                    sender = payload['from']
                    encrypted_msg = bytes.fromhex(payload['message'])
                    sig_hex = payload.get('signature', '')

                    if not sig_hex:
                        print_formatted_text(f"\n[!] no signature on message from {sender}, dropping")
                        continue

                    with recipient_lock:
                        sender_pubkey = public_key_registry.get(sender)
                        sender_ecdh_pub = ecdh_key_registry.get(sender)

                    if sender_pubkey is None or not verify_signature(encrypted_msg, bytes.fromhex(sig_hex), sender_pubkey):
                        print_formatted_text(f"\n[!] bad signature on message from {sender}, dropping")
                        continue

                    if sender_ecdh_pub is None:
                        print_formatted_text(f"\n[!] no ECDH key for {sender}, dropping")
                        continue

                    shared_key = derive_shared_key(ecdh_private_key, sender_ecdh_pub)
                    plaintext = aes_decrypt(encrypted_msg, shared_key)

                    print_formatted_text(f"\n{sender}: {plaintext}")

                except Exception as e:
                    print(f"\n[!] Error decrypting message: {e}")
            else:
                if decoded.startswith("User ") and decoded.endswith(" disconnected."):
                    left_user = decoded.split(" ")[1]
                    with recipient_lock:
                        if recipient_name == left_user:
                            recipient_name = None
                        if left_user in public_key_registry:
                            del public_key_registry[left_user]
                        if left_user in ecdh_key_registry:
                            del ecdh_key_registry[left_user]
                    print_formatted_text(f"\n[!] {decoded}")
                    continue



                print_formatted_text(f"\n{decoded}")

    except (ConnectionResetError, ConnectionAbortedError, OSError):
        if not user_exiting.is_set():
            print("\n[!] Server connection lost.")
        graceful_exit()
    except Exception as e:
        if not user_exiting.is_set():
            print(f"\n[!] Unexpected error: {e}")
        graceful_exit()

def main():
    global private_key, public_key, ecdh_private_key, ecdh_public_key, recipient_name

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("[!] Could not connect to the server.")
        return

    private_key, public_key = generate_rsa_keypair()
    ecdh_private_key, ecdh_public_key = generate_ecdh_keypair()

    try:
        name = input("Enter your name: ")
    except KeyboardInterrupt:
        graceful_exit()

    client.sendall(f"REGISTER::{name}".encode('utf-8'))
    key_payload = json.dumps({
        "rsa": serialize_public_key(public_key).decode('utf-8'),
        "ecdh": serialize_ecdh_public_key(ecdh_public_key).decode('utf-8')
    }).encode('utf-8')
    client.sendall(key_payload)

    print("Connected. Type messages and hit Enter to send.")
    print("Press Ctrl+C to disconnect at any time.")
    


    receiver_thread = threading.Thread(target=receive_messages, args=(client, name))
    receiver_thread.start()

    try:
        while not keys_received_event.wait(0.5):
            if user_exiting.is_set():
                graceful_exit(client, receiver_thread)
    except KeyboardInterrupt:
        graceful_exit(client, receiver_thread)

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
            message_loop_thread(client, name, receiver_thread)
            break  
            

    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
        if not user_exiting.is_set():
            print("\n[!] Server connection lost.")
    finally:
        graceful_exit(client, receiver_thread)


def message_loop_thread(client, name, receiver_thread):
    global recipient_name

    input_queue = queue.Queue()

    def input_thread_loop():
        try:
            while True:
                msg = input("You: ")
                input_queue.put(msg)
        except (KeyboardInterrupt, EOFError):
            graceful_exit(client, receiver_thread)

    input_thread = threading.Thread(target=input_thread_loop)
    input_thread.daemon = True
    input_thread.start()

    try:
        while True:
            if user_exiting.is_set():
                return

            with recipient_lock:
                if recipient_name is None or recipient_name not in public_key_registry:
                    print("\n[!] No recipient selected or your recipient has disconnected.")
                    return

                current_recipient_for_msg = recipient_name
                recipient_ecdh_pub = ecdh_key_registry.get(current_recipient_for_msg)

            try:
                msg = input_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            with recipient_lock:
                if recipient_name != current_recipient_for_msg:
                    print(f"\n[!] Message not sent. {current_recipient_for_msg} disconnected while you were typing.")
                    continue

            if not recipient_ecdh_pub:
                print(f"[!] No ECDH key for {current_recipient_for_msg}. Message not sent.")
                continue

            shared_key = derive_shared_key(ecdh_private_key, recipient_ecdh_pub)
            ciphertext = aes_encrypt(msg, shared_key)
            signature = sign_message(ciphertext, private_key)

            message_package = {
                "from": name,
                "to": current_recipient_for_msg,
                "message": ciphertext.hex(),
                "signature": signature.hex()
            }

            try:
                client.sendall(json.dumps(message_package).encode('utf-8'))
            except (BrokenPipeError, ConnectionResetError, OSError):
                print("\n[!] Server connection lost.")
                graceful_exit(client, receiver_thread)
    except KeyboardInterrupt:
        graceful_exit(client, receiver_thread)



if __name__ == "__main__":
    main()
