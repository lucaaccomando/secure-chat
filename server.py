import socket
import threading
import sys
import json
import time

HOST = '127.0.0.1'
PORT = 65432

clients = {}         # name -> socket
public_keys = {}     # name -> public_key_bytes

def broadcast(message, sender_name):
    for name, client_sock in list(clients.items()):
        if name != sender_name:
            try:
                client_sock.sendall(message)
            except:
                client_sock.close()
                del clients[name]
                if name in public_keys:
                    del public_keys[name]

def handle_client(client_socket, address):
    name = None
    try:
        register_msg = client_socket.recv(1024).decode('utf-8')
        if not register_msg.startswith("REGISTER::"):
            print("[!] Invalid registration message.")
            client_socket.close()
            return

        name = register_msg.replace("REGISTER::", "").strip()
        public_key_bytes = client_socket.recv(2048)
        public_keys[name] = public_key_bytes
        clients[name] = client_socket
        
        # Small delay to ensure proper synchronization
        time.sleep(0.1)
        sync_keys_to_all()
        broadcast(f"{name} has joined the chat.".encode('utf-8'), sender_name=name)

        print(f"[+] {name} connected from {address}")

        while True:
            try:
                message = client_socket.recv(4096)
                if not message:
                    break

                try:
                    decoded = message.decode('utf-8')
                    if decoded.startswith('{') and decoded.endswith('}'):
                        payload = json.loads(decoded)
                        recipient = payload.get("to")
                        
                        if recipient in clients:
                            try:
                                clients[recipient].sendall(message)
                            except:
                                # If sending fails, treat as disconnected
                                print(f"[!] Failed to send to {recipient}")
                                clients[recipient].close()
                                del clients[recipient]
                                if recipient in public_keys:
                                    del public_keys[recipient]
                                broadcast(f"{recipient} has left the chat.".encode('utf-8'), sender_name=None)
                                sync_keys_to_all()
                                
                                # Notify sender about the failure
                                error_response = json.dumps({
                                    "type": "error",
                                    "message": f"Recipient '{recipient}' disconnected during delivery."
                                }).encode('utf-8')
                                client_socket.sendall(error_response)
                        else:
                            print(f"[!] Recipient '{recipient}' not connected.")
                            error_response = json.dumps({
                                "type": "error",
                                "message": f"Recipient '{recipient}' is not connected."
                            }).encode('utf-8')
                            client_socket.sendall(error_response)
                    else:
                        broadcast(message, name)

                except json.JSONDecodeError:
                    print(f"[!] Invalid JSON from {name}")
                except Exception as e:
                    print(f"[!] Failed to route message from {name}: {e}")

            except (ConnectionResetError, ConnectionAbortedError):
                break
            except Exception as e:
                if "WinError 10053" not in str(e):
                    print(f"[!] Error receiving from {name}: {e}")
                break

    finally:
        print(f"[-] {name if name else address} disconnected.")
        try:
            client_socket.close()
        except:
            pass
            
        if name in clients:
            del clients[name]
        if name in public_keys:
            del public_keys[name]
        
        if name:
            try:
                broadcast(f"{name} has left the chat.".encode('utf-8'), sender_name=None)
                sync_keys_to_all()
            except:
                pass

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    server.settimeout(1.0) 
    print(f"[*] Server listening on {HOST}:{PORT}")
    print("[*] Press Ctrl+C to stop the server.")
    try:
        while True:
            try:
                client_socket, addr = server.accept()
                thread = threading.Thread(target=handle_client, args=(client_socket, addr))
                thread.start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\n[!] Server shutting down...")
    finally:
        for sock in clients.values():
            try:
                sock.close()
            except:
                pass
        server.close()
        print("[*] Server stopped.")

def sync_keys_to_all():
    for target_name, sock in clients.items():
        try:
            other_keys = {
                user: public_keys[user].decode('utf-8')
                for user in public_keys if user != target_name
            }
            payload = json.dumps({"type": "key_sync", "keys": other_keys}).encode('utf-8')
            sock.sendall(payload)
        except:
            continue

if __name__ == "__main__":
    start_server()