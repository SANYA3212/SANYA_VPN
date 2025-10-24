#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SANYA-VPN Client Setup and GUI

This script provides a graphical user interface (GUI) for managing a Tailscale VPN
connection on a Windows client. It allows the user to connect to and disconnect
from a specified Tailscale exit node (e.g., a Raspberry Pi). The GUI displays
real-time status information about the connection.
"""

import subprocess
import os
import sys
import logging
import platform
import webbrowser
import threading
import time
import queue
from tkinter import (Tk, Label, Button, Text, END, Frame, Entry, StringVar,
                     Toplevel, messagebox)
from tkinter.scrolledtext import ScrolledText

# --- Constants ---
APP_TITLE = "SANYA-VPN Client"
WINDOW_GEOMETRY = "600x550"
LOG_LEVEL = logging.INFO
UPDATE_INTERVAL_MS = 5000  # 5 seconds
TAILSCALE_DOWNLOAD_URL = "https://tailscale.com/download/windows"

# --- Logging Setup ---
def setup_logging(log_queue):
    """
    Configures logging to direct messages to a queue for the GUI.
    """
    logging.basicConfig(
        level=LOG_LEVEL,
        format='%(asctime)s - %(levelname)s - %(message)s',
    )
    # Add a handler that puts log records into the queue
    queue_handler = QueueHandler(log_queue)
    logging.getLogger().addHandler(queue_handler)

class QueueHandler(logging.Handler):
    """
    A logging handler that directs records to a queue.
    Used to pass log messages from worker threads to the main GUI thread.
    """
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(self.format(record))

# --- Core VPN Logic ---
class VpnLogic:
    """
    Handles all the backend logic for interacting with Tailscale.
    """
    def __init__(self):
        self.tailscale_path = self._find_tailscale_exe()

    def _find_tailscale_exe(self):
        """
        Locates the tailscale.exe executable in common installation paths.

        Returns:
            str: The full path to tailscale.exe, or None if not found.
        """
        search_paths = [
            os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Tailscale"),
            os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Tailscale"),
        ]
        for path in search_paths:
            full_path = os.path.join(path, "tailscale.exe")
            if os.path.exists(full_path):
                logging.info(f"Found Tailscale at: {full_path}")
                return full_path
        logging.warning("tailscale.exe not found in standard locations.")
        return None

    def run_command(self, command, check=True):
        """
        Executes a shell command using subprocess.

        Args:
            command (list): The command to execute.
            check (bool): Whether to raise an exception on a non-zero exit code.

        Returns:
            subprocess.CompletedProcess: The result of the command.
        """
        logging.info(f"Running command: {' '.join(command)}")
        try:
            # On Windows, it's safer to hide the console window
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=check,
                encoding='utf-8',
                startupinfo=startupinfo
            )
            if result.stdout:
                logging.info(f"Output: {result.stdout.strip()}")
            if result.stderr:
                logging.warning(f"Errors/Warnings: {result.stderr.strip()}")
            return result
        except FileNotFoundError:
            logging.error(f"Command not found: {command[0]}. Is Tailscale installed?")
            raise
        except subprocess.CalledProcessError as e:
            logging.error(f"Command failed: {' '.join(command)}")
            logging.error(f"STDOUT: {e.stdout.strip()}")
            logging.error(f"STDERR: {e.stderr.strip()}")
            raise
        return None

    def ensure_installed(self):
        """
        Checks if Tailscale is installed and prompts the user to install it if not.
        """
        if self.tailscale_path:
            return True
        logging.error("Tailscale installation not found.")
        if messagebox.askyesno(
            "Tailscale Not Found",
            "SANYA-VPN requires Tailscale. Would you like to open the download page?"
        ):
            webbrowser.open(TAILSCALE_DOWNLOAD_URL)
        return False

    def login(self):
        """
        Logs into Tailscale, using auth key if available, otherwise interactive.
        """
        logging.info("Checking login status...")
        try:
            status_res = self.run_command([self.tailscale_path, 'status'], check=False)
            if status_res.returncode == 0 and "Logged out" not in status_res.stdout:
                logging.info("Already logged in.")
                return

            auth_key = os.environ.get('TS_AUTHKEY')
            cmd = [self.tailscale_path, 'up']
            if auth_key:
                logging.info("Using TS_AUTHKEY for login.")
                cmd.extend(['--auth-key', auth_key])
            else:
                logging.info("Starting interactive login. Please check your browser.")

            self.run_command(cmd)
            logging.info("Login successful.")

        except Exception as e:
            logging.error(f"Failed to log in: {e}")

    def connect_to_exit_node(self, node_id):
        """
        Connects to a specified exit node.

        Args:
            node_id (str): The Tailscale IP or name of the exit node.
        """
        if not node_id:
            logging.error("Exit node ID/IP cannot be empty.")
            messagebox.showerror("Error", "Please provide an exit node IP or name.")
            return
        logging.info(f"Connecting to exit node: {node_id}...")
        try:
            cmd = [
                self.tailscale_path, 'up',
                f'--exit-node={node_id}',
                '--accept-routes',
                '--accept-dns=true' # Ensure DNS is also routed
            ]
            self.run_command(cmd)
            logging.info("Successfully set exit node.")
        except Exception as e:
            logging.error(f"Failed to connect to exit node: {e}")

    def disconnect_from_exit_node(self):
        """
        Disconnects from the current exit node.
        """
        logging.info("Disconnecting from exit node...")
        try:
            # The correct way to disable an exit node is to set it to empty
            cmd = [self.tailscale_path, 'set', '--exit-node=']
            self.run_command(cmd)
            # Alternative: tailscale up --exit-node=""
            logging.info("Successfully disconnected from exit node.")
        except Exception as e:
            logging.error(f"Failed to disconnect: {e}")

    def get_status(self):
        """
        Fetches various status metrics.

        Returns:
            dict: A dictionary containing status information.
        """
        status = {
            'ping_8888': 'N/A',
            'tailscale_status': 'Not Running',
            'exit_node_status': 'Disconnected',
            'external_ip': 'N/A'
        }
        if not self.tailscale_path:
            return status

        # 1. Tailscale Status
        try:
            res = self.run_command([self.tailscale_path, 'status'], check=True)
            if "Running" in res.stdout:
                status['tailscale_status'] = 'Connected'
            else:
                 status['tailscale_status'] = 'Stopped'

            # Check for exit node status in the output
            if "exit node:" in res.stdout:
                status['exit_node_status'] = 'Connected'
            else:
                status['exit_node_status'] = 'Disconnected'
        except Exception:
            status['tailscale_status'] = 'Error'

        # 2. Ping 8.8.8.8
        try:
            # Use a short timeout and a single ping
            res = self.run_command(['ping', '-n', '1', '-w', '1000', '8.8.8.8'], check=True)
            if "Reply from" in res.stdout:
                status['ping_8888'] = 'OK'
            else:
                status['ping_8888'] = 'Timeout'
        except Exception:
            status['ping_8888'] = 'Failed'

        # 3. External IP
        try:
            # Use powershell's Invoke-RestMethod for a native way to get IP
            cmd = ['powershell', '-command', '(Invoke-RestMethod -Uri "https://ifconfig.me/ip").Trim()']
            res = self.run_command(cmd, check=True)
            status['external_ip'] = res.stdout.strip()
        except Exception:
            status['external_ip'] = 'Failed'

        return status

# --- GUI Application ---
class App(Tk):
    """
    The main GUI application window.
    """
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(WINDOW_GEOMETRY)

        self.log_queue = queue.Queue()
        setup_logging(self.log_queue)

        self.vpn = VpnLogic()

        self.exit_node_ip = StringVar()

        self._create_widgets()
        self.after(100, self._process_log_queue)

        # Initial check and status update
        self.after(500, self.run_initial_checks)
        self.after(1000, self.start_status_updates)

        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _create_widgets(self):
        """
        Creates and arranges all the widgets in the main window.
        """
        # --- Main Frames ---
        top_frame = Frame(self, padx=10, pady=10)
        top_frame.pack(fill='x')

        status_frame = Frame(self, padx=10, pady=5, relief='groove', borderwidth=2)
        status_frame.pack(fill='x', expand=False)

        log_frame = Frame(self, padx=10, pady=10)
        log_frame.pack(fill='both', expand=True)

        # --- Top Frame: Controls ---
        Label(top_frame, text="Exit Node IP/Name:", font=('Helvetica', 10, 'bold')).grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.exit_node_entry = Entry(top_frame, textvariable=self.exit_node_ip, width=30)
        self.exit_node_entry.grid(row=0, column=1, padx=5, pady=5)

        self.connect_button = Button(top_frame, text="Connect to Exit Node", command=self._connect_action)
        self.connect_button.grid(row=1, column=0, pady=10, padx=5)

        self.disconnect_button = Button(top_frame, text="Disconnect", command=self._disconnect_action)
        self.disconnect_button.grid(row=1, column=1, pady=10, padx=5)

        # --- Status Frame: Indicators ---
        Label(status_frame, text="Status", font=('Helvetica', 12, 'bold')).grid(row=0, columnspan=2, pady=5)

        self.status_labels = {
            'ping_8888': Label(status_frame, text="Ping 8.8.8.8: N/A"),
            'tailscale_status': Label(status_frame, text="Tailscale: N/A"),
            'exit_node_status': Label(status_frame, text="Exit Node: N/A"),
            'external_ip': Label(status_frame, text="External IP: N/A")
        }
        r = 1
        for key, label in self.status_labels.items():
            label.grid(row=r, column=0, sticky='w', padx=10)
            r += 1

        # --- Log Frame: Log Viewer ---
        Label(log_frame, text="Logs", font=('Helvetica', 10, 'bold')).pack(anchor='w')
        self.log_text = ScrolledText(log_frame, state='disabled', height=15, wrap='word')
        self.log_text.pack(fill='both', expand=True)

    def _log(self, message):
        """
        Appends a message to the log viewer widget.
        """
        self.log_text.configure(state='normal')
        self.log_text.insert(END, message + '\n')
        self.log_text.see(END)
        self.log_text.configure(state='disabled')

    def _process_log_queue(self):
        """
        Processes messages from the logging queue and displays them in the GUI.
        """
        while not self.log_queue.empty():
            message = self.log_queue.get_nowait()
            self._log(message)
        self.after(100, self._process_log_queue)

    def _run_in_thread(self, target_func, *args):
        """
        Runs a function in a separate thread to avoid blocking the GUI.
        """
        thread = threading.Thread(target=target_func, args=args, daemon=True)
        thread.start()

    def _connect_action(self):
        node_id = self.exit_node_ip.get()
        self._run_in_thread(self.vpn.connect_to_exit_node, node_id)

    def _disconnect_action(self):
        self._run_in_thread(self.vpn.disconnect_from_exit_node)

    def _update_status_display(self, status):
        """
        Updates the status labels in the GUI based on the provided status dict.
        """
        self.status_labels['ping_8888'].config(text=f"Ping 8.8.8.8: {status['ping_8888']}")
        self.status_labels['tailscale_status'].config(text=f"Tailscale Status: {status['tailscale_status']}")
        self.status_labels['exit_node_status'].config(text=f"Exit Node: {status['exit_node_status']}")
        self.status_labels['external_ip'].config(text=f"External IP: {status['external_ip']}")

        # Color coding for clarity
        self.status_labels['exit_node_status'].config(fg='green' if status['exit_node_status'] == 'Connected' else 'red')
        self.status_labels['ping_8888'].config(fg='green' if status['ping_8888'] == 'OK' else 'red')

    def _update_status_periodically(self):
        """
        The function that runs periodically to fetch and display the latest status.
        """
        status = self.vpn.get_status()
        self._update_status_display(status)
        self.after(UPDATE_INTERVAL_MS, self._update_status_periodically)

    def run_initial_checks(self):
        """
        Performs initial checks for Tailscale installation and login.
        """
        logging.info("Running initial checks...")
        if self.vpn.ensure_installed():
            self._run_in_thread(self.vpn.login)
        else:
            self.connect_button.config(state='disabled')
            self.disconnect_button.config(state='disabled')

    def start_status_updates(self):
        """
        Kicks off the periodic status update loop.
        """
        if self.vpn.tailscale_path:
             self._update_status_periodically()

    def _on_closing(self):
        """
        Handles the window closing event.
        """
        if messagebox.askokcancel("Quit", "Do you want to quit SANYA-VPN?"):
            self.destroy()

# --- Main Execution ---
def main():
    """
    Main entry point for the SANYA-VPN client application.
    """
    # Check for Windows
    if platform.system() != "Windows":
        print("This client application is designed for Windows only.", file=sys.stderr)
        # Fallback for non-windows to show an error dialog
        root = Tk()
        root.withdraw()
        messagebox.showerror("Compatibility Error", "This application is for Windows only.")
        sys.exit(1)

    # Launch GUI
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
