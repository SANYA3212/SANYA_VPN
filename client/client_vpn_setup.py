#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SANYA-VPN Client Setup and GUI

This script provides an improved graphical user interface (GUI) for managing a
Tailscale VPN connection on a Windows client. It features a dark theme, persistent
configuration, and clear, real-time status indicators.
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
import json
import locale
from tkinter import Tk, Label, Button, Frame, Entry, StringVar, messagebox, Canvas, END
from tkinter.scrolledtext import ScrolledText

# --- Constants ---
APP_TITLE = "SANYA-VPN Client"
WINDOW_GEOMETRY = "500x500"
LOG_LEVEL = logging.INFO
UPDATE_INTERVAL_MS = 5000  # 5 seconds
TAILSCALE_DOWNLOAD_URL = "https://tailscale.com/download/windows"
CONFIG_FILE = "config.json"

# --- Dark Theme Colors ---
Colors = {
    "BG": "#282c34",
    "FG": "#abb2bf",
    "FRAME": "#3c4049",
    "BUTTON_BG": "#61afef",
    "BUTTON_FG": "#282c34",
    "ENTRY_BG": "#21252b",
    "ENTRY_FG": "#abb2bf",
    "LOG_BG": "#21252b",
    "LOG_FG": "#abb2bf",
    "SUCCESS": "#98c379", # Green
    "ERROR": "#e06c75",   # Red
    "WARN": "#d19a66",   # Orange
    "OFF": "#5c6370"     # Gray
}

# --- Logging Setup ---
# (Identical to previous version, kept for brevity)
def setup_logging(log_queue):
    logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s - %(levelname)s - %(message)s')
    queue_handler = QueueHandler(log_queue)
    logging.getLogger().addHandler(queue_handler)

class QueueHandler(logging.Handler):
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue
    def emit(self, record):
        self.log_queue.put(self.format(record))


# --- Core VPN Logic ---
class VpnLogic:
    """
    Handles all the backend logic for interacting with Tailscale.
    This class is designed to be run from worker threads.
    """
    def __init__(self):
        self.tailscale_path = self._find_tailscale_exe()

    def _find_tailscale_exe(self):
        search_paths = [
            os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Tailscale"),
            os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Tailscale"),
        ]
        for path in search_paths:
            full_path = os.path.join(path, "tailscale.exe")
            if os.path.exists(full_path):
                logging.info(f"Found Tailscale at: {full_path}")
                return full_path
        logging.warning("tailscale.exe not found.")
        return None

    def run_command(self, command, check=True):
        logging.info(f"Running command: {' '.join(command)}")
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        result = subprocess.run(
            command, capture_output=True, text=True, check=check,
            encoding=locale.getpreferredencoding(), startupinfo=startupinfo
        )
        if result.stdout: logging.info(f"Output: {result.stdout.strip()}")
        if result.stderr: logging.warning(f"Errors/Warnings: {result.stderr.strip()}")
        return result

    def ensure_installed(self):
        return self.tailscale_path is not None

    def login(self):
        logging.info("Checking login status...")
        status_res = self.run_command([self.tailscale_path, 'status'], check=False)
        if status_res.returncode == 0 and "Logged out" not in status_res.stdout:
            logging.info("Already logged in.")
            return "Already Logged In"

        auth_key = os.environ.get('TS_AUTHKEY')
        cmd = [self.tailscale_path, 'up']
        if auth_key:
            logging.info("Using TS_AUTHKEY for login.")
            cmd.extend(['--auth-key', auth_key])
        else:
            logging.info("Starting interactive login.")
        self.run_command(cmd)
        return "Login Successful"

    def connect_to_exit_node(self, node_id):
        if not node_id:
            logging.error("Exit node IP cannot be empty.")
            return "Error: No IP"
        logging.info(f"Connecting to exit node: {node_id}...")
        try:
            cmd = [self.tailscale_path, 'up', f'--exit-node={node_id}', '--accept-routes', '--accept-dns=true']
            self.run_command(cmd)
            return "Connection Attempted"
        except subprocess.CalledProcessError:
            logging.error("Failed to connect. Is the exit node approved in the admin console?")
            return "Connection Failed"

    def disconnect_from_exit_node(self):
        logging.info("Disconnecting from exit node...")
        cmd = [self.tailscale_path, 'set', '--exit-node=']
        self.run_command(cmd)
        return "Disconnection Attempted"

    def get_status(self, exit_node_ip):
        """Fetches all status metrics."""
        status = {
            'vpn_status': 'Disabled', 'tailscale_status': 'Offline',
            'raspi_status': 'Offline', 'internet_status': 'Offline'
        }
        if not self.tailscale_path: return status

        # Tailscale and VPN status
        try:
            res = self.run_command([self.tailscale_path, 'status'], check=True)
            status['tailscale_status'] = 'Online' if "Running" in res.stdout else 'Offline'
            status['vpn_status'] = 'Enabled' if "exit node:" in res.stdout else 'Disabled'
        except Exception: pass

        # Internet Status (ping 8.8.8.8)
        try:
            self.run_command(['ping', '-n', '1', '-w', '1000', '8.8.8.8'], check=True)
            status['internet_status'] = 'Online'
        except Exception: pass

        # Raspberry Pi Status (Tailscale ping)
        if exit_node_ip and status['tailscale_status'] == 'Online':
            try:
                self.run_command([self.tailscale_path, 'ping', '--timeout=1s', '-c', '1', exit_node_ip], check=True)
                status['raspi_status'] = 'Online'
            except Exception: pass

        return status


# --- GUI Application ---
class App(Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(WINDOW_GEOMETRY)
        self.configure(bg=Colors["BG"])
        self.resizable(False, False)

        self.log_queue = queue.Queue()
        setup_logging(self.log_queue)

        self.vpn = VpnLogic()
        self.exit_node_ip = StringVar()
        self._load_config()

        self._create_widgets()
        self.after(100, self._process_log_queue)

        self.after(500, self.run_initial_checks)
        self.status_update_job = None
        self.start_status_updates()

        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.exit_node_ip.set(config.get("exit_node_ip", ""))
        except Exception as e:
            logging.error(f"Failed to load config: {e}")

    def _save_config(self):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump({"exit_node_ip": self.exit_node_ip.get()}, f)
        except Exception as e:
            logging.error(f"Failed to save config: {e}")

    def _create_widgets(self):
        # --- Controls Frame ---
        controls_frame = Frame(self, padx=15, pady=15, bg=Colors["BG"])
        controls_frame.pack(fill='x', side='top')
        Label(controls_frame, text="Raspberry Pi (Exit Node) IP:", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 10)).pack(anchor='w')
        self.ip_entry = Entry(controls_frame, textvariable=self.exit_node_ip, bg=Colors["ENTRY_BG"], fg=Colors["ENTRY_FG"], insertbackground=Colors["FG"], relief='flat', width=40)
        self.ip_entry.pack(fill='x', pady=5)

        buttons_frame = Frame(controls_frame, bg=Colors["BG"])
        buttons_frame.pack(pady=10)
        self.connect_button = Button(buttons_frame, text="Enable VPN", command=self._connect_action, bg=Colors["SUCCESS"], fg=Colors["BUTTON_FG"], relief='flat', font=("Helvetica", 10, "bold"), width=15)
        self.connect_button.pack(side='left', padx=10)
        self.disconnect_button = Button(buttons_frame, text="Disable VPN", command=self._disconnect_action, bg=Colors["ERROR"], fg=Colors["BUTTON_FG"], relief='flat', font=("Helvetica", 10, "bold"), width=15)
        self.disconnect_button.pack(side='left', padx=10)

        # --- Status Frame ---
        status_frame = Frame(self, padx=15, pady=10, bg=Colors["BG"])
        status_frame.pack(fill='both', expand=True)
        self.status_widgets = {
            'vpn_status': self._create_status_indicator(status_frame, "VPN Status"),
            'tailscale_status': self._create_status_indicator(status_frame, "Tailscale"),
            'raspi_status': self._create_status_indicator(status_frame, "Raspberry Pi"),
            'internet_status': self._create_status_indicator(status_frame, "Internet Access"),
        }

        # --- Log Frame ---
        log_frame = Frame(self, padx=15, pady=10, bg=Colors["BG"])
        log_frame.pack(fill='both', side='bottom')
        self.log_text = ScrolledText(log_frame, state='disabled', height=8, wrap='word', bg=Colors["LOG_BG"], fg=Colors["LOG_FG"], relief='flat')
        self.log_text.pack(fill='both', expand=True)

    def _create_status_indicator(self, parent, text):
        frame = Frame(parent, bg=Colors["BG"])
        frame.pack(fill='x', pady=4)
        label = Label(frame, text=text, bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 11))
        label.pack(side='left')
        canvas = Canvas(frame, width=20, height=20, bg=Colors["BG"], highlightthickness=0)
        canvas.pack(side='right')
        indicator = canvas.create_oval(5, 5, 18, 18, fill=Colors["OFF"], outline="")
        return canvas, indicator

    def _update_status_indicator(self, key, status):
        canvas, indicator = self.status_widgets[key]
        color = Colors["SUCCESS"] if status == 'Online' or status == 'Enabled' else Colors["ERROR"]
        canvas.itemconfig(indicator, fill=color)

    def _log(self, message):
        self.log_text.configure(state='normal')
        self.log_text.insert(END, message + '\n')
        self.log_text.see(END)
        self.log_text.configure(state='disabled')

    def _process_log_queue(self):
        while not self.log_queue.empty():
            self._log(self.log_queue.get_nowait())
        self.after(100, self._process_log_queue)

    def _run_in_thread(self, target_func, *args):
        threading.Thread(target=target_func, args=args, daemon=True).start()

    def _connect_action(self):
        self._save_config()
        node_id = self.exit_node_ip.get()
        if not node_id:
            messagebox.showwarning("Input Required", "Please enter the Raspberry Pi's Tailscale IP address.")
            return
        self._run_in_thread(self.vpn.connect_to_exit_node, node_id)

    def _disconnect_action(self):
        self._run_in_thread(self.vpn.disconnect_from_exit_node)

    def run_initial_checks(self):
        def check_and_login():
            if not self.vpn.ensure_installed():
                if messagebox.askyesno("Tailscale Not Found", "SANYA-VPN requires Tailscale. Open download page?"):
                    webbrowser.open(TAILSCALE_DOWNLOAD_URL)
                self.after(0, self.destroy)
                return
            try:
                self.vpn.login()
            except Exception as e:
                logging.error(f"Failed during initial login: {e}")
        self._run_in_thread(check_and_login)

    def start_status_updates(self):
        if self.status_update_job:
            self.after_cancel(self.status_update_job)
        self._run_in_thread(self._update_status_periodically)

    def _update_status_periodically(self):
        """Worker thread function to fetch status and schedule UI update."""
        try:
            node_ip = self.exit_node_ip.get()
            status = self.vpn.get_status(node_ip)
            # Schedule the UI update to run on the main thread
            self.after(0, self.update_ui_with_status, status)
        except Exception as e:
            logging.error(f"Error in status update loop: {e}")
        finally:
            # Reschedule the next update
            self.status_update_job = self.after(UPDATE_INTERVAL_MS, self.start_status_updates)

    def update_ui_with_status(self, status):
        """This method runs on the main thread to safely update the GUI."""
        for key, s in status.items():
            self._update_status_indicator(key, s)

    def _on_closing(self):
        self._save_config()
        if self.status_update_job:
            self.after_cancel(self.status_update_job)
        self.destroy()

def main():
    if platform.system() != "Windows":
        messagebox.showerror("Compatibility Error", "This application is for Windows only.")
        sys.exit(1)
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
