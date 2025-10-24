#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SANYA-VPN Client Setup and GUI

This script provides a streamlined graphical user interface (GUI) for managing a
Tailscale VPN connection on a Windows client. It features a clean dark theme,
persistent configuration, and accurate, real-time status indicators.
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
import re
from tkinter import Tk, Label, Button, Frame, Entry, StringVar, messagebox, Canvas

# --- Constants ---
APP_TITLE = "SANYA-VPN Client"
WINDOW_GEOMETRY = "480x320"
LOG_LEVEL = logging.INFO
UPDATE_INTERVAL_MS = 3000  # 3 seconds
TAILSCALE_DOWNLOAD_URL = "https://tailscale.com/download/windows"
CONFIG_FILE = "config.json"

# --- Dark Theme Colors ---
Colors = {
    "BG": "#282c34", "FG": "#abb2bf", "FRAME": "#3c4049",
    "BUTTON_BG": "#61afef", "BUTTON_FG": "#282c34",
    "ENTRY_BG": "#21252b", "ENTRY_FG": "#abb2bf",
    "SUCCESS": "#98c379", "ERROR": "#e06c75", "OFF": "#5c6370"
}

# --- Logging Setup ---
# Setup a dummy logger that does nothing to keep the VpnLogic class clean
# while removing the visual log console from the UI.
logging.basicConfig(level=logging.CRITICAL, format='%(asctime)s - %(message)s')

# --- Core VPN Logic ---
class VpnLogic:
    def __init__(self):
        self.tailscale_path = self._find_tailscale_exe()

    def _find_tailscale_exe(self):
        for path_var in ['ProgramFiles', 'ProgramFiles(x86)']:
            base_path = os.environ.get(path_var)
            if base_path:
                full_path = os.path.join(base_path, "Tailscale", "tailscale.exe")
                if os.path.exists(full_path):
                    logging.info(f"Found Tailscale at: {full_path}")
                    return full_path
        logging.warning("tailscale.exe not found.")
        return None

    def run_command(self, command, check=True):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return subprocess.run(
            command, capture_output=True, text=True, check=check,
            encoding=locale.getpreferredencoding(), startupinfo=startupinfo
        )

    def login(self):
        if "Logged out" not in self.run_command([self.tailscale_path, 'status'], check=False).stdout:
            return
        self.run_command([self.tailscale_path, 'up'])

    def connect_to_exit_node(self, node_id):
        if not node_id: return
        try:
            self.run_command([self.tailscale_path, 'up', f'--exit-node={node_id}', '--accept-routes'])
        except subprocess.CalledProcessError:
            logging.error("Failed to connect. Is the exit node approved?")

    def disconnect_from_exit_node(self):
        self.run_command([self.tailscale_path, 'set', '--exit-node='])

    def get_status(self, exit_node_ip):
        status = {'vpn_status': 'Disabled', 'raspi_status': 'Offline', 'internet_status': 'Offline', 'ping_ms': 'N/A'}
        if not self.tailscale_path: return status

        try:
            # Check VPN Status from Tailscale output
            ts_status_out = self.run_command([self.tailscale_path, 'status'], check=True).stdout
            if f"exit node: {exit_node_ip}" in ts_status_out or (f"exit node: " in ts_status_out and exit_node_ip in ts_status_out):
                status['vpn_status'] = 'Enabled'
        except Exception:
            status['vpn_status'] = 'Disabled'

        # Check Internet Status (ping 8.8.8.8)
        try:
            self.run_command(['ping', '-n', '1', '-w', '1000', '8.8.8.8'], check=True)
            status['internet_status'] = 'Online'
        except Exception:
            status['internet_status'] = 'Offline'

        # Check Raspberry Pi Status and Ping
        if exit_node_ip:
            try:
                ping_res = self.run_command(['ping', '-n', '1', '-w', '1000', exit_node_ip], check=True).stdout
                status['raspi_status'] = 'Online'
                # Universal regex for ping time, looks for " = 123ms" or " = 123 мс"
                match = re.search(r"=\s*(\d+)\s*ms", ping_res, re.IGNORECASE)
                if match:
                    status['ping_ms'] = f"{match.group(1)} ms"
            except Exception:
                status['raspi_status'] = 'Offline'
                status['ping_ms'] = 'Timeout'

        return status

# --- GUI Application ---
class App(Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(WINDOW_GEOMETRY)
        self.configure(bg=Colors["BG"])
        self.resizable(False, False)

        self.vpn = VpnLogic()
        self.exit_node_ip = StringVar()
        self._load_config()

        self._create_widgets()

        self.after(500, self._run_initial_checks)
        self.status_update_job = None
        self._update_status_periodically()

        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f: self.exit_node_ip.set(json.load(f).get("exit_node_ip", ""))

    def _save_config(self):
        with open(CONFIG_FILE, 'w') as f: json.dump({"exit_node_ip": self.exit_node_ip.get()}, f)

    def _create_widgets(self):
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

        status_frame = Frame(self, padx=15, pady=10, bg=Colors["BG"])
        status_frame.pack(fill='both', expand=True)
        self.status_widgets = {
            'vpn_status': self._create_status_indicator(status_frame, "VPN Status"),
            'raspi_status': self._create_status_indicator(status_frame, "Raspberry Pi"),
            'internet_status': self._create_status_indicator(status_frame, "Internet Access"),
        }
        self.ping_label = self._create_ping_display(status_frame, "Ping to Pi:")

    def _create_status_indicator(self, parent, text):
        frame = Frame(parent, bg=Colors["BG"]); frame.pack(fill='x', pady=5)
        Label(frame, text=text, bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 11)).pack(side='left')
        canvas = Canvas(frame, width=20, height=20, bg=Colors["BG"], highlightthickness=0); canvas.pack(side='right')
        indicator_id = canvas.create_oval(5, 5, 18, 18, fill=Colors["OFF"], outline="")
        return canvas, indicator_id

    def _create_ping_display(self, parent, text):
        frame = Frame(parent, bg=Colors["BG"]); frame.pack(fill='x', pady=5)
        Label(frame, text=text, bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 11)).pack(side='left')
        ping_label = Label(frame, text="N/A", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 11, "bold"))
        ping_label.pack(side='right')
        return ping_label

    def _run_in_thread(self, target, *args):
        threading.Thread(target=target, args=args, daemon=True).start()

    def _connect_action(self):
        self._save_config()
        if not self.exit_node_ip.get():
            messagebox.showwarning("Input Required", "Please enter the Raspberry Pi's IP.")
            return
        self._run_in_thread(self.vpn.connect_to_exit_node, self.exit_node_ip.get())

    def _disconnect_action(self):
        self._run_in_thread(self.vpn.disconnect_from_exit_node)

    def _run_initial_checks(self):
        if not self.vpn.tailscale_path:
            if messagebox.askyesno("Tailscale Not Found", "Download Tailscale?"): webbrowser.open(TAILSCALE_DOWNLOAD_URL)
            self.destroy()
        else: self._run_in_thread(self.vpn.login)

    def _update_status_periodically(self):
        def worker():
            status = self.vpn.get_status(self.exit_node_ip.get())
            self.after(0, self._update_ui, status)
            self.status_update_job = self.after(UPDATE_INTERVAL_MS, self._update_status_periodically)
        self._run_in_thread(worker)

    def _update_ui(self, status):
        for key, s in status.items():
            if key in self.status_widgets:
                canvas, indicator_id = self.status_widgets[key]
                color = Colors["SUCCESS"] if s in ['Online', 'Enabled'] else Colors["ERROR"]
                canvas.itemconfig(indicator_id, fill=color)
        self.ping_label.config(text=status['ping_ms'])

    def _on_closing(self):
        self._save_config()
        if self.status_update_job: self.after_cancel(self.status_update_job)
        self.destroy()

def main():
    if platform.system() != "Windows":
        messagebox.showerror("Error", "This application is for Windows only.")
        sys.exit(1)
    App().mainloop()

if __name__ == "__main__":
    main()
