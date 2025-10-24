#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SANYA-VPN Client Setup and GUI

This script provides a streamlined graphical user interface (GUI) for managing a
Tailscale VPN connection on a Windows client. It is designed to be compiled into
a standalone executable using PyInstaller.
"""

import subprocess
import os
import sys
import logging
import platform
import webbrowser
import threading
import json
import locale
import re
from tkinter import Tk, Label, Button, Frame, Entry, StringVar, messagebox, Canvas

# --- Constants ---
APP_NAME = "SANYA-VPN"
APP_TITLE = f"{APP_NAME} Client"
WINDOW_GEOMETRY = "480x320"
UPDATE_INTERVAL_MS = 3000
TAILSCALE_DOWNLOAD_URL = "https://tailscale.com/download/windows"

# --- Configuration Path ---
# Store config in %APPDATA%\SANYA-VPN\config.json for EXE compatibility
APP_DATA_PATH = os.path.join(os.getenv('APPDATA'), APP_NAME)
CONFIG_FILE = os.path.join(APP_DATA_PATH, "config.json")

# --- Dark Theme Colors ---
Colors = {
    "BG": "#282c34", "FG": "#abb2bf", "FRAME": "#3c4049",
    "BUTTON_BG": "#61afef", "BUTTON_FG": "#282c34",
    "ENTRY_BG": "#21252b", "ENTRY_FG": "#abb2bf",
    "SUCCESS": "#98c379", "ERROR": "#e06c75", "OFF": "#5c6370"
}

# --- Logging (Disabled for UI) ---
logging.basicConfig(level=logging.CRITICAL)

# --- Core VPN Logic ---
class VpnLogic:
    def __init__(self):
        self.tailscale_path = self._find_tailscale_exe()

    def _find_tailscale_exe(self):
        for path_var in ['ProgramFiles', 'ProgramFiles(x86)']:
            base_path = os.environ.get(path_var)
            if base_path and os.path.exists(os.path.join(base_path, "Tailscale", "tailscale.exe")):
                return os.path.join(base_path, "Tailscale", "tailscale.exe")
        return None

    def run_command(self, command, check=True):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return subprocess.run(
            command, capture_output=True, text=True, check=check,
            encoding=locale.getpreferredencoding(), startupinfo=startupinfo
        )

    def connect_to_exit_node(self, node_id):
        if not node_id: return
        self.run_command([self.tailscale_path, 'up', f'--exit-node={node_id}', '--accept-routes'], check=False)

    def disconnect_from_exit_node(self):
        self.run_command([self.tailscale_path, 'set', '--exit-node='])

    def get_status(self, exit_node_ip):
        status = {'raspi_status': 'Offline', 'internet_status': 'Offline', 'ping_ms': 'N/A'}
        try:
            self.run_command(['ping', '-n', '1', '-w', '1000', 'google.com'], check=True)
            status['internet_status'] = 'Online'
        except Exception:
            status['internet_status'] = 'Offline'
        if exit_node_ip:
            try:
                ping_res = self.run_command(['ping', '-n', '1', '-w', '1000', exit_node_ip], check=True).stdout
                status['raspi_status'] = 'Online'
                match = re.search(r"time(?:<|=)(\d+)ms", ping_res, re.IGNORECASE)
                if match: status['ping_ms'] = f"{match.group(1)} ms"
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

    def _ensure_config_dir(self):
        if not os.path.exists(APP_DATA_PATH):
            os.makedirs(APP_DATA_PATH)

    def _load_config(self):
        self._ensure_config_dir()
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f: self.exit_node_ip.set(json.load(f).get("exit_node_ip", ""))

    def _save_config(self):
        self._ensure_config_dir()
        with open(CONFIG_FILE, 'w') as f: json.dump({"exit_node_ip": self.exit_node_ip.get()}, f)

    def _create_widgets(self):
        controls_frame = Frame(self, padx=15, pady=15, bg=Colors["BG"])
        controls_frame.pack(fill='x', side='top')
        Label(controls_frame, text="Raspberry Pi (Exit Node) IP:", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 10)).pack(anchor='w')
        Entry(controls_frame, textvariable=self.exit_node_ip, bg=Colors["ENTRY_BG"], fg=Colors["ENTRY_FG"], insertbackground=Colors["FG"], relief='flat', width=40).pack(fill='x', pady=5)

        buttons_frame = Frame(controls_frame, bg=Colors["BG"])
        buttons_frame.pack(pady=10)
        Button(buttons_frame, text="Enable VPN", command=self._connect_action, bg=Colors["SUCCESS"], fg=Colors["BUTTON_FG"], relief='flat', font=("Helvetica", 10, "bold"), width=15).pack(side='left', padx=10)
        Button(buttons_frame, text="Disable VPN", command=self._disconnect_action, bg=Colors["ERROR"], fg=Colors["BUTTON_FG"], relief='flat', font=("Helvetica", 10, "bold"), width=15).pack(side='left', padx=10)

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
        self._update_vpn_indicator('Enabled')

    def _disconnect_action(self):
        self._run_in_thread(self.vpn.disconnect_from_exit_node)
        self._update_vpn_indicator('Disabled')

    def _update_vpn_indicator(self, status):
        canvas, indicator_id = self.status_widgets['vpn_status']
        canvas.itemconfig(indicator_id, fill=Colors["SUCCESS"] if status == 'Enabled' else Colors["ERROR"])

    def _run_initial_checks(self):
        if not self.vpn.tailscale_path:
            if messagebox.askyesno("Tailscale Not Found", "Download Tailscale?"): webbrowser.open(TAILSCALE_DOWNLOAD_URL)
            self.destroy()

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
                canvas.itemconfig(indicator_id, fill=Colors["SUCCESS"] if s == 'Online' else Colors["ERROR"])
        self.ping_label.config(text=status['ping_ms'])

    def _on_closing(self):
        self._save_config()
        if self.status_update_job: self.after_cancel(self.status_update_job)
        self.destroy()

def main():
    if platform.system() != "Windows": messagebox.showerror("Error", "This application is for Windows only.")
    else: App().mainloop()

if __name__ == "__main__":
    main()
