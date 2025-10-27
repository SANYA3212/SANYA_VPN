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
import platform
import webbrowser
import threading
import json
import locale
import re
import queue
from tkinter import Tk, Label, Button, Frame, Entry, StringVar, messagebox, Canvas

# --- Constants ---
APP_NAME = "SANYA-VPN"
APP_TITLE = f"{APP_NAME} Client"
WINDOW_GEOMETRY = "480x320"
TAILSCALE_DOWNLOAD_URL = "https://tailscale.com/download/windows"
IS_WINDOWS = platform.system() == "Windows"
PING_RE = re.compile(r'(?:time|время)\s*[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*(?:ms|мс)', re.IGNORECASE)

# --- Configuration Path ---
if IS_WINDOWS:
    APP_DATA_PATH = os.path.join(os.getenv('APPDATA'), APP_NAME)
else:
    # This is a Windows-only app, but we need a placeholder for other OSes
    # to avoid crashing on import. The main() function prevents execution.
    APP_DATA_PATH = "/tmp/sanya-vpn-dummy-config"
CONFIG_FILE = os.path.join(APP_DATA_PATH, "config.json")

# --- Dark Theme Colors ---
Colors = {
    "BG": "#282c34", "FG": "#abb2bf", "SUCCESS": "#98c379", "ERROR": "#e06c75", "OFF": "#5c6370"
}

# --- Background Ping Thread ---
class PingThread(threading.Thread):
    def __init__(self, host, q, ping_type):
        super().__init__(daemon=True)
        self.host = host
        self.q = q
        self.ping_type = ping_type
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        cmd = ["ping", self.host, "-t"]
        encoding = "cp866" if IS_WINDOWS else "utf-8"
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding=encoding, bufsize=1, creationflags=flags)

        while not self.stop_event.is_set():
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                self.q.put((f"{self.ping_type}_status", "Offline"))
                break
            if not line:
                continue

            m = PING_RE.search(line.strip())
            if m:
                self.q.put((self.ping_type, m.group(1)))

        proc.terminate()

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
        return subprocess.run(command, capture_output=True, text=True, check=check, encoding=locale.getpreferredencoding(), startupinfo=startupinfo)

    def connect(self, node_id):
        if node_id: self.run_command([self.tailscale_path, 'up', f'--exit-node={node_id}', '--accept-routes'], check=False)

    def disconnect(self):
        self.run_command([self.tailscale_path, 'set', '--exit-node='])

# --- GUI Application ---
class App(Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(WINDOW_GEOMETRY)
        self.configure(bg=Colors["BG"])
        self.resizable(False, False)

        self.vpn = VpnLogic()
        self.q = queue.Queue()
        self.raspi_ping_thread = None
        self.internet_ping_thread = None
        self.exit_node_ip = StringVar()
        self.exit_node_ip.trace_add("write", self.on_ip_change)
        self._load_config()

        self._create_widgets()

        self.after(100, self._check_queue)
        self.after(500, self._run_initial_checks)
        self.start_internet_ping()

        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _ensure_config_dir(self):
        if not os.path.exists(APP_DATA_PATH): os.makedirs(APP_DATA_PATH)

    def _load_config(self):
        self._ensure_config_dir()
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f: self.exit_node_ip.set(json.load(f).get("exit_node_ip", ""))

    def _save_config(self):
        self._ensure_config_dir()
        with open(CONFIG_FILE, 'w') as f: json.dump({"exit_node_ip": self.exit_node_ip.get()}, f)

    def _create_widgets(self):
        controls = Frame(self, padx=15, pady=15, bg=Colors["BG"])
        controls.pack(fill='x', side='top')
        Label(controls, text="Raspberry Pi (Exit Node) IP:", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 10)).pack(anchor='w')
        Entry(controls, textvariable=self.exit_node_ip, bg="#21252b", fg="#abb2bf", insertbackground="#abb2bf", relief='flat', width=40).pack(fill='x', pady=5)

        buttons = Frame(controls, bg=Colors["BG"]); buttons.pack(pady=10)
        Button(buttons, text="Enable VPN", command=self._connect, bg=Colors["SUCCESS"], fg="#282c34", relief='flat', font=("Helvetica", 10, "bold"), width=15).pack(side='left', padx=10)
        Button(buttons, text="Disable VPN", command=self._disconnect, bg=Colors["ERROR"], fg="#282c34", relief='flat', font=("Helvetica", 10, "bold"), width=15).pack(side='left', padx=10)

        statuses = Frame(self, padx=15, pady=10, bg=Colors["BG"]); statuses.pack(fill='both', expand=True)
        self.indicators = {
            'vpn': self._create_indicator(statuses, "VPN Status"),
            'raspi': self._create_indicator(statuses, "Raspberry Pi"),
            'internet': self._create_indicator(statuses, "Internet Access"),
        }
        self.ping_label = self._create_ping_display(statuses, "Ping to Pi:")

    def _create_indicator(self, parent, text):
        frame = Frame(parent, bg=Colors["BG"]); frame.pack(fill='x', pady=5)
        Label(frame, text=text, bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 11)).pack(side='left')
        canvas = Canvas(frame, width=20, height=20, bg=Colors["BG"], highlightthickness=0); canvas.pack(side='right')
        return canvas, canvas.create_oval(5, 5, 18, 18, fill=Colors["OFF"], outline="")

    def _create_ping_display(self, parent, text):
        frame = Frame(parent, bg=Colors["BG"]); frame.pack(fill='x', pady=5)
        Label(frame, text=text, bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 11)).pack(side='left')
        ping_label = Label(frame, text="N/A", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 11, "bold"))
        ping_label.pack(side='right')
        return ping_label

    def _run_in_thread(self, target, *args):
        threading.Thread(target=target, args=args, daemon=True).start()

    def _connect(self):
        self._save_config()
        ip = self.exit_node_ip.get()
        if not ip: messagebox.showwarning("Input Required", "Please enter the Raspberry Pi's IP.")
        else:
            self._run_in_thread(self.vpn.connect, ip)
            self._set_indicator('vpn', 'Enabled')

    def _disconnect(self):
        self._run_in_thread(self.vpn.disconnect)
        self._set_indicator('vpn', 'Disabled')

    def _set_indicator(self, key, status):
        canvas, indicator_id = self.indicators[key]
        canvas.itemconfig(indicator_id, fill=Colors["SUCCESS"] if status in ['Online', 'Enabled'] else Colors["ERROR"])

    def on_ip_change(self, *args):
        if self.raspi_ping_thread: self.raspi_ping_thread.stop()
        ip = self.exit_node_ip.get()
        if ip:
            self.raspi_ping_thread = PingThread(ip, self.q, "raspi_ping")
            self.raspi_ping_thread.start()
        else:
            self.ping_label.config(text="N/A")
            self._set_indicator('raspi', 'Offline')

    def start_internet_ping(self):
        if self.internet_ping_thread: self.internet_ping_thread.stop()
        self.internet_ping_thread = PingThread("google.com", self.q, "internet_ping")
        self.internet_ping_thread.start()

    def _check_queue(self):
        try:
            while True:
                typ, val = self.q.get_nowait()
                if typ == "raspi_ping":
                    self.ping_label.config(text=f"{val} ms")
                    ping_val = float(val)
                    if 0 < ping_val < 600:
                        self._set_indicator('raspi', 'Online')
                    else:
                        self._set_indicator('raspi', 'Offline')
                elif typ == "internet_ping":
                    ping_val = float(val)
                    if 0 < ping_val < 600:
                        self._set_indicator('internet', 'Online')
                    else:
                        self._set_indicator('internet', 'Offline')
                elif typ == "raspi_ping_status":
                    self._set_indicator('raspi', val)
                elif typ == "internet_ping_status":
                    self._set_indicator('internet', val)
        except queue.Empty: pass
        self.after(100, self._check_queue)

    def _run_initial_checks(self):
        if not self.vpn.tailscale_path and messagebox.askyesno("Tailscale Not Found", "Download Tailscale?"):
            webbrowser.open(TAILSCALE_DOWNLOAD_URL)
            self.destroy()

    def _on_closing(self):
        if self.raspi_ping_thread: self.raspi_ping_thread.stop()
        if self.internet_ping_thread: self.internet_ping_thread.stop()
        self._save_config()
        self.destroy()

def main():
    if not IS_WINDOWS: messagebox.showerror("Error", "This application is for Windows only.")
    else: App().mainloop()

if __name__ == "__main__":
    main()
