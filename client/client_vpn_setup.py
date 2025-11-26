#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""SANYA-VPN Client GUI.

This script provides a graphical user interface (GUI) for managing an OpenVPN
connection on a Windows client. It is fully portable and handles the automatic
installation of its own OpenVPN engine on first run.
"""

import subprocess
import os
import sys
import platform
import threading
import json
import queue
import psutil
import re
import urllib.request
import shutil
import ctypes
from tkinter import (Tk, Label, Button, Frame, Entry, StringVar, messagebox,
                     Canvas, Scrollbar)
from tkinter import ttk
from tkinter import filedialog

# --- Constants ---
APP_NAME = "SANYA-VPN"
APP_TITLE = f"{APP_NAME} Client"
WINDOW_GEOMETRY = "500x600"
IS_WINDOWS = platform.system() == "Windows"
OPENVPN_DOWNLOAD_URL = "https://build.openvpn.net/downloads/releases/OpenVPN-2.6.16-I001-amd64.msi"


def _find_script_dir():
    """Finds the directory where the script or executable is located."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))


# --- Application Paths ---
BASE_APP_PATH = _find_script_dir()
CONFIG_FILE = os.path.join(BASE_APP_PATH, "config.json")
VPN_ENGINE_PATH = os.path.join(BASE_APP_PATH, "vpn_engine")
# We now exclusively use the local OpenVPN executable
LOCAL_OPENVPN_EXE = os.path.join(VPN_ENGINE_PATH, "bin", "openvpn.exe")

# --- Dark Theme Colors ---
Colors = {
    "BG": "#282c34", "FG": "#abb2bf", "SUCCESS": "#98c379", "ERROR": "#e06c75",
    "INPUT_BG": "#21252b", "BUTTON": "#61afef", "OFF": "#5c6370"
}

# Regex to parse ping output for latency
PING_RE = re.compile(
    r'(?:time|время)\s*[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*(?:ms|мс)',
    re.IGNORECASE
)


class PingThread(threading.Thread):
    """A thread that continuously pings a host and reports latency."""
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
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            encoding=encoding, bufsize=1, creationflags=flags
        )
        while not self.stop_event.is_set():
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    self.q.put((f"{self.ping_type}_status", "Offline"))
                    break
                continue
            match = PING_RE.search(line.strip())
            if match:
                self.q.put((self.ping_type, match.group(1)))
        proc.terminate()


class VpnLogic:
    """Handles the core logic for the OpenVPN connection."""
    def __init__(self, openvpn_path):
        self.process = None
        self.openvpn_path = openvpn_path
        self.auth_file_path = os.path.join(BASE_APP_PATH, "auth.txt")

    def connect(self, ovpn_path, username, password, whitelist_ips=None):
        if not self.openvpn_path:
            messagebox.showerror("Error", "OpenVPN engine not found!")
            return
        if self.process and self.process.poll() is None:
            messagebox.showinfo("Info", "VPN is already connected.")
            return
        try:
            with open(self.auth_file_path, "w") as f:
                f.write(f"{username}\n")
                f.write(f"{password}\n")
        except IOError as e:
            messagebox.showerror("Error", f"Failed to create auth file: {e}")
            return

        command = [
            self.openvpn_path, "--config", ovpn_path,
            "--auth-user-pass", self.auth_file_path
        ]
        if whitelist_ips:
            command.append("--route-noexec")
            for ip in whitelist_ips:
                command.extend(["--route", ip, "255.255.255.255"])
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            self.process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, startupinfo=startupinfo
            )
            messagebox.showinfo("VPN", "Connecting...")
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to start OpenVPN: {e}")
        finally:
            if os.path.exists(self.auth_file_path):
                os.remove(self.auth_file_path)

    def disconnect(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process = None
            messagebox.showinfo("VPN", "Disconnected.")
        else:
            messagebox.showinfo("Info", "VPN is not connected.")
        if hasattr(self, 'auth_file_path') and os.path.exists(self.auth_file_path):
            os.remove(self.auth_file_path)


class App(Tk):
    """The main application class for the Tkinter GUI."""
    def __init__(self, openvpn_path):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(WINDOW_GEOMETRY)
        self.configure(bg=Colors["BG"])
        self.resizable(False, False)

        self.vpn = VpnLogic(openvpn_path)
        self.ovpn_path = StringVar()
        self.username = StringVar()
        self.password = StringVar()
        self.active_processes = StringVar()
        self.whitelist = {}
        self.q = queue.Queue()
        self.server_ping_thread = None
        self.internet_ping_thread = None

        self._load_config()
        self._create_widgets()
        self._populate_processes()
        self.after(100, self._check_queue)
        self.start_internet_ping()
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                self.ovpn_path.set(config.get("ovpn_path", ""))
                self.username.set(config.get("username", ""))
                self._update_ovpn_label()

    def _save_config(self):
        config = { "ovpn_path": self.ovpn_path.get(), "username": self.username.get() }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)

    def _select_ovpn_file(self):
        filepath = filedialog.askopenfilename(
            title="Select .ovpn file",
            filetypes=(("OpenVPN configuration", "*.ovpn"), ("All files", "*.*"))
        )
        if filepath:
            self.ovpn_path.set(filepath)
            self._update_ovpn_label()

    def _update_ovpn_label(self):
        path = self.ovpn_path.get()
        self.ovpn_path_label.config(text=os.path.basename(path) if path else "No file selected")

    def _create_widgets(self):
        main_frame = Frame(self, padx=15, pady=15, bg=Colors["BG"])
        main_frame.pack(fill='both', expand=True)
        # ... (Widget creation code is unchanged, so it's shortened for brevity)
        conn_frame = Frame(main_frame, bg=Colors["BG"], pady=5)
        conn_frame.pack(fill='x')
        Button(conn_frame, text="Select .ovpn File", command=self._select_ovpn_file, bg=Colors["BUTTON"], fg="#282c34", relief='flat', font=("Helvetica", 9)).pack(anchor='w', pady=(0, 5))
        self.ovpn_path_label = Label(conn_frame, text="No file selected", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 8))
        self.ovpn_path_label.pack(anchor='w')
        Label(conn_frame, text="Username:", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 10)).pack(anchor='w', pady=(5, 0))
        Entry(conn_frame, textvariable=self.username, bg=Colors["INPUT_BG"], fg=Colors["FG"], insertbackground=Colors["FG"], relief='flat', width=40).pack(fill='x', pady=2)
        Label(conn_frame, text="Password:", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 10)).pack(anchor='w', pady=(5, 0))
        Entry(conn_frame, textvariable=self.password, show="*", bg=Colors["INPUT_BG"], fg=Colors["FG"], insertbackground=Colors["FG"], relief='flat', width=40).pack(fill='x', pady=2)
        buttons = Frame(main_frame, bg=Colors["BG"]); buttons.pack(pady=10)
        Button(buttons, text="Connect", command=self._connect, bg=Colors["SUCCESS"], fg="#282c34", relief='flat', font=("Helvetica", 10, "bold"), width=15).pack(side='left', padx=10)
        Button(buttons, text="Disconnect", command=self._disconnect, bg=Colors["ERROR"], fg="#282c34", relief='flat', font=("Helvetica", 10, "bold"), width=15).pack(side='left', padx=10)
        statuses = Frame(main_frame, bg=Colors["BG"], pady=10); statuses.pack(fill='x')
        self.indicators = { 'vpn': self._create_indicator(statuses, "VPN Status"), 'server': self._create_indicator(statuses, "Server"), 'internet': self._create_indicator(statuses, "Internet"), }
        self.ping_label = self._create_ping_display(statuses, "Server Ping:")
        st_frame = Frame(main_frame, bg=Colors["BG"], pady=10); st_frame.pack(fill='both', expand=True)
        Label(st_frame, text="Split Tunneling: Whitelist", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 12, "bold")).pack(anchor='w')
        proc_frame = Frame(st_frame, bg=Colors["BG"]); proc_frame.pack(fill='x', pady=5)
        Label(proc_frame, text="Active Processes:", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 10)).pack(side='left', anchor='w')
        self.proc_menu = ttk.Combobox(proc_frame, textvariable=self.active_processes, state="readonly", width=30)
        self.proc_menu.pack(side='left', padx=5)
        Button(proc_frame, text="Refresh", command=self._populate_processes, bg=Colors["BUTTON"], fg="#282c34", relief='flat', font=("Helvetica", 9, "bold")).pack(side='left', padx=(0, 5))
        Button(proc_frame, text="Add", command=self._add_exception, bg=Colors["BUTTON"], fg="#282c34", relief='flat', font=("Helvetica", 9, "bold")).pack(side='left')
        ex_container = Frame(st_frame, bg=Colors["BG"]); ex_container.pack(fill='both', expand=True, pady=5)
        canvas = Canvas(ex_container, bg=Colors["INPUT_BG"], highlightthickness=0)
        scrollbar = Scrollbar(ex_container, orient="vertical", command=canvas.yview)
        self.whitelist_frame = Frame(canvas, bg=Colors["INPUT_BG"])
        self.whitelist_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.whitelist_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _redraw_whitelist_frame(self):
        for widget in self.whitelist_frame.winfo_children(): widget.destroy()
        for proc_name in sorted(self.whitelist.keys()):
            row_frame = Frame(self.whitelist_frame, bg=Colors["INPUT_BG"])
            row_frame.pack(fill='x', expand=True, pady=2, padx=5)
            Label(row_frame, text=proc_name, bg=Colors["INPUT_BG"], fg=Colors["FG"], anchor="w").pack(side='left', fill='x', expand=True)
            Button(row_frame, text="Remove", command=lambda name=proc_name: self._remove_exception(name), bg=Colors["ERROR"], fg="#282c34", relief='flat', font=("Helvetica", 8)).pack(side='right', padx=5)

    def _create_indicator(self, parent, text):
        frame = Frame(parent, bg=Colors["BG"]); frame.pack(fill='x', pady=5)
        Label(frame, text=text, bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 11)).pack(side='left')
        canvas = Canvas(frame, width=20, height=20, bg=Colors["BG"], highlightthickness=0); canvas.pack(side='right')
        oval = canvas.create_oval(5, 5, 18, 18, fill=Colors["OFF"], outline=""); return canvas, oval

    def _create_ping_display(self, parent, text):
        frame = Frame(parent, bg=Colors["BG"]); frame.pack(fill='x', pady=5)
        Label(frame, text=text, bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 11)).pack(side='left')
        ping_label = Label(frame, text="N/A", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 11, "bold")); ping_label.pack(side='right')
        return ping_label

    def _set_indicator(self, key, status):
        canvas, indicator_id = self.indicators[key]
        color = Colors["SUCCESS"] if status in ['Online', 'Enabled'] else Colors["ERROR"]
        canvas.itemconfig(indicator_id, fill=color)

    def start_internet_ping(self):
        if self.internet_ping_thread: self.internet_ping_thread.stop()
        self.internet_ping_thread = PingThread("google.com", self.q, "internet_ping")
        self.internet_ping_thread.start()

    def _check_queue(self):
        try:
            while True:
                typ, val = self.q.get_nowait()
                if typ == "server_ping": self.ping_label.config(text=f"{val} ms"); self._set_indicator('server', 'Online' if 0 < float(val) < 600 else 'Offline')
                elif typ == "internet_ping": self._set_indicator('internet', 'Online' if 0 < float(val) < 600 else 'Offline')
                elif typ.endswith("_status"): self._set_indicator(typ.split('_')[0], val)
        except queue.Empty: pass
        self.after(100, self._check_queue)

    def _run_in_thread(self, target, *args):
        threading.Thread(target=target, args=args, daemon=True).start()

    def _connect(self):
        self._save_config()
        ovpn, user, pwd = self.ovpn_path.get(), self.username.get(), self.password.get()
        if not all([ovpn, user, pwd]):
            messagebox.showwarning("Warning", "Please select an .ovpn file and fill in all fields.")
            return
        all_whitelist_ips = set().union(*self.whitelist.values())
        self._set_indicator('vpn', 'Enabled')
        self._run_in_thread(self.vpn.connect, ovpn, user, pwd, list(all_whitelist_ips))

    def _disconnect(self):
        self._set_indicator('vpn', 'Disabled')
        self._run_in_thread(self.vpn.disconnect)

    def _add_exception(self):
        proc_name = self.active_processes.get()
        if not proc_name: messagebox.showinfo("Info", "Please select a process first."); return
        found_ips = set()
        pids = [p.info['pid'] for p in psutil.process_iter(['pid', 'name']) if p.info['name'] == proc_name]
        if not pids: messagebox.showinfo("Info", f"Process '{proc_name}' not found."); return
        for pid in pids:
            try:
                p = psutil.Process(pid)
                for conn in p.connections(kind='inet'):
                    if conn.status == psutil.CONN_ESTABLISHED and conn.raddr: found_ips.add(conn.raddr.ip)
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue
        if not found_ips: messagebox.showinfo("Info", f"No active network connections found for '{proc_name}'."); return
        self.whitelist.setdefault(proc_name, set()).update(found_ips)
        self._redraw_whitelist_frame()
        messagebox.showinfo("Success", f"Added/updated {len(found_ips)} IP addresses for '{proc_name}'.")

    def _remove_exception(self, proc_name_to_remove):
        if proc_name_to_remove in self.whitelist:
            del self.whitelist[proc_name_to_remove]
            self._redraw_whitelist_frame()
            messagebox.showinfo("Success", f"Process '{proc_name_to_remove}' removed from whitelist.")
        else:
            messagebox.showwarning("Warning", f"Process '{proc_name_to_remove}' not found in whitelist.")

    def _on_closing(self):
        if self.server_ping_thread: self.server_ping_thread.stop()
        if self.internet_ping_thread: self.internet_ping_thread.stop()
        self._save_config()
        self.destroy()

    def _populate_processes(self):
        try:
            unique_processes = sorted(list(set(p.name() for p in psutil.process_iter(['name']))), key=str.lower)
            self.proc_menu['values'] = unique_processes
            if unique_processes: self.active_processes.set(unique_processes[0])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get process list: {e}")

# --- Admin and Installation Functions ---
def is_admin():
    """Checks if the script is running with administrator privileges."""
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def run_as_admin():
    """Re-runs the script with administrator privileges."""
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    except Exception as e:
        messagebox.showerror("Elevation Error", f"Failed to request administrator privileges: {e}")

def _install_openvpn_engine():
    """Downloads and silently installs the OpenVPN MSI package."""
    installer_path = os.path.join(BASE_APP_PATH, "openvpn_installer.msi")
    setup_root = Tk()
    setup_root.withdraw()
    try:
        messagebox.showinfo("Setup", "SANYA-VPN needs to install its VPN engine (OpenVPN).\n\nThis is a one-time setup.", parent=setup_root)
        messagebox.showinfo("Setup", "Downloading the OpenVPN engine...", parent=setup_root)

        urllib.request.urlretrieve(OPENVPN_DOWNLOAD_URL, installer_path)

        messagebox.showinfo("Setup", "Download complete. Installing silently...", parent=setup_root)

        cmd = ["msiexec", "/i", installer_path, "/quiet", "/qn", "/norestart", f'TARGETDIR="{os.path.abspath(VPN_ENGINE_PATH)}"']
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise OSError(f"Installer failed with code {result.returncode}.\n\nStderr:\n{result.stderr}")

        if not os.path.exists(LOCAL_OPENVPN_EXE):
            raise FileNotFoundError("Installation seemed to succeed, but openvpn.exe was not found.")

        messagebox.showinfo("Success", "VPN engine installed successfully.", parent=setup_root)
        return LOCAL_OPENVPN_EXE

    except Exception as e:
        messagebox.showerror("Installation Failed", f"An error occurred: {e}", parent=setup_root)
        return None
    finally:
        if setup_root.winfo_exists(): setup_root.destroy()
        if os.path.exists(installer_path): os.remove(installer_path)

def main():
    """The main entry point for the application."""
    if not IS_WINDOWS:
        messagebox.showerror("Error", "This application is for Windows only.")
        return

    if os.path.exists(LOCAL_OPENVPN_EXE):
        openvpn_path = LOCAL_OPENVPN_EXE
    else:
        if not is_admin():
            root = Tk(); root.withdraw()
            messagebox.showinfo("Admin Required", "For first-time setup, please accept the administrator prompt to install the VPN engine.")
            root.destroy()
            run_as_admin()
            sys.exit(0)
        else:
            openvpn_path = _install_openvpn_engine()

    if not openvpn_path:
        messagebox.showerror("Setup Error", "SANYA-VPN cannot run without its engine. Exiting.")
        return

    app = App(openvpn_path=openvpn_path)
    app.mainloop()

if __name__ == "__main__":
    main()
