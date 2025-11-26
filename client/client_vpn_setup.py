#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""SANYA-VPN Client GUI.

This script provides a graphical user interface (GUI) for managing an OpenVPN
connection on a Windows client. It allows users to select a configuration
file, enter credentials, and connect/disconnect from the VPN.

The client also features a split-tunneling "whitelist" mode, where only
traffic from specified running applications is routed through the VPN.
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
from tkinter import (Tk, Label, Button, Frame, Entry, StringVar, messagebox,
                     Listbox, Scrollbar, Canvas)
from tkinter import ttk
from tkinter import filedialog

# --- Constants ---
APP_NAME = "SANYA-VPN"
APP_TITLE = f"{APP_NAME} Client"
WINDOW_GEOMETRY = "500x600" # Increased height for better layout
IS_WINDOWS = platform.system() == "Windows"


def _find_script_dir():
    """Finds the directory where the script or executable is located.

    This is necessary to locate assets like config files, whether the app
    is running as a script or a frozen executable from PyInstaller.

    Returns:
        str: The absolute path to the script's directory.
    """
    if getattr(sys, 'frozen', False):
        # Running as a bundled executable.
        return os.path.dirname(sys.executable)
    else:
        # Running as a standard Python script.
        return os.path.dirname(os.path.abspath(__file__))


# --- Application Paths ---
BASE_APP_PATH = _find_script_dir()
CONFIG_FILE = os.path.join(BASE_APP_PATH, "config.json")

# --- Dark Theme Colors ---
Colors = {
    "BG": "#282c34", "FG": "#abb2bf", "SUCCESS": "#98c379", "ERROR": "#e06c75",
    "INPUT_BG": "#21252b", "BUTTON": "#61afef", "OFF": "#5c6370"
}

# Regex to parse ping output for latency, supporting multiple languages.
PING_RE = re.compile(
    r'(?:time|время)\s*[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*(?:ms|мс)',
    re.IGNORECASE
)


class PingThread(threading.Thread):
    """A thread that continuously pings a host and reports latency.

    Results are communicated back to the main thread via a queue.

    Attributes:
        host (str): The hostname or IP address to ping.
        q (queue.Queue): The queue to put ping results into.
        ping_type (str): A string identifier for the ping (e.g., 'server').
    """

    def __init__(self, host, q, ping_type):
        """Initializes the PingThread.

        Args:
            host (str): The hostname or IP address to ping.
            q (queue.Queue): The queue for communicating results.
            ping_type (str): A string identifier for this ping task.
        """
        super().__init__(daemon=True)
        self.host = host
        self.q = q
        self.ping_type = ping_type
        self.stop_event = threading.Event()

    def stop(self):
        """Signals the thread to stop its execution."""
        self.stop_event.set()

    def run(self):
        """The main execution method of the thread.

        Continuously runs a ping command, parses the output for latency,
        and puts the result into the queue.
        """
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
    """Handles the core logic for the OpenVPN connection.

    This class is responsible for finding the OpenVPN executable, creating
    the necessary authentication files, and managing the OpenVPN subprocess.
    """

    def __init__(self):
        """Initializes the VpnLogic instance."""
        self.process = None
        self.openvpn_path = self._find_openvpn_exe()
        self.auth_file_path = os.path.join(BASE_APP_PATH, "auth.txt")

    def _find_openvpn_exe(self):
        """Locates the OpenVPN executable on the system.

        Searches in common installation directories and then in the system's
        PATH.

        Returns:
            str or None: The full path to `openvpn.exe` or None if not found.
        """
        for path_var in ['ProgramFiles', 'ProgramFiles(x86)']:
            base_path = os.environ.get(path_var)
            if base_path:
                full_path = os.path.join(
                    base_path, "OpenVPN", "bin", "openvpn.exe"
                )
                if os.path.exists(full_path):
                    return full_path
        try:
            # Fallback to checking the system PATH.
            result = subprocess.run(
                ['where', 'openvpn'], capture_output=True, text=True,
                check=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            return result.stdout.strip().split('\n')[0]
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None

    def connect(self, ovpn_path, username, password, whitelist_ips=None):
        """Establishes the OpenVPN connection.

        Args:
            ovpn_path (str): Path to the .ovpn configuration file.
            username (str): The VPN username.
            password (str): The VPN password.
            whitelist_ips (list, optional): A list of IP addresses to route
                                            through the VPN. Defaults to None.
        """
        if not self.openvpn_path:
            messagebox.showerror(
                "Error",
                "OpenVPN not found. Please install OpenVPN Community Edition."
            )
            return
        if self.process and self.process.poll() is None:
            messagebox.showinfo("Info", "VPN is already connected.")
            return

        try:
            with open(self.auth_file_path, "w") as f:
                f.write(f"{username}\n")
                f.write(f"{password}\n")
        except IOError as e:
            messagebox.showerror(
                "Error", f"Failed to create authentication file: {e}"
            )
            return

        command = [
            self.openvpn_path,
            "--config", ovpn_path,
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
            messagebox.showerror(
                "Connection Error", f"Failed to start OpenVPN: {e}"
            )
        finally:
            # Securely remove the temporary auth file.
            if os.path.exists(self.auth_file_path):
                os.remove(self.auth_file_path)

    def disconnect(self):
        """Terminates the OpenVPN connection."""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process = None
            messagebox.showinfo("VPN", "Disconnected.")
        else:
            messagebox.showinfo("Info", "VPN is not connected.")
        # Ensure auth file is removed on disconnect as well.
        if hasattr(self, 'auth_file_path') and \
                os.path.exists(self.auth_file_path):
            os.remove(self.auth_file_path)


class App(Tk):
    """The main application class for the Tkinter GUI.

    Inherits from `tkinter.Tk` and orchestrates the UI, event handling,
    and interaction with the VpnLogic.
    """

    def __init__(self):
        """Initializes the main application window and its components."""
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(WINDOW_GEOMETRY)
        self.configure(bg=Colors["BG"])
        self.resizable(False, False)

        self.vpn = VpnLogic()
        self.ovpn_path = StringVar()
        self.username = StringVar()
        self.password = StringVar()
        self.active_processes = StringVar()
        self.whitelist = {}  # Maps process names to sets of IPs
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
        """Loads configuration from `config.json` if it exists."""
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                self.ovpn_path.set(config.get("ovpn_path", ""))
                self.username.set(config.get("username", ""))
                self._update_ovpn_label()

    def _save_config(self):
        """Saves the current configuration to `config.json`."""
        config = {
            "ovpn_path": self.ovpn_path.get(),
            "username": self.username.get()
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)

    def _select_ovpn_file(self):
        """Opens a file dialog to select an .ovpn file."""
        filepath = filedialog.askopenfilename(
            title="Select .ovpn file",
            filetypes=(("OpenVPN configuration", "*.ovpn"),
                       ("All files", "*.*"))
        )
        if filepath:
            self.ovpn_path.set(filepath)
            self._update_ovpn_label()

    def _update_ovpn_label(self):
        """Updates the label showing the selected .ovpn file name."""
        path = self.ovpn_path.get()
        if path:
            self.ovpn_path_label.config(text=os.path.basename(path))
        else:
            self.ovpn_path_label.config(text="No file selected")

    def _create_widgets(self):
        """Creates and arranges all widgets in the main window."""
        main_frame = Frame(self, padx=15, pady=15, bg=Colors["BG"])
        main_frame.pack(fill='both', expand=True)

        # --- Connection Frame ---
        conn_frame = Frame(main_frame, bg=Colors["BG"], pady=5)
        conn_frame.pack(fill='x')

        Button(
            conn_frame, text="Select .ovpn File",
            command=self._select_ovpn_file, bg=Colors["BUTTON"],
            fg="#282c34", relief='flat', font=("Helvetica", 9)
        ).pack(anchor='w', pady=(0, 5))
        self.ovpn_path_label = Label(
            conn_frame, text="No file selected", bg=Colors["BG"],
            fg=Colors["FG"], font=("Helvetica", 8)
        )
        self.ovpn_path_label.pack(anchor='w')

        Label(
            conn_frame, text="Username:", bg=Colors["BG"], fg=Colors["FG"],
            font=("Helvetica", 10)
        ).pack(anchor='w', pady=(5, 0))
        Entry(
            conn_frame, textvariable=self.username, bg=Colors["INPUT_BG"],
            fg=Colors["FG"], insertbackground=Colors["FG"], relief='flat',
            width=40
        ).pack(fill='x', pady=2)

        Label(
            conn_frame, text="Password:", bg=Colors["BG"], fg=Colors["FG"],
            font=("Helvetica", 10)
        ).pack(anchor='w', pady=(5, 0))
        Entry(
            conn_frame, textvariable=self.password, show="*",
            bg=Colors["INPUT_BG"], fg=Colors["FG"],
            insertbackground=Colors["FG"], relief='flat', width=40
        ).pack(fill='x', pady=2)

        buttons = Frame(main_frame, bg=Colors["BG"])
        buttons.pack(pady=10)
        Button(
            buttons, text="Connect", command=self._connect,
            bg=Colors["SUCCESS"], fg="#282c34", relief='flat',
            font=("Helvetica", 10, "bold"), width=15
        ).pack(side='left', padx=10)
        Button(
            buttons, text="Disconnect", command=self._disconnect,
            bg=Colors["ERROR"], fg="#282c34", relief='flat',
            font=("Helvetica", 10, "bold"), width=15
        ).pack(side='left', padx=10)

        # --- Status Indicators ---
        statuses = Frame(main_frame, bg=Colors["BG"], pady=10)
        statuses.pack(fill='x') # Changed to fill='x'
        self.indicators = {
            'vpn': self._create_indicator(statuses, "VPN Status"),
            'server': self._create_indicator(statuses, "Server"),
            'internet': self._create_indicator(statuses, "Internet"),
        }
        self.ping_label = self._create_ping_display(
            statuses, "Server Ping:"
        )

        # --- Split Tunneling Frame ---
        st_frame = Frame(main_frame, bg=Colors["BG"], pady=10)
        st_frame.pack(fill='both', expand=True)
        Label(
            st_frame, text="Split Tunneling: Whitelist", bg=Colors["BG"],
            fg=Colors["FG"], font=("Helvetica", 12, "bold")
        ).pack(anchor='w')

        proc_frame = Frame(st_frame, bg=Colors["BG"])
        proc_frame.pack(fill='x', pady=5)
        Label(
            proc_frame, text="Active Processes:", bg=Colors["BG"],
            fg=Colors["FG"], font=("Helvetica", 10)
        ).pack(side='left', anchor='w')
        self.proc_menu = ttk.Combobox(
            proc_frame, textvariable=self.active_processes,
            state="readonly", width=30
        )
        self.proc_menu.pack(side='left', padx=5)
        Button(
            proc_frame, text="Refresh", command=self._populate_processes,
            bg=Colors["BUTTON"], fg="#282c34", relief='flat',
            font=("Helvetica", 9, "bold")
        ).pack(side='left', padx=(0, 5))
        Button(
            proc_frame, text="Add", command=self._add_exception,
            bg=Colors["BUTTON"], fg="#282c34", relief='flat',
            font=("Helvetica", 9, "bold")
        ).pack(side='left')

        # --- Whitelist Display Frame ---
        ex_container = Frame(st_frame, bg=Colors["BG"])
        ex_container.pack(fill='both', expand=True, pady=5)

        canvas = Canvas(ex_container, bg=Colors["INPUT_BG"], highlightthickness=0)
        scrollbar = Scrollbar(ex_container, orient="vertical", command=canvas.yview)
        self.whitelist_frame = Frame(canvas, bg=Colors["INPUT_BG"])

        self.whitelist_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=self.whitelist_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _redraw_whitelist_frame(self):
        """Clears and redraws the whitelist UI from the self.whitelist data."""
        for widget in self.whitelist_frame.winfo_children():
            widget.destroy()

        for proc_name in sorted(self.whitelist.keys()):
            row_frame = Frame(self.whitelist_frame, bg=Colors["INPUT_BG"])
            row_frame.pack(fill='x', expand=True, pady=2, padx=5)

            label = Label(
                row_frame, text=proc_name, bg=Colors["INPUT_BG"],
                fg=Colors["FG"], anchor="w"
            )
            label.pack(side='left', fill='x', expand=True)

            remove_button = Button(
                row_frame, text="Remove",
                command=lambda name=proc_name: self._remove_exception(name),
                bg=Colors["ERROR"], fg="#282c34", relief='flat',
                font=("Helvetica", 8)
            )
            remove_button.pack(side='right', padx=5)


    def _create_indicator(self, parent, text):
        """Creates a status indicator widget.

        Args:
            parent: The parent tkinter widget.
            text (str): The label text for the indicator.

        Returns:
            tuple: A tuple containing the Canvas widget and the oval item ID.
        """
        frame = Frame(parent, bg=Colors["BG"])
        frame.pack(fill='x', pady=5)
        Label(
            frame, text=text, bg=Colors["BG"], fg=Colors["FG"],
            font=("Helvetica", 11)
        ).pack(side='left')
        canvas = Canvas(
            frame, width=20, height=20, bg=Colors["BG"],
            highlightthickness=0
        )
        canvas.pack(side='right')
        oval = canvas.create_oval(5, 5, 18, 18, fill=Colors["OFF"], outline="")
        return canvas, oval

    def _create_ping_display(self, parent, text):
        """Creates a label for displaying ping latency.

        Args:
            parent: The parent tkinter widget.
            text (str): The label text.

        Returns:
            Label: The Label widget used to display the ping.
        """
        frame = Frame(parent, bg=Colors["BG"])
        frame.pack(fill='x', pady=5)
        Label(
            frame, text=text, bg=Colors["BG"], fg=Colors["FG"],
            font=("Helvetica", 11)
        ).pack(side='left')
        ping_label = Label(
            frame, text="N/A", bg=Colors["BG"], fg=Colors["FG"],
            font=("Helvetica", 11, "bold")
        )
        ping_label.pack(side='right')
        return ping_label

    def _set_indicator(self, key, status):
        """Sets the color of a status indicator.

        Args:
            key (str): The key of the indicator in `self.indicators`.
            status (str): The status, e.g., 'Online', 'Enabled', 'Offline'.
        """
        canvas, indicator_id = self.indicators[key]
        color = Colors["SUCCESS"] \
            if status in ['Online', 'Enabled'] else Colors["ERROR"]
        canvas.itemconfig(indicator_id, fill=color)

    def start_internet_ping(self):
        """Starts the background thread for pinging the internet."""
        if self.internet_ping_thread:
            self.internet_ping_thread.stop()
        self.internet_ping_thread = PingThread("google.com", self.q,
                                               "internet_ping")
        self.internet_ping_thread.start()

    def _check_queue(self):
        """Periodically checks the queue for messages from threads."""
        try:
            while True:
                typ, val = self.q.get_nowait()
                if typ == "server_ping":
                    self.ping_label.config(text=f"{val} ms")
                    self._set_indicator(
                        'server',
                        'Online' if 0 < float(val) < 600 else 'Offline'
                    )
                elif typ == "internet_ping":
                    self._set_indicator(
                        'internet',
                        'Online' if 0 < float(val) < 600 else 'Offline'
                    )
                elif typ.endswith("_status"):
                    key = typ.split('_')[0]
                    self._set_indicator(key, val)
        except queue.Empty:
            pass
        self.after(100, self._check_queue)

    def _run_in_thread(self, target, *args):
        """Runs a target function in a new daemon thread.

        Args:
            target (callable): The function to execute.
            *args: Arguments to pass to the target function.
        """
        threading.Thread(target=target, args=args, daemon=True).start()

    def _connect(self):
        """Handles the connect button click event."""
        self._save_config()
        ovpn = self.ovpn_path.get()
        user = self.username.get()
        pwd = self.password.get()
        if not all([ovpn, user, pwd]):
            messagebox.showwarning(
                "Warning",
                "Please select an .ovpn file and fill in all fields."
            )
            return

        all_whitelist_ips = set()
        for ip_set in self.whitelist.values():
            all_whitelist_ips.update(ip_set)

        self._set_indicator('vpn', 'Enabled')
        self._run_in_thread(
            self.vpn.connect, ovpn, user, pwd, list(all_whitelist_ips)
        )

    def _disconnect(self):
        """Handles the disconnect button click event."""
        self._set_indicator('vpn', 'Disabled')
        self._run_in_thread(self.vpn.disconnect)

    def _add_exception(self):
        """Adds a selected process to the split-tunneling whitelist."""
        proc_name = self.active_processes.get()
        if not proc_name:
            messagebox.showinfo("Info", "Please select a process first.")
            return

        found_ips = set()
        pids = [p.info['pid'] for p in psutil.process_iter(['pid', 'name'])
                if p.info['name'] == proc_name]

        if not pids:
            messagebox.showinfo("Info", f"Process '{proc_name}' not found.")
            return

        for pid in pids:
            try:
                p = psutil.Process(pid)
                connections = p.connections(kind='inet')
                for conn in connections:
                    if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                        found_ips.add(conn.raddr.ip)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not found_ips:
            messagebox.showinfo(
                "Info",
                f"No active network connections found for '{proc_name}'."
            )
            return

        current_ips = self.whitelist.get(proc_name, set())
        self.whitelist[proc_name] = current_ips.union(found_ips)
        self._redraw_whitelist_frame()

        messagebox.showinfo(
            "Success",
            f"Added/updated {len(found_ips)} IP addresses for '{proc_name}'."
        )

    def _remove_exception(self, proc_name_to_remove):
        """Removes a specified process from the whitelist.

        Args:
            proc_name_to_remove (str): The name of the process to remove.
        """
        if proc_name_to_remove in self.whitelist:
            del self.whitelist[proc_name_to_remove]
            self._redraw_whitelist_frame()
            messagebox.showinfo(
                "Success",
                f"Process '{proc_name_to_remove}' removed from whitelist."
            )
        else:
            messagebox.showwarning(
                "Warning",
                f"Process '{proc_name_to_remove}' not found in whitelist."
            )

    def _on_closing(self):
        """Handles the window close event."""
        if self.server_ping_thread:
            self.server_ping_thread.stop()
        if self.internet_ping_thread:
            self.internet_ping_thread.stop()
        self._save_config()
        self.destroy()

    def _populate_processes(self):
        """Fetches and populates the list of running processes."""
        try:
            processes = sorted(
                [p.name() for p in psutil.process_iter(['name'])],
                key=str.lower
            )
            unique_processes = sorted(list(set(processes)))
            self.proc_menu['values'] = unique_processes
            if unique_processes:
                self.active_processes.set(unique_processes[0])
        except Exception as e:
            messagebox.showerror(
                "Error", f"Failed to get process list: {e}"
            )


def main():
    """The main entry point for the application."""
    if not IS_WINDOWS:
        messagebox.showerror("Error", "This application is for Windows only.")
        return
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
