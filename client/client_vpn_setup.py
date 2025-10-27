#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SANYA-VPN Client GUI

This script provides a graphical user interface (GUI) for managing a VPN connection
on a Windows client.
"""

import subprocess
import os
import sys
import platform
import threading
import json
import queue
import psutil
from tkinter import Tk, Label, Button, Frame, Entry, StringVar, messagebox, Listbox, Scrollbar
from tkinter import ttk  # For Combobox

# --- Constants ---
APP_NAME = "SANYA-VPN"
APP_TITLE = f"{APP_NAME} Client"
WINDOW_GEOMETRY = "500x550"
IS_WINDOWS = platform.system() == "Windows"

# --- Configuration Path ---
if IS_WINDOWS:
    APP_DATA_PATH = os.path.join(os.getenv('APPDATA'), APP_NAME)
else:
    APP_DATA_PATH = "/tmp/sanya-vpn-dummy-config"
CONFIG_FILE = os.path.join(APP_DATA_PATH, "config.json")

# --- Dark Theme Colors ---
Colors = {
    "BG": "#282c34", "FG": "#abb2bf", "SUCCESS": "#98c379", "ERROR": "#e06c75",
    "INPUT_BG": "#21252b", "BUTTON": "#61afef"
}

# --- Core VPN Logic ---
class VpnLogic:
    def __init__(self):
        self.process = None
        self.openvpn_path = self._find_openvpn_exe()

    def _find_openvpn_exe(self):
        """Finds the OpenVPN executable in common Windows locations."""
        for path_var in ['ProgramFiles', 'ProgramFiles(x86)']:
            base_path = os.environ.get(path_var)
            if base_path:
                full_path = os.path.join(base_path, "OpenVPN", "bin", "openvpn.exe")
                if os.path.exists(full_path):
                    return full_path
        # Fallback to check if it's in the system PATH
        try:
            result = subprocess.run(['where', 'openvpn'], capture_output=True, text=True, check=True)
            return result.stdout.strip().split('\\n')[0]
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None

    def connect(self, server_ip, username, password, protocol, whitelist_ips=None):
        """Establishes the VPN connection."""
        ca_path = os.path.join(APP_DATA_PATH, "ca.crt")
        if not os.path.exists(ca_path):
            messagebox.showerror("Ошибка", f"Файл ca.crt не найден!\\n\\nПожалуйста, получите ca.crt у вашего VPN-администратора и поместите его в папку:\\n{APP_DATA_PATH}")
            return

        if not self.openvpn_path:
            messagebox.showerror("Ошибка", "OpenVPN не найден. Пожалуйста, установите OpenVPN Community Edition.")
            return

        if self.process and self.process.poll() is None:
            messagebox.showinfo("Информация", "VPN уже подключен.")
            return

        # Create a temporary file for username and password
        auth_file_path = os.path.join(APP_DATA_PATH, "auth.txt")
        try:
            with open(auth_file_path, "w") as f:
                f.write(f"{username}\\n")
                f.write(f"{password}\\n")
        except IOError as e:
            messagebox.showerror("Ошибка", f"Не удалось создать файл аутентификации: {e}")
            return

        proto_map = {"OpenVPN (UDP)": "udp", "OpenVPN (TCP)": "tcp"}
        command = [
            self.openvpn_path, "--client", "--dev", "tun",
            "--proto", proto_map.get(protocol, "udp"), # Default to UDP if something goes wrong
            "--remote", server_ip,
            "--auth-user-pass", auth_file_path,
            "--verb", "3",
            "--ca", os.path.join(APP_DATA_PATH, "ca.crt"),
            "--remote-cert-tls", "server"
        ]

        if whitelist_ips:
            # For split tunneling, we don't pull all routes.
            # Instead, we add a route for each whitelisted IP.
            command.append("--route-noexec") # Don't apply server-pushed routes automatically
            for ip in whitelist_ips:
                # Assuming a standard /32 route for each IP
                command.extend(["--route", ip, "255.255.255.255"])
        else:
            # Default behavior: pull all routes from the server (full tunnel)
            command.append("--pull")

        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, startupinfo=startupinfo)
            messagebox.showinfo("VPN", "Подключение...")
        except Exception as e:
            messagebox.showerror("Ошибка подключения", f"Не удалось запустить OpenVPN: {e}")

    def disconnect(self):
        """Terminates the VPN connection."""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process = None
            messagebox.showinfo("VPN", "Отключено.")
        else:
            messagebox.showinfo("Информация", "VPN не подключен.")

# --- GUI Application ---
class App(Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(WINDOW_GEOMETRY)
        self.configure(bg=Colors["BG"])
        self.resizable(False, False)

        self.vpn = VpnLogic()
        self.server_ip = StringVar()
        self.username = StringVar()
        self.password = StringVar()
        self.protocol = StringVar()
        self.active_processes = StringVar()

        self._load_config()
        self._create_widgets()
        self._populate_processes()

        self.protocol.set("OpenVPN (UDP)") # Set default protocol

        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _ensure_config_dir(self):
        if not os.path.exists(APP_DATA_PATH):
            os.makedirs(APP_DATA_PATH)

    def _load_config(self):
        self._ensure_config_dir()
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                self.server_ip.set(config.get("server_ip", ""))
                self.username.set(config.get("username", ""))

    def _save_config(self):
        self._ensure_config_dir()
        config = {
            "server_ip": self.server_ip.get(),
            "username": self.username.get()
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)

    def _create_widgets(self):
        # --- Main Container ---
        main_frame = Frame(self, padx=15, pady=15, bg=Colors["BG"])
        main_frame.pack(fill='both', expand=True)

        # --- Connection Details ---
        conn_frame = Frame(main_frame, bg=Colors["BG"], pady=5)
        conn_frame.pack(fill='x')

        Label(conn_frame, text="IP Адрес Сервера:", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 10)).pack(anchor='w')
        Entry(conn_frame, textvariable=self.server_ip, bg=Colors["INPUT_BG"], fg=Colors["FG"], insertbackground=Colors["FG"], relief='flat', width=40).pack(fill='x', pady=2)

        Label(conn_frame, text="Логин:", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 10)).pack(anchor='w', pady=(5,0))
        Entry(conn_frame, textvariable=self.username, bg=Colors["INPUT_BG"], fg=Colors["FG"], insertbackground=Colors["FG"], relief='flat', width=40).pack(fill='x', pady=2)

        Label(conn_frame, text="Пароль:", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 10)).pack(anchor='w', pady=(5,0))
        Entry(conn_frame, textvariable=self.password, show="*", bg=Colors["INPUT_BG"], fg=Colors["FG"], insertbackground=Colors["FG"], relief='flat', width=40).pack(fill='x', pady=2)

        Label(conn_frame, text="Протокол:", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 10)).pack(anchor='w', pady=(5,0))
        protocol_menu = ttk.Combobox(conn_frame, textvariable=self.protocol, values=["OpenVPN (UDP)", "OpenVPN (TCP)"], state="readonly")
        protocol_menu.pack(fill='x', pady=2)

        # --- Action Buttons ---
        buttons = Frame(main_frame, bg=Colors["BG"]); buttons.pack(pady=10)
        Button(buttons, text="Подключиться", command=self._connect, bg=Colors["SUCCESS"], fg="#282c34", relief='flat', font=("Helvetica", 10, "bold"), width=15).pack(side='left', padx=10)
        Button(buttons, text="Отключиться", command=self._disconnect, bg=Colors["ERROR"], fg="#282c34", relief='flat', font=("Helvetica", 10, "bold"), width=15).pack(side='left', padx=10)

        # --- Split Tunneling ---
        split_tunnel_frame = Frame(main_frame, bg=Colors["BG"], pady=10)
        split_tunnel_frame.pack(fill='both', expand=True)
        Label(split_tunnel_frame, text="Split Tunneling: Белый список", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 12, "bold")).pack(anchor='w')

        # Process selection
        proc_select_frame = Frame(split_tunnel_frame, bg=Colors["BG"])
        proc_select_frame.pack(fill='x', pady=5)
        Label(proc_select_frame, text="Активные процессы:", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 10)).pack(side='left', anchor='w')
        self.proc_menu = ttk.Combobox(proc_select_frame, textvariable=self.active_processes, state="readonly", width=30)
        self.proc_menu.pack(side='left', padx=5)
        Button(proc_select_frame, text="Обновить", command=self._populate_processes, bg=Colors["BUTTON"], fg="#282c34", relief='flat', font=("Helvetica", 9, "bold")).pack(side='left', padx=(0, 5))
        Button(proc_select_frame, text="Добавить", command=self._add_exception, bg=Colors["BUTTON"], fg="#282c34", relief='flat', font=("Helvetica", 9, "bold")).pack(side='left')

        # Exception list
        exception_list_frame = Frame(split_tunnel_frame, bg=Colors["BG"])
        exception_list_frame.pack(fill='both', expand=True, pady=5)
        self.exception_listbox = Listbox(exception_list_frame, bg=Colors["INPUT_BG"], fg=Colors["FG"], relief='flat', selectbackground=Colors["BUTTON"])
        self.exception_listbox.pack(side='left', fill='both', expand=True)
        scrollbar = Scrollbar(exception_list_frame, orient="vertical", command=self.exception_listbox.yview)
        scrollbar.pack(side='right', fill='y')
        self.exception_listbox.config(yscrollcommand=scrollbar.set)
        Button(split_tunnel_frame, text="Удалить выбранное", command=self._remove_exception, bg=Colors["ERROR"], fg="#282c34", relief='flat', font=("Helvetica", 9, "bold")).pack(pady=5)

        # Add a button to open the config directory at the bottom
        config_button = Button(main_frame, text="Открыть папку с ca.crt", command=self._open_config_dir,
                               bg=Colors["BUTTON"], fg="#282c34", relief='flat', font=("Helvetica", 9))
        config_button.pack(pady=(10, 0))

    def _run_in_thread(self, target, *args):
        threading.Thread(target=target, args=args, daemon=True).start()

    def _connect(self):
        self._save_config()
        ip = self.server_ip.get()
        user = self.username.get()
        pwd = self.password.get()
        proto = self.protocol.get()
        if not all([ip, user, pwd, proto]):
            messagebox.showwarning("Внимание", "Пожалуйста, заполните все поля.")
            return

        whitelist_ips = self.exception_listbox.get(0, "end")
        self._run_in_thread(self.vpn.connect, ip, user, pwd, proto, whitelist_ips)

    def _disconnect(self):
        self._run_in_thread(self.vpn.disconnect)

    def _add_exception(self):
        selected_process_name = self.active_processes.get()
        if not selected_process_name:
            messagebox.showinfo("Информация", "Сначала выберите процесс.")
            return

        found_ips = set()
        pids = [p.info['pid'] for p in psutil.process_iter(['pid', 'name']) if p.info['name'] == selected_process_name]

        if not pids:
            messagebox.showinfo("Информация", f"Процесс '{selected_process_name}' не найден.")
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
            messagebox.showinfo("Информация", f"Не найдено активных сетевых подключений для '{selected_process_name}'.")
            return

        current_list = self.exception_listbox.get(0, "end")
        added_count = 0
        for ip in found_ips:
            if ip not in current_list:
                self.exception_listbox.insert("end", ip)
                added_count += 1

        if added_count > 0:
            messagebox.showinfo("Успех", f"Добавлено {added_count} IP-адресов для '{selected_process_name}'.")

    def _remove_exception(self):
        selected_indices = self.exception_listbox.curselection()
        if not selected_indices:
            messagebox.showinfo("Информация", "Выберите программу для удаления.")
            return
        # Iterate backwards to avoid index shifting issues
        for i in sorted(selected_indices, reverse=True):
            self.exception_listbox.delete(i)

    def _open_config_dir(self):
        """Opens the application's configuration directory in the file explorer."""
        self._ensure_config_dir()
        if platform.system() == "Windows":
            os.startfile(APP_DATA_PATH)
        else:
            messagebox.showinfo("Информация", f"Папка с конфигурацией: {APP_DATA_PATH}")

    def _on_closing(self):
        self._save_config()
        self.destroy()

    def _populate_processes(self):
        try:
            processes = sorted([p.name() for p in psutil.process_iter(['name'])], key=str.lower)
            self.proc_menu['values'] = list(set(processes)) # Remove duplicates
            if processes:
                self.active_processes.set(processes[0])
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось получить список процессов: {e}")

def main():
    if not IS_WINDOWS:
        messagebox.showerror("Ошибка", "Это приложение предназначено только для Windows.")
        return
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
