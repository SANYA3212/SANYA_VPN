#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SANYA-VPN Client GUI — FIXED FULL VERSION
Исправлено:
 – ошибка ovpn_path_label (создание виджета перенесено выше)
 – порядок инициализации
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
from tkinter import Tk, Label, Button, Frame, Entry, StringVar, messagebox, Listbox, Scrollbar, Canvas
from tkinter import ttk
from tkinter import filedialog

APP_NAME = "SANYA-VPN"
APP_TITLE = f"{APP_NAME} Client"
WINDOW_GEOMETRY = "500x550"
IS_WINDOWS = platform.system() == "Windows"

def _find_script_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

BASE_APP_PATH = _find_script_dir()
CONFIG_FILE = os.path.join(BASE_APP_PATH, "config.json")

Colors = {
    "BG": "#282c34", "FG": "#abb2bf", "SUCCESS": "#98c379", "ERROR": "#e06c75",
    "INPUT_BG": "#21252b", "BUTTON": "#61afef", "OFF": "#5c6370"
}

PING_RE = re.compile(r'(?:time|время)\s*[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*(?:ms|мс)', re.IGNORECASE)


# ------------------- PING THREAD -------------------
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

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding=encoding,
            bufsize=1,
            creationflags=flags
        )

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


# ------------------- VPN LOGIC -------------------
class VpnLogic:
    def __init__(self):
        self.process = None
        self.openvpn_path = self._find_openvpn_exe()
        self.auth_file_path = os.path.join(BASE_APP_PATH, "auth.txt")

    def _find_openvpn_exe(self):
        for path_var in ['ProgramFiles', 'ProgramFiles(x86)']:
            base_path = os.environ.get(path_var)
            if base_path:
                full_path = os.path.join(base_path, "OpenVPN", "bin", "openvpn.exe")
                if os.path.exists(full_path):
                    return full_path

        try:
            result = subprocess.run(['where', 'openvpn'], capture_output=True, text=True, check=True)
            return result.stdout.strip().split('\n')[0]
        except Exception:
            return None

    def connect(self, ovpn_path, username, password, whitelist_ips=None):
        if not self.openvpn_path:
            messagebox.showerror("Ошибка", "OpenVPN не найден.")
            return

        if self.process and self.process.poll() is None:
            messagebox.showinfo("Информация", "VPN уже подключён.")
            return

        try:
            with open(self.auth_file_path, "w") as f:
                f.write(f"{username}\n{password}\n")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось создать auth.txt: {e}")
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
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                startupinfo=startupinfo
            )

            messagebox.showinfo("VPN", "Подключение...")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось запустить OpenVPN: {e}")
        finally:
            if os.path.exists(self.auth_file_path):
                os.remove(self.auth_file_path)

    def disconnect(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process = None
            messagebox.showinfo("VPN", "Отключено.")
        else:
            messagebox.showinfo("Информация", "VPN не подключён.")


# ------------------- GUI -------------------
class App(Tk):
    def __init__(self):
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

        self.whitelist = {}
        self.q = queue.Queue()

        self.server_ping_thread = None
        self.internet_ping_thread = None

        # 🔥 FIX — сначала создаём интерфейс
        self._create_widgets()

        # 🔥 FIX — потом грузим конфиг
        self._load_config()

        self._populate_processes()
        self.after(100, self._check_queue)
        self.start_internet_ping()

        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    # ------------------- CONFIG -------------------
    def _load_config(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                self.ovpn_path.set(config.get("ovpn_path", ""))
                self.username.set(config.get("username", ""))

        self._update_ovpn_label()

    def _save_config(self):
        config = {
            "ovpn_path": self.ovpn_path.get(),
            "username": self.username.get()
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)

    # ------------------- OVPN SELECT -------------------
    def _select_ovpn_file(self):
        filepath = filedialog.askopenfilename(
            title="Выберите .ovpn файл",
            filetypes=(("OpenVPN config", "*.ovpn"), ("All files", "*.*"))
        )

        if filepath:
            self.ovpn_path.set(filepath)
            self._update_ovpn_label()

    def _update_ovpn_label(self):
        path = self.ovpn_path.get()
        if path:
            self.ovpn_path_label.config(text=os.path.basename(path))
        else:
            self.ovpn_path_label.config(text="Файл не выбран")

    # ------------------- WIDGETS -------------------
    def _create_widgets(self):
        main_frame = Frame(self, padx=15, pady=15, bg=Colors["BG"])
        main_frame.pack(fill='both', expand=True)

        conn_frame = Frame(main_frame, bg=Colors["BG"], pady=5)
        conn_frame.pack(fill='x')

        Button(
            conn_frame,
            text="Выбрать .ovpn файл",
            command=self._select_ovpn_file,
            bg=Colors["BUTTON"], fg="#282c34",
            relief='flat', font=("Helvetica", 9)
        ).pack(anchor='w', pady=(0, 5))

        self.ovpn_path_label = Label(
            conn_frame,
            text="Файл не выбран",
            bg=Colors["BG"], fg=Colors["FG"],
            font=("Helvetica", 8)
        )
        self.ovpn_path_label.pack(anchor='w')

        Label(conn_frame, text="Логин:", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 10)).pack(anchor='w')
        Entry(conn_frame, textvariable=self.username, bg=Colors["INPUT_BG"], fg=Colors["FG"],
              insertbackground=Colors["FG"], relief='flat').pack(fill='x', pady=2)

        Label(conn_frame, text="Пароль:", bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 10)).pack(anchor='w')
        Entry(conn_frame, textvariable=self.password, show="*", bg=Colors["INPUT_BG"],
              fg=Colors["FG"], insertbackground=Colors["FG"], relief='flat').pack(fill='x', pady=2)

        # CONNECT / DISCONNECT BUTTONS
        btns = Frame(main_frame, bg=Colors["BG"])
        btns.pack(pady=10)

        Button(btns, text="Подключиться", command=self._connect, bg=Colors["SUCCESS"],
               fg="#282c34", font=("Helvetica", 10, "bold"), relief='flat', width=15).pack(side='left', padx=10)

        Button(btns, text="Отключиться", command=self._disconnect, bg=Colors["ERROR"],
               fg="#282c34", font=("Helvetica", 10, "bold"), relief='flat', width=15).pack(side='left', padx=10)

        # STATUS BLOCK
        statuses = Frame(main_frame, bg=Colors["BG"])
        statuses.pack(fill='both', expand=True)

        self.indicators = {
            'vpn': self._create_indicator(statuses, "VPN Статус"),
            'server': self._create_indicator(statuses, "Сервер"),
            'internet': self._create_indicator(statuses, "Интернет"),
        }

        self.ping_label = self._create_ping_display(statuses, "Пинг до сервера:")

        # SPLIT TUNNEL (process selector)
        split_frame = Frame(main_frame, bg=Colors["BG"], pady=10)
        split_frame.pack(fill='x')

        Label(split_frame, text="Split Tunneling — Белый список",
              bg=Colors["BG"], fg=Colors["FG"], font=("Helvetica", 12, "bold")).pack(anchor='w')

        proc_frame = Frame(split_frame, bg=Colors["BG"])
        proc_frame.pack(fill='x', pady=5)

        Label(proc_frame, text="Активные процессы:",
              bg=Colors["BG"], fg=Colors["FG"]).pack(side='left')

        self.proc_menu = ttk.Combobox(proc_frame, textvariable=self.active_processes, state="readonly", width=30)
        self.proc_menu.pack(side='left', padx=5)

        Button(proc_frame, text="Обновить", command=self._populate_processes,
               bg=Colors["BUTTON"], fg="#282c34", relief='flat').pack(side='left', padx=3)

        Button(proc_frame, text="Добавить", command=self._add_exception,
               bg=Colors["BUTTON"], fg="#282c34", relief='flat').pack(side='left')

        # LISTBOX
        list_frame = Frame(split_frame, bg=Colors["BG"])
        list_frame.pack(fill='both', expand=True)

        self.exception_listbox = Listbox(
            list_frame,
            bg=Colors["INPUT_BG"], fg=Colors["FG"],
            relief='flat',
            selectbackground=Colors["BUTTON"]
        )
        self.exception_listbox.pack(side='left', fill='both', expand=True)

        scrollbar = Scrollbar(list_frame, command=self.exception_listbox.yview)
        scrollbar.pack(side='right', fill='y')
        self.exception_listbox.config(yscrollcommand=scrollbar.set)

        Button(split_frame, text="Удалить выбранное", command=self._remove_exception,
               bg=Colors["ERROR"], fg="#282c34", relief='flat').pack(pady=5)

    # ------------------- INDICATORS -------------------
    def _create_indicator(self, parent, text):
        frame = Frame(parent, bg=Colors["BG"])
        frame.pack(fill='x', pady=4)

        Label(frame, text=text, bg=Colors["BG"], fg=Colors["FG"],
              font=("Helvetica", 11)).pack(side='left')

        canvas = Canvas(frame, width=20, height=20, bg=Colors["BG"], highlightthickness=0)
        canvas.pack(side='right')

        circle = canvas.create_oval(5, 5, 18, 18, fill=Colors["OFF"], outline="")
        return canvas, circle

    def _create_ping_display(self, parent, text):
        frame = Frame(parent, bg=Colors["BG"])
        frame.pack(fill='x', pady=4)

        Label(frame, text=text, bg=Colors["BG"], fg=Colors["FG"],
              font=("Helvetica", 11)).pack(side='left')

        ping_label = Label(frame, text="N/A", bg=Colors["BG"], fg=Colors["FG"],
                           font=("Helvetica", 11, "bold"))
        ping_label.pack(side='right')

        return ping_label

    def _set_indicator(self, key, status):
        canvas, circle = self.indicators[key]
        if status in ["Online", "Enabled"]:
            canvas.itemconfig(circle, fill=Colors["SUCCESS"])
        else:
            canvas.itemconfig(circle, fill=Colors["ERROR"])

    # ------------------- PING QUEUE -------------------
    def start_internet_ping(self):
        if self.internet_ping_thread:
            self.internet_ping_thread.stop()

        self.internet_ping_thread = PingThread("google.com", self.q, "internet_ping")
        self.internet_ping_thread.start()

    def _check_queue(self):
        try:
            while True:
                typ, val = self.q.get_nowait()

                if typ == "server_ping":
                    self.ping_label.config(text=f"{val} ms")
                    self._set_indicator('server', 'Online')

                elif typ == "internet_ping":
                    self._set_indicator('internet', 'Online')

                elif typ.endswith("_status"):
                    key = typ.split("_")[0]
                    self._set_indicator(key, val)

        except queue.Empty:
            pass

        self.after(100, self._check_queue)

    # ------------------- CONNECT -------------------
    def _run_in_thread(self, target, *args):
        threading.Thread(target=target, args=args, daemon=True).start()

    def _connect(self):
        self._save_config()

        ovpn = self.ovpn_path.get()
        user = self.username.get()
        pwd = self.password.get()

        if not all([ovpn, user, pwd]):
            messagebox.showwarning("Ошибка", "Заполните все поля.")
            return

        all_ips = set()
        for ip_list in self.whitelist.values():
            all_ips.update(ip_list)

        self._set_indicator('vpn', "Enabled")
        self._run_in_thread(self.vpn.connect, ovpn, user, pwd, list(all_ips))

    def _disconnect(self):
        self._set_indicator('vpn', "Disabled")
        self._run_in_thread(self.vpn.disconnect)

    # ------------------- SPLIT TUNNEL -------------------
    def _populate_processes(self):
        try:
            processes = sorted({p.name() for p in psutil.process_iter(['name'])})
            self.proc_menu['values'] = processes
            if processes:
                self.active_processes.set(processes[0])
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось получить процессы: {e}")

    def _add_exception(self):
        proc_name = self.active_processes.get()
        if not proc_name:
            return messagebox.showinfo("Информация", "Сначала выберите процесс.")

        found_ips = set()

        pids = [
            p.info['pid'] for p in psutil.process_iter(['pid', 'name'])
            if p.info['name'] == proc_name
        ]

        for pid in pids:
            try:
                p = psutil.Process(pid)
                for conn in p.connections(kind='inet'):
                    if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                        found_ips.add(conn.raddr.ip)
            except Exception:
                pass

        if not found_ips:
            return messagebox.showinfo("Информация", "Нет активных подключений.")

        if proc_name not in self.whitelist:
            self.exception_listbox.insert("end", proc_name)

        self.whitelist.setdefault(proc_name, set()).update(found_ips)

        messagebox.showinfo("Успех", f"Добавлено IP: {len(found_ips)}")

    def _remove_exception(self):
        selected = self.exception_listbox.curselection()
        if not selected:
            return messagebox.showinfo("Информация", "Выберите процесс.")

        for i in selected[::-1]:
            name = self.exception_listbox.get(i)
            self.exception_listbox.delete(i)
            self.whitelist.pop(name, None)

    # ------------------- EXIT -------------------
    def _on_closing(self):
        if self.server_ping_thread:
            self.server_ping_thread.stop()
        if self.internet_ping_thread:
            self.internet_ping_thread.stop()

        self._save_config()
        self.destroy()


# ------------------- MAIN -------------------
def main():
    if not IS_WINDOWS:
        messagebox.showerror("Ошибка", "Только Windows.")
        return
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
