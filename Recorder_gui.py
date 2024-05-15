import tkinter as tk
from tkinter import ttk  # Добавленный импорт
import subprocess


class TcpdumpGUI:
    def __init__(self, parent):
        self.parent = parent

        # Создаем объект ttk.Notebook
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill='both', expand=True)

        # Создаем фрейм для вкладки
        self.frame = ttk.Frame(self.notebook)
        self.notebook.add(self.frame, text="PCAP Recorder")
        self.interface_label = tk.Label(self.frame, text="Выберите интерфейс:")
        self.interface_label.pack()

        self.interfaces = ["ens33", "eth0", "wlan0"]  # Пример списка интерфейсов
        self.interface_var = tk.StringVar(self.frame)
        self.interface_var.set(self.interfaces[0])
        self.interface_menu = tk.OptionMenu(self.frame, self.interface_var, *self.interfaces)
        self.interface_menu.pack()

        self.filename_label = tk.Label(self.frame, text="Введите название файла pcap:")
        self.filename_label.pack()

        self.filename_entry = tk.Entry(self.frame)
        self.filename_entry.pack()

        self.start_button = tk.Button(self.frame, text="Начать запись", command=self.start_tcpdump)
        self.start_button.pack()

        self.stop_button = tk.Button(self.frame, text="Остановить запись", command=self.stop_tcpdump, state=tk.DISABLED)
        self.stop_button.pack()

    def start_tcpdump(self):
        interface = self.interface_var.get()
        filename = self.filename_entry.get() + ".pcap" if self.filename_entry.get() else "testo.pcap"
        command = ["tcpdump", "-i", interface, "-w", filename]

        self.process = subprocess.Popen(command)

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

    def stop_tcpdump(self):
        self.process.terminate()

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
