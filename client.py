import os.path
import tkinter as tk
import logging
from modules.login import LoginRegister
from modules.box import BoxConnection
from modules.main_ui import MainUI
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import json
from cryptography.hazmat.primitives.asymmetric import padding

logging.basicConfig(level=logging.INFO)

if not os.path.exists("auth"):
    os.mkdir("auth")

window = tk.Tk()

def login_callback(username, private_key):
    logging.getLogger().log(logging.INFO, "Logged in as user " + username)
    # remove login stuff
    for widget in window.winfo_children():
        widget.destroy()

    main_ui = MainUI(username, private_key, window, create_login)
    main_ui.grid(column=0, row=0)

def create_login():
    # remove everything
    for widget in window.winfo_children():
        widget.destroy()

    login = LoginRegister(master=window, on_complete=login_callback)
    login.grid(column=0, row=0, columnspan=2)

create_login()
#print(tk.filedialog.askopenfilename())
window.mainloop()