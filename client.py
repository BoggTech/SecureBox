import os.path
import tkinter as tk
import logging
from modules.login import LoginRegister

logging.basicConfig(level=logging.INFO)

if not os.path.exists("auth"):
    os.mkdir("auth")

window = tk.Tk()

def login_callback(username, private_key):
    logging.log(logging.INFO, "Logged in as user " + username)
    # remove login stuff
    for widget in window.winfo_children():
        widget.destroy()

login = LoginRegister(master=window, on_complete=login_callback)
login.grid(column=0, row=0, columnspan=2)

#print(tk.filedialog.askopenfilename())

window.mainloop()