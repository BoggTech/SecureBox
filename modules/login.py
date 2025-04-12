import os.path
import re
import tkinter as tk
import logging
import tkinter.messagebox
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class LoginRegister(tk.Frame):
    """tkinter frame for logging in or registering, and handling the loading of private keys."""
    MIN_USERNAME_LENGTH = 3
    MAX_USERNAME_LENGTH = 32
    MIN_PASSWORD_LENGTH = 8

    def __init__(self, master=None, on_complete=None):
        """on_complete will be passed the username and private_key when complete."""
        self.frame = tk.Frame.__init__(self, master)
        self.on_complete = on_complete

        title = "Please enter your credentials:"

        greeting = tk.Label(text="SecureBox v0.1", font='Arial 25 bold')
        greeting.grid(column=0, row=0, columnspan=2)
        greeting1 = tk.Label(text=title, font='Arial 13')
        greeting1.grid(column=0, row=1, columnspan=2)

        command = self.on_button
        tk.Label(self.frame, text="Username").grid(row=2)
        self.e1 = tk.Entry(self.frame)
        self.e1.grid(row=2, column=1)

        tk.Label(self.frame, text="Password").grid(row=3)
        self.e2 = tk.Entry(self.frame)
        self.e2.grid(row=3, column=1)

        self.button = tk.Button(self.frame, text="Submit", width=10, command=command)
        self.button.grid(row=4, column=0, columnspan=2)

    def on_button(self):
        """Called when we register a new .pem"""
        # first, disable the button
        self.button["state"] = "disabled"

        # get values from input
        username = self.e1.get()
        password = self.e2.get()
        pem_location = os.path.join("auth", username + ".pem")

        # check if the values are right
        regex = "/^[A-Za-z0-9_]+$/"
        username_len = len(username)
        password_len = len(password)
        if username_len < self.MIN_USERNAME_LENGTH:
            tk.messagebox.showwarning("Registration Failed",
                                      "Username must be greater than {} characters".format(self.MIN_USERNAME_LENGTH))
            self.button["state"] = "active"
            return
        elif password_len < self.MIN_PASSWORD_LENGTH:
            tk.messagebox.showwarning("Registration Failed",
                                      "Password must be greater than {} characters".format(self.MIN_PASSWORD_LENGTH))
            self.button["state"] = "active"
            return
        elif username_len > self.MAX_USERNAME_LENGTH:
            tk.messagebox.showwarning("Registration Failed",
                                      "Username must be less than {} characters".format(self.MAX_USERNAME_LENGTH))
            self.button["state"] = "active"
            return
        elif not re.match("^[A-Za-z0-9_]+$", username):
            tk.messagebox.showwarning("Registration Failed",
                                      "Username must only contain alphanumeric characters or underscores.")
            self.button["state"] = "active"
            return

        # check for a username in our auth folder
        if not (os.path.exists(pem_location) and os.path.isfile(pem_location)):
            logging.log(logging.INFO, "Username " + username + " not found, creating...")
            # TODO: check username doesn't exist against server
            # generate a new private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # serialize and store to .pem
            serialized_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
            )

            with open(pem_location, "wb") as f:
                f.write(serialized_key)
            tk.messagebox.showinfo("Account Registered", "No account found with this username, so a new "
                                                         "one has been registered. PLEASE REMEMBER YOUR PASSWORD: "
                                   + password + " - IT CANT BE RESET!")

        password = self.e2.get().encode("utf-8")
        try:
            with open(pem_location, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=password,
                )
        except ValueError:
            tk.messagebox.showwarning("Login Failed", "Wrong password!")
            self.button["state"] = "active"
            return
        except FileNotFoundError:
            tk.messagebox.showwarning("Login Failed", "Missing key file. Did you just delete it? Try restarting.")
            self.button["state"] = "active"
            return

        tk.messagebox.showinfo("Login Successful!", "Successfully logged in.")
        self.button["state"] = "active"
        self.on_complete(username, private_key)