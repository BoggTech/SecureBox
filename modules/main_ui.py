import base64
import os.path
import re
import tkinter as tk
import tkinter.filedialog
import logging
import tkinter.messagebox
from tkinter import IntVar
from cryptography.exceptions import InvalidSignature
import modules.globals as globals
import modules.box as box
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from modules.globals import aes_decrypt_file


class MainUI(tk.Frame):
    """The main program ui, for uploading and adding people to your group."""
    def __init__(self, username, private_key, master=None, on_logout=None):
        super().__init__(master)
        self.master = master
        self.username = username
        self.private_key = private_key

        row = 0

        # application title
        greeting = tk.Label(master=self, text="SecureBox v0.1", font='Arial 25 bold')
        greeting.grid(column=0, row=row, columnspan=6)
        row += 1

        # refresh button
        self.refresh = tk.Button(master=self, text="Refresh", font='Arial 12', command=self.refresh_with_cooldown)
        self.refresh.grid(column=0, row=row, columnspan=6)
        row += 1

        # group users list
        tk.Label(master=self, text="In Group", font='Arial 12').grid(column=4, row=row, columnspan=2)
        self.group_list = tk.Listbox(master=self)
        self.group_list.grid(column=4, row=row+1, columnspan=2, rowspan=5, padx=25)
        self.remove_button = tk.Button(master=self, text="Remove", font='Arial 12', command=self.on_remove_group)
        self.remove_button.grid(column=4, row=row+6, columnspan=2, pady=10)
        self.group = {}

        # files
        tk.Label(master=self, text="Files", font='Arial 12').grid(column=0, row=row, columnspan=4)
        self.file_list = tk.Listbox(master=self)
        self.file_list.grid(column=0, row=row+1, columnspan=4, rowspan=12, sticky='nsew', padx=25)
        self.file_dict = {}

        row += 7

        # user list
        tk.Label(master=self, text="Users", font='Arial 12').grid(column=4, row=row, columnspan=2)
        row += 1
        self.user_list = tk.Listbox(master=self)
        self.user_list.grid(column=4, row=row, columnspan=2, rowspan=5, padx=25)
        self.users = {}
        row += 5
        self.add_button = tk.Button(master=self, text="Add", font='Arial 12', command=self.on_add_group)
        self.add_button.grid(column=4, row=row, columnspan=2, pady=10)
        row += 1

        # upload button
        self.upload_button = tk.Button(master=self, text="Upload", font='Arial 12', command=self.on_upload)
        self.upload_button.grid(column=0, row=15, columnspan=2, pady=10)

        # download button
        self.download_button = tk.Button(master=self, text="Download", font='Arial 12', command=self.on_download)
        self.download_button.grid(column=2, row=15, columnspan=2, pady=10)

        # logout button
        self.logout_button = tk.Button(master=self, text="Log Out", font='Arial 12', command=on_logout)
        self.logout_button.grid(column=0, row=16, columnspan=6, pady=10)

        # ensure downloads/temp folder exists
        if not (os.path.exists("downloads") and os.path.isdir("downloads")):
            os.mkdir("downloads")
        if not (os.path.exists("temp") and os.path.isdir("temp")):
            os.mkdir("temp")

        # set up box connection
        with open(os.path.join("auth", "box_token"), "r") as f:
            auth = f.read()
            self.box_connection = box.BoxConnection(auth)

        # load the servers public key
        self.server_public = serialization.load_pem_public_key(open("auth\\-server-public.pem", "rb").read())

        # refresh all data
        self.refresh_all()

    def enable_refresh_button(self):
        self.refresh["state"] = "active"

    def disable_refresh_button(self):
        self.refresh["state"] = "disabled"

    def refresh_all(self):
        # refresh everything to be up to date
        self.get_users_from_server()
        self.get_group_from_server()
        self.add_files_to_list()

    def refresh_with_cooldown(self):
        """Refresh and disable the button for an amount of time."""
        self.disable_refresh_button()
        self.refresh_all()
        self.refresh.after(globals.COOLDOWN, self.enable_refresh_button)

    def add_files_to_list(self):
        folder = self.box_connection.get_all_files()
        self.file_list.delete(0, tk.END)
        self.file_dict = {}
        for file in folder:
            if not file.type == "folder":
                self.file_list.insert(tk.END, file.name)
                self.file_dict[file.name] = file.id

    def get_users_from_server(self):
        self.user_list.delete(0, tk.END)                          # clear list as-is
        response = json.loads(globals.get_server("/getusers").text)    # get users from server
        users = globals.verify_response(response, self.server_public)  # verify
        if users is None:
            logging.getLogger().log(logging.CRITICAL, "Failed to verify server's message")
            exit(1)
        for user in users.keys():                                      # finally, insert new values
            self.user_list.insert(tk.END, user)
        self.users = users  # keep track of user public keys

    def get_group_from_server(self):
        self.group_list.delete(0, tk.END)                        # clear list as-is
        response = json.loads(globals.get_server("/getgroup").text)   # get group from server
        group = globals.verify_response(response, self.server_public) # verify
        if group is None:
            logging.getLogger().log(logging.CRITICAL, "Failed to verify server's message")
            exit(1)
        for user in group.keys():                                     # finally, insert new values
            self.group_list.insert(tk.END, user)
        self.group = group

    def on_download(self):
        """function called when download button is pressed"""
        # check if we're part of the group
        response_code = globals.get_server("/isgroup/{}".format(self.username)).status_code
        if not response_code == 200:
            tk.messagebox.showerror("Error", "Non-group users can't decrypt files.")
            return

        # get file info for what we're downloading
        list_id = self.file_list.curselection()
        if not list_id:
            return
        name = self.file_list.get(list_id[0])
        file_id = self.file_dict[self.file_list.get(list_id[0])]

        # get the AES key for the file
        params = globals.build_response({"username": self.username, "filename": name}, self.private_key)
        response = json.loads(globals.post_server("/getkey", params).text)
        keys = globals.verify_response(response, self.server_public)
        if keys is None:
            logging.getLogger().log(logging.CRITICAL, "Failed to verify server's message")
            exit(1)
        b64_aes = keys["key"] if "key" in keys else None
        if b64_aes is None:
            logging.getLogger().log(logging.CRITICAL, "We have no key for this file.")
            return

        # download the encrypted file
        self.box_connection.download_file("temp\\" + name, file_id)

        # decrypt the AES key
        aes_encrypted = base64.b64decode(b64_aes)
        aes = globals.decrypt(aes_encrypted, self.private_key)

        # decrypt the file
        with open("temp\\" + name, "rb") as f:
            plaintext = aes_decrypt_file(aes, f.read())

        # save the file to downloads
        with open("downloads\\" + name, "wb") as f:
            f.write(plaintext)

        # remove temp files
        os.remove("temp\\" + name)

    def on_upload(self):
        """function called when the upload button is pressed"""
        # check if we're part of the group
        response_code = globals.get_server("/isgroup/{}".format(self.username)).status_code
        if not response_code == 200:
            tk.messagebox.showerror("Error", "Non-group users can't upload.")
            return
        path = tk.filedialog.askopenfilename()
        filename = os.path.basename(path)
        if not path:
            return
        with open(path, "rb") as f:
            output_bytes = f.read()   # read file from user
        # encrypt file and get the key
        key, file = globals.aes_encrypt_file(output_bytes)
        # write encrypted file to disk
        with open("temp\\" + filename, "wb") as f:
            f.write(file)
        # encrypt a version for every user
        encrypted_keys = {}
        for group_user in self.group:
            encrypted_keys[group_user] = {}
            public_key = serialization.load_pem_public_key(self.users[group_user].encode("utf-8"))
            encrypted_key = globals.encrypt(key, public_key)
            encrypted_keys[group_user][filename] = base64.b64encode(encrypted_key).decode("utf-8")
        # upload encrypted file to box
        self.box_connection.upload_file("temp\\" + filename, filename)
        # send those keys to the server
        params = globals.build_response({"username": self.username, "keys": encrypted_keys}, self.private_key)
        globals.post_server("/insertkeys", params)
        self.refresh_all()

    def on_add_group(self):
        """function called when add to group button is pressed"""
        list_id = self.user_list.curselection()
        if not list_id:
            return
        new_username = self.user_list.get(list_id[0])

        # add user to the group
        params = globals.build_response({"username": self.username,
                                                "username_to_add": new_username}, self.private_key)
        if not globals.post_server("/addgroup", params).status_code == 200:
            return

        # get all of our keys
        params = globals.build_response({"username": self.username, "username_to_fetch": self.username},
                                        self.private_key)

        response = json.loads(globals.post_server("/getallkeys", params).text)
        keys = globals.verify_response(response, self.server_public)
        if keys is None:
            logging.getLogger().log(logging.CRITICAL, "Failed to verify server's message")
            exit(1)

        # unencrypt our key for each file, then re-encrypt it with the new users public key
        new_public_key = serialization.load_pem_public_key(self.users[new_username].encode("utf-8"))
        new_keys = {new_username: {}}
        for filename in keys:
            encoded_key = base64.b64decode(keys[filename].encode("utf-8"))
            aes_key = globals.decrypt(encoded_key, self.private_key)
            encrypted_aes = globals.encrypt(aes_key, new_public_key)
            new_keys[new_username][filename] = base64.b64encode(encrypted_aes).decode("utf-8")

        params = globals.build_response({"username": self.username, "keys": new_keys}, self.private_key)
        globals.post_server("/insertkeys", params)
        self.refresh_all()

    def on_remove_group(self):
        """function called when remove from group button is pressed"""
        list_id = self.group_list.curselection()
        if not list_id:
            return
        remove_username = self.group_list.get(list_id[0])
        params = globals.build_response({"username": self.username,
                                                "username_to_remove": remove_username}, self.private_key)

        globals.post_server("/removegroup", params)
        self.refresh_all()


if __name__ == '__main__':
    root = tk.Tk()
    MainUI(master=root).grid(column=0, row=0)
    root.mainloop()