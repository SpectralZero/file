#!/usr/bin/env python
"""
Secure-Chat Client
──────────────────
• TLS client socket with pinning
• Login GUI (CustomTkinter)
• USB 2-factor picker
• Heartbeat + auto-reconnect (keeps GUI alive)
"""

import os, socket, ssl, sys, threading, time, logging
from typing import Tuple, Optional, Dict

from cryptography.hazmat.primitives import serialization 

import base64, os                                   
from security import (                              
    encrypt_message, decrypt_message,
    generate_ecdh_keypair, derive_shared_key
)

import customtkinter as ctk
from tkinter import messagebox

from ui.login_screen import LoginDialog
from utils.tls_setup  import configure_tls_context
from logging_config   import setup_logging

logger = setup_logging()
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

MAX_MSG_LEN = 64 * 1024           # max 64 KB

class AuthRetryError(Exception):
    """Wrong password / temporary lock - show dialog again."""

class ChatClient:
    HEARTBEAT_INTERVAL = 20       # send a ping every 20 s.
    RECONNECT_MAX_TRIES = 5
    BACKOFF_BASE_SECS = 2         # 1, 2, 4, 8… seconds  exponential backoff

    def __init__(self, master: ctk.CTk, host: str,
                 server_port: int, client_port: int,
                 position: Tuple[int, int] = (100, 100)):
        self.master = master
        self.host, self.server_port, self.client_port = host, int(server_port), int(client_port)
        self.position = position
        self.username = self.password = ""
        self.tls_ctx: Optional[ssl.SSLContext] = None
        self.sock: Optional[ssl.SSLSocket] = None
        self.running = False       #for controls loops (heartbeat & recv loop)                
        self.recipient = "Everyone"

        # E2E keys
        self.priv, self.pub = generate_ecdh_keypair()
        self.peer_keys : Dict[str, bytes] = {} 

        self.peer_keys[self.username] = b""

    # ── main entry ──────────────────────────────────────────────────
    def start(self) -> None:
        # TLS context – pin to server_cert.pem
        server_cert = os.path.join(os.path.dirname(__file__),
                                   "utils", "cert", "server_cert.pem")
        self.tls_ctx = configure_tls_context(
            certfile=None, keyfile=None,
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile=server_cert)

        # ---- login loop ------------------------------------------------
        while True:
            dlg = LoginDialog(self.master)
            self.master.wait_window(dlg)
            if dlg.result is None:           # user pressed Cancel / closed
                self.master.quit()
                return
            self.username, self.password = dlg.result

            try:
                self._open_socket()
                self._authenticate()
                break                        # SUCCESS → out of login loop
            except AuthRetryError as e:
                messagebox.showerror("Login error", str(e))
                try:                         # drop the half-open socket
                    self.sock.close()
                except Exception:
                    pass
                continue                     # show login dialog again
            except Exception as e:
                messagebox.showerror("Connection error", str(e))
                self.master.quit()
                return

        # GUI + threads
        self._build_gui()
        self.running = True
        threading.Thread(target=self._recv_loop, daemon=True).start()
        self._restart_heartbeat()

    # ── networking ──────────────────────────────────────────────────
    def _open_socket(self):
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind(("0.0.0.0", self.client_port))
        self.sock = self.tls_ctx.wrap_socket(raw, server_hostname=self.host)
        self.sock.connect((self.host, self.server_port))
        logger.info("Connected to %s:%s", self.host, self.server_port)

    def _authenticate(self):
        # 1) send credentials
        self._send_prefixed(f"{self.username}:{self.password}".encode())
        reply = self._recv_prefixed().decode()

        if reply == "USBREQ":
            pass  # continue to USB stage (passwor and  username are OK)

        elif reply.startswith("LOGINFAIL"):
            tries = int(reply.split()[1])
            raise AuthRetryError(f"Wrong password - {tries} attempt(s) left.")

        elif reply.startswith("LOCKED"):
            mins = max(1, int(reply.split()[1]) // 60)
            raise AuthRetryError(f"Too many failures. Try again in {mins} minute(s).")

        else:
            raise RuntimeError("Login rejected")

        # 2) USB loop
        while True:
            token = self._pick_usb_token()
            if token is None:
                messagebox.showerror("USB Key", "Insert the correct USB key.")
                continue
            self._send_prefixed(f"{token[0]}:{token[1]}".encode())
            reply = self._recv_prefixed().decode()

            if reply == "SUCCESS":
                logger.info("Authenticated (USB OK)")
                self._send_keypub()
                self.peer_keys[self.username] = b""
                return
            if reply.startswith("USBFAIL"):
                left = int(reply.split()[1])
                messagebox.showerror("USB Key",
                                     f"Wrong key - {left} attempt(s) left.")
                continue
            if reply.startswith("LOCKED"):
                mins = max(1, int(reply.split()[1]) // 60)
                raise RuntimeError(f"USB locked for {mins} minute(s).")
            raise RuntimeError(f"Unexpected: {reply}")

    # ── USB picker (unchanged) ───────────────────────────────────────
    @staticmethod
    def _pick_usb_token() -> Optional[Tuple[str, str]]:
        import win32api, os, hashlib, time, customtkinter as ctk

        def scan():
            found = []
            for d in win32api.GetLogicalDriveStrings().split('\000')[:-1]:
                kp = os.path.join(d, "key.dat")
                if os.path.exists(kp):
                    serial = str(win32api.GetVolumeInformation(d)[1])
                    digest = hashlib.sha256(open(kp, "rb").read()).hexdigest()
                    found.append((d, serial, digest))
            return found

        for _ in range(4):
            drives = scan()
            if drives:
                break
            time.sleep(0.5)
        else:
            return None

        if len(drives) == 1:  # only one drive found
            _, s, d = drives[0]
            return s, d

        win = ctk.CTkToplevel();  win.title("Select USB key");  win.grab_set()
        win.geometry("340x170");  choice: list[Tuple[str, str]] = []

        def pick(s, d):
            choice.append((s, d));  win.grab_release();  win.destroy()
        win.protocol("WM_DELETE_WINDOW", lambda: pick(None, None))

        for drv, serial, dig in drives:
            label = win32api.GetVolumeInformation(drv)[0] or "No-Label"
            ctk.CTkButton(win, text=f"{drv}  (Name: {label})",
                          command=lambda s=serial, d=dig: pick(s, d)
                          ).pack(padx=10, pady=6, fill="x")
        win.wait_window();return choice[0] if choice else None                               # .wait_window() blocks until closed (until USB selected)

    # ---------------- announce pubkey
    def _send_keypub(self):
        pub_b64 = base64.b64encode(
            self.pub.public_bytes(
                encoding = serialization.Encoding.PEM,
                format   = serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        self._send_prefixed(b"KEYPUB " + pub_b64)

    # ── heartbeat ───────────────────────────────────────────────────
    def _heartbeat(self):      #firewalls will silently drop idle TCP connections after a minute or two so we send a ping every 20 seconds to keep the connection alive
        while self.running:
            try:
                self._send_prefixed(b"PING")
            except Exception:
                break
            time.sleep(self.HEARTBEAT_INTERVAL)

    def _restart_heartbeat(self):
        if not any(t.name == "_hb" for t in threading.enumerate()):
            threading.Thread(target=self._heartbeat,
                             daemon=True, name="_hb").start()

    # ── sender / receiver ───────────────────────────────────────────
    def _send_prefixed(self, data: bytes):
        self.sock.sendall(len(data).to_bytes(4, "big") + data)

    def _recv_prefixed(self) -> bytes:
        hdr = self.sock.recv(4)
        length = int.from_bytes(hdr, "big") if hdr else 0
        return b"" if not hdr or length <= 0 or length > MAX_MSG_LEN else self.sock.recv(length)

    def _recv_loop(self):
        while self.running:
            try:
                data = self._recv_prefixed()
                if not data: raise ConnectionError("EOF")
                # ---- frame types ----
                if data.startswith(b"USERS "):
                    self._update_user_list(data.split(b" ", 1)[1].decode().split(","))
                    continue
                if data.startswith(b"KEYPUB "):      # peer pubkey
                    _, user, blob_b64 = data.decode().split(" ", 2)
                    if user == self.username: continue
                    peer_pub = base64.b64decode(blob_b64)
                    self.peer_keys[user] = derive_shared_key(
                        self.priv, peer_pub, b"", b"SecureChat AES-GCM")
                    if user == self.recipient:
                        self.entry.configure(state="normal")
    
                    continue
                if data.startswith(b"BCAST "):
                    _, sender_b, blob_b64 = data.split(b" ", 2)
                    sender = sender_b.decode()
                    # lookup the same key we used originally
                    key = self.peer_keys.get(sender)
                    if not key: 
                        return
                    pt = decrypt_message(key, base64.b64decode(blob_b64))
                    if pt is not None:
                        self._display(f"[{sender}] {pt}")
                    continue

                elif data.startswith(b"CIPH "):
                    _, sender, recipient, blob_b64 = data.split(b" ", 3)
                    if recipient.decode() != self.username:
                        continue
                    key = self.peer_keys.get(sender.decode())
                    # we know 'key' is exactly the right one, so decrypt
                    pt = decrypt_message(key, base64.b64decode(blob_b64))
                    if pt is not None:
                        self._display(f"[PM from {sender.decode()}] {pt}")

            except Exception as e:
                logger.warning("Connection lost: %s", e); self.running = False
                if not messagebox.askyesno("Disconnected",
                                           "Lost connection.\nReconnect?"):
                    self.master.quit(); return
                if self._reconnect(): continue
                messagebox.showerror("Reconnect failed", "Unable to reconnect.")
                self.master.quit(); return

    def _reconnect(self) -> bool:
        for attempt in range(1, self.RECONNECT_MAX_TRIES + 1):
            wait = self.BACKOFF_BASE_SECS ** (attempt - 1)
            logger.info("Reconnect attempt %s in %ss …", attempt, wait)
            time.sleep(wait)
            try:
                self.peer_keys.clear()
                self.priv, self.pub = generate_ecdh_keypair()
                self._open_socket(); self._authenticate(); self._send_keypub()
                self.running = True; self._restart_heartbeat(); return True
            except Exception as e:
                logger.warning("reconnect failed: %s", e)
        return False

    # ── GUI (unchanged) ─────────────────────────────────────────────
    def _build_gui(self):
        self.master.title(f"Secure Chat - {self.username}")
        self.master.geometry("800x680")
        self.master.configure(fg_color="#1a1a1a")
        self.master.geometry(f"+{self.position[0]}+{self.position[1]}")
        self.master.grid_columnconfigure(1, weight=1)
        self.master.grid_rowconfigure(1, weight=1)

        # sidebar
        sidebar = ctk.CTkFrame(self.master, width=250, fg_color="#212121")
        sidebar.grid(row=0, column=0, rowspan=3, sticky="ns",
                     padx=(10, 0), pady=10)
        self.user_list = ctk.CTkScrollableFrame(sidebar, label_text="Users",
                                                width=210, height=159,
                                                fg_color="#212121")
        self.user_list.pack(padx=3, pady=3, anchor="center")

        # header
        ctk.CTkLabel(self.master, text=f"Secure Chat - {self.username}",
                     font=("Courier New", 20, "bold"),
                     text_color="#5F87AF"
                     ).grid(row=0, column=1, pady=6, padx=10, sticky="ew")

        # chat textbox
        frame = ctk.CTkFrame(self.master, fg_color="#3A506B")
        frame.grid(row=1, column=1, padx=10, pady=6, sticky="nsew")
        self.textbox = ctk.CTkTextbox(frame, fg_color="#1a1a1a",
                                      text_color="#00FF00",
                                      font=("Courier New", 18),
                                      state="disabled")
        self.textbox.pack(fill="both", expand=True, padx=4, pady=4)

        # message entry
        input_fr = ctk.CTkFrame(self.master, fg_color="#1a1a1a")
        input_fr.grid(row=2, column=1, padx=10, pady=10, sticky="ew")
        input_fr.grid_columnconfigure(0, weight=1)

        self.entry = ctk.CTkEntry(input_fr, fg_color="#262626",
                                  text_color="#00FF00",
                                  font=("Helvetica", 18))
        self.entry.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        self.entry.bind("<Return>", self._send)
        self.entry.configure(state="disabled")


        ctk.CTkButton(input_fr, text="Send", fg_color="#8A9BA8",
                      text_color="#1a1a1a", command=self._send
                      ).grid(row=0, column=1, padx=5, pady=5)
        self.entry.focus()

    def _update_user_list(self, users):
        for w in self.user_list.winfo_children():
            w.pack_forget()
        self.user_labels = {}
        for u in ["Everyone", self.username] + [x for x in users if x != self.username]:
            lbl = ctk.CTkLabel(self.user_list, text=u, fg_color="#212121",
                               text_color="white", anchor="w", padx=10)
            lbl.pack(pady=2, padx=2, anchor="w", fill="x")
            lbl.bind("<Button-1>", lambda e, usr=u: self._set_recipient(usr))
            self.user_labels[u] = lbl
        if self.recipient not in users + ["Everyone"]:
            self._set_recipient("Everyone")

    def _set_recipient(self, user):
        # de-highlight old label
        if hasattr(self, "user_labels") and self.recipient in self.user_labels:
            self.user_labels[self.recipient].configure(fg_color="#212121")

        self.recipient = user                                 # store new choice

        # highlight new label
        if user in self.user_labels:
            self.user_labels[user].configure(fg_color="#2A2D2E")

        # enable Send if allowed
        self.entry.configure(
            state="normal" if (
                user == "Everyone" or
                user == self.username or                       # ← NEW
                (user in self.peer_keys and len(self.peer_keys[user]) == 32)
            ) else "disabled"
        )

    def _send(self, _=None):
        msg = self.entry.get().strip()
        if not msg:
            return

        try:
            # ── self-chat ──
            if self.recipient == self.username:
                self._display(f"You (self): {msg}")
                self.entry.delete(0, "end")
                return

            # ── broadcast to every other peer ──
            if self.recipient == "Everyone":
                # make sure at least one other key is ready
                ready = [u for u,k in self.peer_keys.items()
                        if u != self.username and len(k)==32]
                if not ready:
                    messagebox.showinfo(
                        "Waiting",
                        "No other user has completed key exchange; message not sent."
                    )
                    return

                # loop, encrypt once per recipient, send via CIPH route
                for peer in ready:
                    key = self.peer_keys[peer]
                    blob = encrypt_message(key, msg)
                    frame = (
                        b"CIPH " +
                        self.username.encode() + b" " +
                        peer.encode() + b" " +
                        base64.b64encode(blob)
                    )
                    self._send_prefixed(frame)

                shown = f"You: {msg}"

            # ── private PM ── (unchanged)
            else:
                key = self.peer_keys.get(self.recipient)
                if not key or len(key)!=32:
                    messagebox.showerror("Key error", "No key for user")
                    return
                blob = encrypt_message(key, msg)
                frame = (
                    b"CIPH " +
                    self.username.encode() + b" " +
                    self.recipient.encode() + b" " +
                    base64.b64encode(blob)
                )
                self._send_prefixed(frame)
                shown = f"You ➜ {self.recipient}: {msg}"

            # ── local echo ──
            self._display(shown)
            self.entry.delete(0, "end")

        except Exception as e:
            logger.error("send failed: %s", e)
            messagebox.showerror("Send error", str(e))
            self.master.quit()

    def _send_secure(self, target: str, msg: str, key: bytes):
        if target == self.username:
            self._display(f"You (self): {msg}")
            return

        if len(key) != 32:
            logger.warning("Key for %s not ready - message skipped", target)
            return

        blob  = encrypt_message(key, msg)
        frame = b"CIPH " + self.username.encode() \
            + b" " + target.encode() \
            + b" " + base64.b64encode(blob)
        self._send_prefixed(frame)

        # private PM
        blob  = encrypt_message(key, msg)
        frame = b"CIPH " + self.username.encode() + b" " + target.encode() + b" " + \
                base64.b64encode(blob)
        self._send_prefixed(frame)     

    def _display(self, text):
        self.textbox.configure(state="normal")
        self.textbox.insert("end", text + "\n")
        self.textbox.configure(state="disabled")
        self.textbox.yview("end")

    # ── cleanup ─────────────────────────────────────────────────────
    def close(self):
        logger.info("Client '%s' closing.", self.username)
        self.running = False
        try:
            if self.sock:
                self._send_prefixed(f"{self.username}:<left the chat>".encode())
                self.sock.close()
        except Exception:
            pass
        self.master.quit()

# ── entrypoint ──────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python secure_chat_client.py <server_ip> <server_port> <client_port>")
        sys.exit(1)
    host, srv_port, cli_port = sys.argv[1:]
    root = ctk.CTk()
    ChatClient(root, host, srv_port, cli_port).start()
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()
