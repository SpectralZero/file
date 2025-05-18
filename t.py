# import requests

# def check_internet_via_http(url: str = "https://www.google.com", timeout: float = 3.0) -> bool:
#     """
#     Returns True if we can successfully perform a HEAD request to `url`.
#     """
#     try:
#         requests.head(url, timeout=timeout)
#         return True
#     except requests.RequestException:
#         return False
    
# print(f"Has internet: {check_internet_via_http()}")

import socket
import sys
from tkinter import messagebox
def check_internet_via_socket(host: str = "8.8.8.8", port: int = 53, timeout: float = 3.0) -> bool:
    """
    Returns True if we can open a TCP connection to (host, port).
    Default host=Google DNS, port=53.
    """
    try:
        socket.setdefaulttimeout(timeout)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))
        return True
    except socket.error:
        return False
    
def ensure_online():
    if not check_internet_via_socket():  # or check_internet_via_socket()
        messagebox.showerror(
            "No Internet Connection",
            "Unable to reach the Internet.\n"
            "Please check your network and try again."
        )
        sys.exit(1)

    else:
        print("Connected to the Internet.")    


ensure_online()
