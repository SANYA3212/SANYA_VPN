# SANYA-VPN

**SANYA-VPN** is a self-hosted VPN solution using OpenVPN, designed for simplicity and security. It provides Python-based automation scripts to set up a robust OpenVPN server on a Debian-based machine (like a Raspberry Pi) and a user-friendly GUI client for Windows.

This project is ideal for users who want to route their internet traffic through their home network, securing their connection on public Wi-Fi and accessing local network resources from anywhere.

The project consists of two main components:
1.  **Server Script (`server/server_vpn_setup.py`):** An automation script that installs and configures a complete OpenVPN server, including certificate generation and user setup.
2.  **Client GUI (`client/client_vpn_setup.py`):** A user-friendly Tkinter application for Windows that allows you to manage the VPN connection, with an added feature for "split tunneling" on a per-application basis.

## Architecture

*   **Server (Raspberry Pi / Debian VPS):** Runs a Python script that automates the entire OpenVPN server setup. It installs `openvpn` and `easy-rsa`, generates the necessary server certificates, creates a default system user for authentication (via PAM), and generates a client configuration (`.ovpn`) file.
*   **Client (Windows):** Runs a GUI application that uses the generated `.ovpn` file to connect to the server. The client requires OpenVPN Community Edition to be installed. The GUI provides a clean interface for managing the connection and whitelisting specific applications whose traffic should be routed through the VPN.

## Features

*   **Fully Automated Server Setup:** A single script handles all server-side dependencies, configuration, and key generation.
*   **Modern Tkinter Client UI:** A clean, dark-themed interface for the Windows client.
*   **Username/Password Authentication:** Securely authenticates against system users on the server via the PAM plugin.
*   **Split Tunneling (Whitelist Mode):** The client can be configured to only route traffic for specific, user-selected applications through the VPN.
*   **Persistent Configuration:** The client saves your `.ovpn` file path and username for quick connections.
*   **Real-time Status Indicators:** The GUI provides at-a-glance status for the VPN connection and internet reachability.
*   **Portable Client:** The client can be run from any directory and can be compiled into a single `.exe` file.

## Prerequisites

*   A **Server Machine** running a Debian-based Linux distribution (e.g., Raspberry Pi OS, Debian, Ubuntu).
*   A **Public IP Address** on your server. If your server is behind a router (like a Raspberry Pi at home), you will need to set up **Port Forwarding**.
*   A **Windows PC** (Windows 10 or 11).
*   **OpenVPN Community Edition** installed on the Windows PC. You can download it [here](https://openvpn.net/community-downloads/).

## Installation and Setup

### 1. Server Setup (Raspberry Pi / Debian)

#### Step 1: Port Forwarding (If your server is on a home network)

If your server is a device like a Raspberry Pi on your home network, it's behind a router. You need to forward incoming traffic from the internet to your server.

1.  **Find your Server's Local IP:** On your server, run `hostname -I` to get its local IP address (e.g., `192.168.1.10`).
2.  **Log in to your Router:** Open a web browser and navigate to your router's admin page (commonly `192.168.1.1` or `192.168.0.1`).
3.  **Find the Port Forwarding Section:** This is usually in a section called "Port Forwarding," "Virtual Servers," or "Firewall."
4.  **Create a New Rule:**
    *   **Service/Rule Name:** `OpenVPN`
    *   **External Port:** `1194`
    *   **Internal Port:** `1194`
    *   **Protocol:** `UDP` (this is the default in the script)
    *   **Device/Internal IP:** The local IP of your server (e.g., `192.168.1.10`).
5.  **Save the rule and apply the changes.** Your router will now send all incoming OpenVPN traffic to your server.

#### Step 2: Run the Setup Script

1.  **Clone the Repository:**
    Open a terminal on your server and clone this repository:
    ```bash
    git clone <repository_url>
    cd sanya-vpn
    ```

2.  **Configure the Public IP:**
    Edit the server script to set your public IP address. Open the file `server/server_vpn_setup.py` with a text editor like `nano`:
    ```bash
    nano server/server_vpn_setup.py
    ```
    Find the line `SERVER_PUBLIC_IP = "YOUR_IP_HERE"` and replace `"YOUR_IP_HERE"` with your actual public IP address. If you don't know your public IP, you can find it by running `curl ifconfig.me` on your server.

3.  **Run the Script:**
    Execute the server setup script with `sudo`. This is required for installing packages and configuring the system.
    ```bash
    sudo python3 server/server_vpn_setup.py
    ```
    The script will now automate the entire setup process. When it's finished, it will generate a client configuration file named `SANYA-VPN.ovpn` in your home directory (`/home/<your_username>/`).

4.  **Transfer the `.ovpn` File:**
    You need to securely transfer this `SANYA-VPN.ovpn` file from your server to your Windows client machine. You can use a tool like `scp` (on Linux/macOS) or WinSCP (on Windows).

### 2. Client Setup (Windows)

1.  **Install OpenVPN Community Edition:** Make sure you have installed the official OpenVPN client from the link in the "Prerequisites" section.
2.  **Clone or Download the Repository** to your Windows PC.
3.  **Launch the SANYA-VPN Client:** Double-click `SANYA-VPN.bat`.
4.  **Configure the Client:**
    *   Click **"Select .ovpn File"** and choose the `SANYA-VPN.ovpn` file you transferred from the server.
    *   **Username:** Enter `SANYAPI` (the default username).
    *   **Password:** Enter the password you created during the server setup.
5.  **Connect:** Click the **"Connect"** button. The status indicators should turn green, indicating a successful connection.

## How to Use Split Tunneling

The client's split tunneling feature allows you to only send traffic from specific applications through the VPN, while the rest of your traffic goes through your normal internet connection.

1.  **Select a Process:** Choose a running application from the "Active Processes" dropdown menu. Click "Refresh" if you don't see your application.
2.  **Add to Whitelist:** Click the **"Add"** button. The client will find all active network connections for that application and add their destination IP addresses to a routing list. The application name will appear in the box below.
3.  **Connect:** When you click "Connect," only traffic destined for these collected IPs will be routed through the VPN.
4.  **Remove from Whitelist:** To remove an application, simply click the "Remove" button next to its name in the list.

## Compiling to .EXE (for Windows)

You can compile the client into a single `.exe` file for easy use without needing Python installed.

1.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    pip install pyinstaller
    ```

2.  **Run the Build Command:**
    Navigate to the project's root directory and run:
    ```bash
    pyinstaller --name "SANYA-VPN" --onefile --windowed --icon=NONE client/client_vpn_setup.py
    ```
3.  The final `SANYA-VPN.exe` will be in the `dist` folder.

## Troubleshooting FAQ

*   **Server script fails with a "must be run as root" error.**
    *   **Solution:** Use `sudo` to run the script: `sudo python3 server/server_vpn_setup.py`.

*   **Client fails to connect.**
    *   **Solution 1:** Verify that **Port Forwarding** is correctly set up on your router.
    *   **Solution 2:** Ensure your server's firewall is not blocking port `1194` for the `UDP` protocol.
    *   **Solution 3:** Double-check that the `SERVER_PUBLIC_IP` in the server script is correct.

*   **"OpenVPN not found" error on the client.**
    *   **Solution:** Make sure you have installed OpenVPN Community Edition on your Windows machine and that `openvpn.exe` is in the standard installation directory or your system's PATH.
