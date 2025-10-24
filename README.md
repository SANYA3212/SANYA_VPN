# SANYA-VPN

**SANYA-VPN** is a comprehensive VPN solution that leverages Tailscale to route all internet traffic from a Windows client through a Raspberry Pi exit node. The entire setup and management process is automated with Python scripts, providing a simple and powerful way to secure your connection and access the internet via your home network from anywhere.

The project consists of two main components:
1.  **Server Script (`server_vpn_setup.py`):** An automation script for setting up a Raspberry Pi as a Tailscale exit node.
2.  **Client GUI (`client_vpn_setup.py`):** A user-friendly Tkinter application for Windows to easily manage the VPN connection.

## Architecture

The architecture is a straightforward client-server model:

*   **Server (Raspberry Pi):** Runs a Python script that installs, configures, and starts Tailscale. It enables IP forwarding and advertises itself as an "exit node" on your private Tailscale network (tailnet). This means other devices on your tailnet can route their internet traffic through it.
*   **Client (Windows):** Runs a GUI application that allows the user to connect to the Raspberry Pi exit node with a single click. It handles Tailscale installation, login, and the necessary network routing on the client machine. The GUI provides real-time status feedback on the connection.

## Features

*   **Modern UI:** A clean, dark-themed interface for comfortable use.
*   **Persistent Configuration:** Automatically saves your Raspberry Pi's IP address in a `config.json` file.
*   **Fully Automated Setup:** Scripts handle installation and configuration on both server and client.
*   **No Python Dependencies:** Uses only the standard Python library.
*   **Real-time Status Indicators:** The GUI provides clear, at-a-glance status for the VPN, Tailscale, Raspberry Pi, and internet connectivity.
*   **Flexible Authentication:** Supports both interactive (browser-based) login and headless authentication using a Tailscale Auth Key (`TS_AUTHKEY`).
*   **Built-in Troubleshooting:** The scripts provide clear, English-language logging to diagnose and resolve common issues.

## Prerequisites

*   A **Raspberry Pi** (any model with network access) running Raspberry Pi OS or another Debian-based Linux distribution.
*   A **Windows PC** (Windows 10 or 11).
*   A **Tailscale Account** (a free personal account is sufficient).

## Installation and Setup

### 1. Server Setup (Raspberry Pi)

1.  **Clone the Repository:**
    Open a terminal on your Raspberry Pi and clone this repository:
    ```bash
    git clone <repository_url>
    cd sanya-vpn
    ```

2.  **Run the Setup Script:**
    Execute the server setup script with `sudo`.
    ```bash
    sudo python3 server/server_vpn_setup.py
    ```
    *   The script will install Tailscale if needed and guide you through the login process.
    *   **For headless setup,** you can use an [Auth Key](https://tailscale.com/kb/1085/auth-keys/):
        ```bash
        export TS_AUTHKEY="your_auth_key_here"
        sudo -E python3 server/server_vpn_setup.py
        ```

3.  **Approve the Exit Node:**
    After the script completes, you **must** approve the Raspberry Pi as an exit node in your [Tailscale Admin Console](https://login.tailscale.com/admin/machines). Find your Raspberry Pi, click the menu (`...`), and select `Edit route settings...` > `Use as exit node`.

4.  **Get the Tailscale IP:**
    The script will output the Tailscale IP address of your Raspberry Pi (e.g., `100.x.y.z`). Note this down.

### 2. Client Setup (Windows)

1.  **Clone or Download the Repository.**

2.  **Prepare the Environment:**
    Double-click `install_venv.bat` to check for Python and create a virtual environment.

3.  **Launch the SANYA-VPN Client:**
    Double-click `SANYA-VPN.bat`.

## How to Use the Client GUI

1.  **First-Time Login:** If you are not logged into Tailscale, the application will guide you.
2.  **Enter Exit Node IP:** In the "Raspberry Pi (Exit Node) IP" field, enter the Tailscale IP address of your server. This will be saved automatically for future use.
3.  **Connect:** Click **"Enable VPN"**. The status indicators will turn green as the connection is established.
4.  **Disconnect:** Click **"Disable VPN"** to stop routing traffic through the exit node.

## Troubleshooting FAQ

*   **Server script fails with a "must be run as root" error.**
    *   **Solution:** Use `sudo` to run the script: `sudo python3 server/server_vpn_setup.py`.

*   **The status indicator for "Raspberry Pi" is red.**
    *   **Solution:** Ensure your Raspberry Pi is online and `tailscaled` is running. Verify that the IP address entered in the client is correct.

*   **VPN status is red ("Disabled") even after connecting.**
    *   **Solution:** Make sure you have approved the Raspberry Pi as an exit node in the Tailscale admin console. This is a mandatory security step.

## Files in This Repository

*   `README.md`: This file.
*   `server/server_vpn_setup.py`: The automation script for the Raspberry Pi.
*   `server/server_commands.txt`: A list of commands for manual server setup.
*   `client/client_vpn_setup.py`: The Python script for the Windows GUI client.
*   `client/config.json`: Stores the client configuration (created automatically).
*   `SANYA-VPN.bat`: A batch file to launch the client on Windows.
*   `install_venv.bat`: A batch file to prepare the Python environment on Windows.
*   `LICENSE`: The project's license file.
