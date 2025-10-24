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

*   **Fully Automated Setup:** Scripts handle installation and configuration on both server and client.
*   **No Python Dependencies:** Uses only the standard Python library, making the setup lightweight and simple.
*   **User-Friendly GUI:** The Windows client features a clean interface for connecting, disconnecting, and monitoring the VPN status.
*   **Flexible Authentication:** Supports both interactive (browser-based) login and headless authentication using a Tailscale Auth Key (`TS_AUTHKEY`).
*   **Real-time Diagnostics:** The client GUI shows live status for ping, Tailscale connection, exit node status, and your external IP address.
*   **Built-in Troubleshooting:** The scripts provide clear, English-language logging to diagnose and resolve common issues.

## Prerequisites

*   A **Raspberry Pi** (any model with network access) running Raspberry Pi OS or another Debian-based Linux distribution.
*   A **Windows PC** (Windows 10 or 11).
*   A **Tailscale Account** (a free personal account is sufficient).

## Installation and Setup

Follow these steps to get SANYA-VPN up and running.

### 1. Server Setup (Raspberry Pi)

1.  **Clone the Repository:**
    Open a terminal on your Raspberry Pi and clone this repository:
    ```bash
    git clone <repository_url>
    cd sanya-vpn
    ```

2.  **Run the Setup Script:**
    Execute the server setup script with `sudo`. This is required for installing software and modifying network settings.
    ```bash
    sudo python3 server/server_vpn_setup.py
    ```
    *   The script will first check if Tailscale is installed and, if not, will install it.
    *   It will then prompt you to log in. An interactive login will provide a URL to open in a browser on any device to authenticate.
    *   **For headless setup,** you can use an [Auth Key](https://tailscale.com/kb/1085/auth-keys/) from your Tailscale admin console:
        ```bash
        export TS_AUTHKEY="your_auth_key_here"
        sudo -E python3 server/server_vpn_setup.py
        ```
        *(Note the `-E` flag to preserve the environment variable)*.

3.  **Approve the Exit Node:**
    After the script completes, you **must** approve the Raspberry Pi as an exit node in your [Tailscale Admin Console](https://login.tailscale.com/admin/machines). Find your Raspberry Pi in the list of machines, click the menu (`...`), and select `Edit route settings...` > `Use as exit node`.

4.  **Get the Tailscale IP:**
    The script will output the Tailscale IP address of your Raspberry Pi (e.g., `100.x.y.z`). Note this down; you will need it for the client.

### 2. Client Setup (Windows)

1.  **Clone or Download the Repository:**
    Get the project files onto your Windows machine.

2.  **Prepare the Environment:**
    Navigate to the repository folder and run the environment setup script by double-clicking `install_venv.bat`. This script will:
    *   Check if Python is installed.
    *   Create a Python virtual environment in a `venv` folder.
    *   Check if Tailscale is installed.

3.  **Launch the SANYA-VPN Client:**
    Double-click `SANYA-VPN.bat` to start the client application.

## How to Use the Client GUI

1.  **First-Time Login:** If you are not logged into Tailscale, the application will guide you through the interactive browser login.
2.  **Enter Exit Node IP:** In the "Exit Node IP/Name" field, enter the Tailscale IP address of your Raspberry Pi that you noted earlier.
3.  **Connect:** Click the **"Connect to Exit Node"** button. The status indicators will update to show the connection progress. Once connected, your external IP should match your Raspberry Pi's public IP.
4.  **Disconnect:** Click the **"Disconnect"** button to stop routing traffic through the exit node.

## Troubleshooting FAQ

*   **Server script fails with a "must be run as root" error.**
    *   **Solution:** You forgot to use `sudo`. Run the command as `sudo python3 server/server_vpn_setup.py`.

*   **Client GUI shows "Connected" but my IP address hasn't changed.**
    *   **Solution:** Ensure you have approved the Raspberry Pi as an exit node in the Tailscale admin console. This is a mandatory security step. Also, check the logs in the client for any routing errors.

*   **Client can't find `tailscale.exe`.**
    *   **Solution:** Make sure Tailscale is installed on your Windows machine in the default location (`C:\Program Files\Tailscale`). If it's not, the client will prompt you to open the download page.

*   **Headless authentication with `TS_AUTHKEY` does not work.**
    *   **Solution (Server):** Make sure you are using `sudo -E` to preserve the environment variable for the root user.
    *   **Solution (Client):** Ensure the `TS_AUTHKEY` environment variable is set for the current user before running the `.bat` file.

## Files in This Repository

*   `README.md`: This file.
*   `server/server_vpn_setup.py`: The main automation script for the Raspberry Pi server.
*   `server/server_commands.txt`: A text file with the key shell commands for manual server setup.
*   `client/client_vpn_setup.py`: The Python script for the Windows GUI client.
*   `SANYA-VPN.bat`: A batch file to easily launch the client application on Windows.
*   `install_venv.bat`: A batch file to prepare the Python environment on Windows.
*   `LICENSE`: The project's license file.
