#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SANYA-VPN Server Setup Script

This script automates the setup of a Raspberry Pi as a Tailscale exit node.
It handles Tailscale installation, configuration, and system settings for IP forwarding.
The script is designed to be run on Raspberry Pi OS (or other Debian-based systems)
with administrator privileges (sudo).
"""

import subprocess
import os
import sys
import logging
import platform
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

def run_command(command, check=True):
    """
    Executes a shell command and logs its output.

    Args:
        command (list): The command to execute as a list of strings.
        check (bool): If True, raises a CalledProcessError on non-zero exit codes.

    Returns:
        subprocess.CompletedProcess: The result of the command execution.

    Raises:
        subprocess.CalledProcessError: If the command returns a non-zero exit code and check is True.
    """
    logging.info(f"Running command: {' '.join(command)}")
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=check,
            encoding='utf-8'
        )
        if result.stdout:
            logging.info(f"Output:\n{result.stdout.strip()}")
        if result.stderr:
            logging.warning(f"Errors/Warnings:\n{result.stderr.strip()}")
        return result
    except FileNotFoundError:
        logging.error(f"Command not found: {command[0]}")
        raise
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with exit code {e.returncode}: {' '.join(command)}")
        logging.error(f"STDOUT: {e.stdout.strip()}")
        logging.error(f"STDERR: {e.stderr.strip()}")
        raise

def check_sudo():
    """
    Checks if the script is being run with superuser (sudo) privileges.
    Exits if it's not.
    """
    if os.geteuid() != 0:
        logging.error("This script must be run as root. Please use 'sudo'.")
        sys.exit(1)
    logging.info("Sudo privileges check passed.")

def is_tailscale_installed():
    """
    Checks if the Tailscale binary is present in the system's PATH.

    Returns:
        bool: True if Tailscale is installed, False otherwise.
    """
    try:
        run_command(['which', 'tailscale'], check=True)
        logging.info("Tailscale is already installed.")
        return True
    except subprocess.CalledProcessError:
        logging.info("Tailscale is not installed.")
        return False

def install_tailscale():
    """
    Installs Tailscale using the official script for Raspberry Pi OS.
    """
    logging.info("Installing Tailscale...")
    try:
        # The official installer command
        install_command = [
            "bash", "-c",
            "curl -fsSL https://tailscale.com/install.sh | sh"
        ]
        run_command(install_command, check=True)
        logging.info("Tailscale installation completed successfully.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.error(f"Failed to install Tailscale: {e}")
        logging.error("Please try installing Tailscale manually from https://tailscale.com/download/")
        sys.exit(1)

def ensure_tailscale_running():
    """
    Ensures the tailscaled service is active and enabled.
    """
    logging.info("Ensuring tailscaled service is running...")
    try:
        # Use systemctl to check and start the service
        run_command(['systemctl', 'enable', '--now', 'tailscaled'], check=True)
        run_command(['systemctl', 'start', 'tailscaled'], check=True) # Ensure it's started
        status_result = run_command(['systemctl', 'is-active', 'tailscaled'], check=False)
        if status_result.stdout.strip() != "active":
             raise RuntimeError("tailscaled service is not active after attempting to start.")
        logging.info("tailscaled service is active.")
    except (subprocess.CalledProcessError, RuntimeError) as e:
        logging.error(f"Failed to start or enable tailscaled service: {e}")
        sys.exit(1)

def login_to_tailscale():
    """
    Logs into Tailscale using an auth key if provided, otherwise uses interactive login.
    """
    logging.info("Checking Tailscale login status...")
    try:
        # Check current status
        status_result = run_command(['tailscale', 'status'], check=False)
        if status_result.returncode == 0 and "Logged out" not in status_result.stdout:
            logging.info("Already logged into Tailscale.")
            return

        auth_key = os.environ.get('TS_AUTHKEY')
        command = ['tailscale', 'up']
        if auth_key:
            logging.info("Attempting to log in with TS_AUTHKEY...")
            command.extend(['--auth-key', auth_key])
        else:
            logging.info("No TS_AUTHKEY found. Starting interactive login.")
            logging.info("Please open the URL provided by Tailscale in your browser to authenticate.")

        # Always advertise as exit node during 'up'
        command.append('--advertise-exit-node')

        run_command(command, check=True)
        logging.info("Tailscale login successful.")

        # Give a moment for the network to settle
        time.sleep(5)

    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to log into Tailscale: {e}")
        logging.error("Please check your authentication key or network connection.")
        sys.exit(1)

def enable_ip_forwarding():
    """
    Enables IPv4 and IPv6 forwarding by updating sysctl settings.
    """
    logging.info("Enabling IP forwarding...")
    config_file = "/etc/sysctl.d/99-tailscale-forwarding.conf"
    settings = [
        "net.ipv4.ip_forward=1",
        "net.ipv6.conf.all.forwarding=1"
    ]
    try:
        with open(config_file, "w") as f:
            for setting in settings:
                f.write(setting + "\n")
        logging.info(f"Created/updated sysctl config at {config_file}.")

        # Apply the new settings
        run_command(['sysctl', '-p', config_file], check=True)
        logging.info("Successfully enabled IP forwarding.")
    except (IOError, subprocess.CalledProcessError) as e:
        logging.error(f"Failed to enable IP forwarding: {e}")
        logging.error("You may need to enable it manually.")
        sys.exit(1)

def advertise_exit_node():
    """
    Ensures the device is advertising itself as an exit node.
    This is often done with 'tailscale up', but this function makes sure.
    """
    logging.info("Advertising as an exit node...")
    try:
        # The 'tailscale up --advertise-exit-node' handles this,
        # but we can use 'tailscale set' to be certain.
        run_command(['tailscale', 'set', '--advertise-exit-node'], check=True)
        logging.info("Successfully advertised as an exit node.")
        logging.info("IMPORTANT: You may need to approve this exit node in the Tailscale admin console:")
        logging.info("https://login.tailscale.com/admin/machines")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to advertise as exit node: {e}")
        sys.exit(1)

def run_diagnostics():
    """
    Runs and displays various diagnostic commands to verify the setup.
    """
    logging.info("="*30)
    logging.info("       RUNNING DIAGNOSTICS")
    logging.info("="*30)
    try:
        logging.info("--- Tailscale Status ---")
        run_command(['tailscale', 'status'], check=True)

        logging.info("\n--- Tailscale IP ---")
        run_command(['tailscale', 'ip', '-4'], check=True)

        logging.info("\n--- IP Address Info ---")
        run_command(['ip', 'addr'], check=True)

        logging.info("\n--- IP Route Info ---")
        run_command(['ip', 'route'], check=True)

        logging.info("\n--- Traceroute to 8.8.8.8 ---")
        # Check if traceroute is installed
        try:
            run_command(['which', 'traceroute'], check=True)
            run_command(['traceroute', '8.8.8.8'], check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            logging.warning("'traceroute' command not found. Skipping.")

        logging.info("\n--- External IP Check ---")
        # Check if curl is installed
        try:
            run_command(['which', 'curl'], check=True)
            run_command(['curl', 'https://ifconfig.me'], check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            logging.warning("'curl' command not found. Skipping external IP check.")

    except subprocess.CalledProcessError as e:
        logging.error(f"A diagnostic command failed: {e}")

def main():
    """
    Main function to orchestrate the server setup process.
    """
    logging.info("SANYA-VPN Server Setup for Tailscale -- STARTING")

    # 1. Check for sudo
    check_sudo()

    # 2. Check for Linux
    if platform.system() != "Linux":
        logging.error("This script is designed for Linux (Raspberry Pi OS).")
        sys.exit(1)

    # 3. Install Tailscale if not present
    if not is_tailscale_installed():
        install_tailscale()

    # 4. Ensure Tailscale service is running
    ensure_tailscale_running()

    # 5. Log into Tailscale
    login_to_tailscale()

    # 6. Enable IP Forwarding
    enable_ip_forwarding()

    # 7. Advertise as exit node (redundant but safe)
    advertise_exit_node()

    # 8. Run diagnostics
    run_diagnostics()

    logging.info("SANYA-VPN Server Setup -- COMPLETE")
    logging.info("The device is now configured as a Tailscale exit node.")

if __name__ == "__main__":
    main()
