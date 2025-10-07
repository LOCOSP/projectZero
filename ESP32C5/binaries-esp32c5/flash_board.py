import time
import sys
import subprocess
import os

def ensure_packages():
    required_pip = []
    # Check pyserial
    try:
        import serial.tools.list_ports
    except ImportError:
        required_pip.append("pyserial")
    # Check esptool
    try:
        import esptool
    except ImportError:
        required_pip.append("esptool")
    if required_pip:
        print(f"\033[93mInstalling missing packages: {', '.join(required_pip)}\033[0m")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + required_pip)
        print("\033[92mPackages installed. Restarting script...\033[0m")
        os.execv(sys.executable, [sys.executable] + sys.argv)

ensure_packages()

import serial.tools.list_ports

# ANSI escape codes for colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

REQUIRED_FILES = [
    "bootloader.bin",
    "partition-table.bin",
    "projectZero.bin"
]

def check_files():
    missing = [f for f in REQUIRED_FILES if not os.path.exists(f)]
    if missing:
        print(f"{RED}Missing files: {', '.join(missing)}{RESET}")
        sys.exit(1)
    else:
        print(f"{GREEN}All required files found.{RESET}")

def list_ports():
    return set([port.device for port in serial.tools.list_ports.comports()])

def wait_for_new_port(before):
    print(f"{CYAN}Please hold Boot button and connect the LabC5 board via USB.{RESET}")
    spinner = ['|', '/', '-', '\\']
    print(f"{YELLOW}Waiting for new serial port...{RESET}")
    for i in range(40):  # 20s max
        after = list_ports()
        new_ports = after - before
        sys.stdout.write(f"\r{spinner[i % len(spinner)]} ")
        sys.stdout.flush()
        if new_ports:
            sys.stdout.write("\r")  # Clear spinner
            return new_ports.pop()
        time.sleep(0.5)
    print(f"\n{RED}No new serial port detected!{RESET}")
    sys.exit(1)

def main():
    check_files()
    before_ports = list_ports()
    port = wait_for_new_port(before_ports)
    print(f"{GREEN}Detected new serial port: {port}{RESET}")

    cmd = [
        sys.executable, "-m", "esptool",
        "-p", port,
        "-b", "460800",
        "--before", "default_reset",
        "--after", "hard_reset",
        "--chip", "esp32c5",
        "write_flash",
        "--flash_mode", "dio",
        "--flash_freq", "80m",
        "--flash_size", "detect",
        "0x2000", "bootloader.bin",
        "0x8000", "partition-table.bin",
        "0x10000", "projectZero.bin"
    ]
    print(f"{CYAN}Flashing command:{RESET} {' '.join(cmd)}")
    subprocess.run(cmd)

if __name__ == "__main__":
    main()