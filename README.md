# Network Intrusion Detection Systems (IDS) Project

This repository contains two distinct Intrusion Detection System (IDS) implementations:

    A C-based IDS backend with an Electron-based Graphical User Interface (GUI).

    A standalone Python-based IDS.

Both systems are designed to monitor network traffic for suspicious activities, log alerts, and provide insights into potential threats.
Project Overview

This project showcases two different approaches to building an IDS:

    C IDS with Electron GUI: A high-performance, low-level IDS written in C that leverages libpcap for direct network packet capture. It communicates with a modern desktop GUI built with Electron, allowing users to monitor live alerts, manage threat signatures, and check IDS status through an intuitive interface. This setup focuses on performance and a rich user experience.

    Python IDS: A more accessible and extensible IDS implemented purely in Python using Scapy for packet handling and scikit-learn for machine learning-driven anomaly detection. This version is ideal for prototyping, research, and environments where Python's ecosystem is preferred.

## Important Note: These are two separate IDS implementations. The Electron GUI is designed to interact specifically with the C IDS backend. The Python IDS runs as a standalone command-line application.
Features
Shared IDS Capabilities (Conceptual)

    Network Packet Sniffing: Both IDSs capture live network traffic.

    Threat Detection: Identify suspicious patterns.

    Logging: Record detected alerts.

## C IDS Specific Features (with Electron GUI)

    High Performance: C-based backend for efficient packet processing.

    Configurable Parameters: Adjustable detection thresholds, logging options, and network interface via config.json.

    Customizable Threat Signatures: Upload JSON-based threat signatures directly through the GUI.

    Live Alerts Log in GUI: View detected alerts streamed in real-time.

    IDS Status Monitoring: Check the current operational status of the C backend from the GUI.

    Modern User Interface: An intuitive and responsive Electron-based GUI.

## Python IDS Specific Features

    Ease of Use: Written in Python, leveraging a rich ecosystem of libraries.

    Traffic Analysis: Maintains flow-level statistics (packet count, byte count, duration).

    Feature Extraction: Extracts features like packet size, rates, TCP flags, and window size.

    Signature-Based Detection: Predefined rules (as Python lambda functions) for known attack patterns.

    Anomaly-Based Detection: Uses scikit-learn's Isolation Forest model to detect unusual traffic.

## Requirements
For the C IDS Backend (ids_final)

    Operating System: Linux / macOS (due to libpcap and POSIX threads usage).

    C Compiler: GCC (GNU Compiler Collection) is recommended.

    libpcap-dev (or equivalent): Essential for network packet sniffing.

        Debian/Ubuntu: sudo apt-get install libpcap-dev

        Fedora/RHEL: sudo dnf install libpcap-devel

        macOS (with Homebrew): brew install libpcap

    pthread: POSIX threads library (usually available by default on Linux/macOS).

For the Electron GUI (to run with C IDS)

    Node.js & npm: Download and install from nodejs.org. npm is included with Node.js.

For the Python IDS

    Python 3.x

    pip (Python package installer)

    Required Python Libraries:

        scapy

        scikit-learn

        numpy

## Setup Instructions
Setting up the C IDS Backend and Electron GUI

    Navigate to the Project Directory:
    Open your terminal and change to the project's root directory where ids_final.c, main.js, package.json, etc., are located.

    cd path/to/your/IDS/project

    Configure the C IDS (Optional but Recommended):
    Edit config.json to customize parameters. Crucially, ensure the "interface" matches your active network interface (e.g., eth0, wlan0, en0, Wi-Fi). You can find this using ifconfig or ip addr (Linux/macOS) or ipconfig (Windows).

    {
        "interface": "eth0",
        "alert_log_file": "ids_alerts.log",
        "cooldown_period_seconds": 10,
        "syn_flood_packet_rate": 80,
        "port_scan_packet_rate": 50,
        "udp_flood_packet_rate": 90,
        "icmp_flood_packet_rate": 70,
        "xmas_fin_null_scan_packet_rate": 40,
        "large_packet_bytes": 2000,
        "invalid_tcp_flags_count": 7,
        "gui_listen_port": 8888
    }

    Compile the C Backend:
    Compile ids_final.c and cJSON.c using GCC.

    gcc ids_final.c cJSON.c -o ids_final -lpcap -pthread

    Install Electron GUI Dependencies:
    Install the Node.js dependencies for the Electron application.

    npm install

## Setting up the Python IDS

    Save the Python Code:
    Save the Python code (provided in previous turns) to a file named python_ids.py (or any other .py extension).

    Install Python Dependencies:
    Open your terminal and install the required Python libraries:

    pip install scapy scikit-learn numpy

    Configure the Network Interface in Python Code:
    Open python_ids.py and modify the interface variable within the main() function to match your system's network interface.

    # Inside the main() function in python_ids.py
    if sys.platform.startswith('linux'):
        interface = "wlan0" # <-- ADJUST THIS TO YOUR ACTUAL LINUX INTERFACE (e.g., "eth0")
    elif sys.platform == 'darwin':
        interface = "en0" # <-- ADJUST THIS TO YOUR ACTUAL macOS INTERFACE
    elif sys.platform == 'win32':
        interface = None # On Windows, you might need to specify the exact name or GUID.
                         # If None, Scapy might attempt auto-detection, but explicit is better.
        logging.warning("On Windows, you might need to specify the exact interface name (e.g., 'Ethernet 2') or GUID if automatic detection fails.")
    else:
        interface = None

    packet_capture.start_capture(interface=interface)

## Running the IDSs
Running the C IDS with Electron GUI

To run this IDS, you must start both the C backend and the Electron GUI.

    Start the C Backend:
    Open a terminal and run the compiled C executable. This typically requires superuser privileges for network sniffing.

    sudo ./ids_final

    You should see initial configuration and sniffing messages in this terminal.

    Start the Electron GUI:
    Open a separate terminal in the same project directory and start the Electron application.

    npm start

    This will launch the IDS GUI window.

## Running the Python IDS

To run the Python IDS, execute the Python script with root/administrator privileges directly from the command line.

sudo python3 python_ids.py

(On Windows, open Command Prompt or PowerShell as Administrator and run python python_ids.py)

You will see all logging and alert output directly in the terminal where you run this command.
Using the C IDS GUI

Once the GUI is running (after starting the C backend and npm start):

    Home: Provides a dashboard overview (currently placeholder widgets).

    Live Logs: This is the primary view for real-time alerts.

        Click "Start Live Log" to begin streaming alerts from the C backend.

        Click "Stop Live Log" to halt the stream.

    Signatures: Upload custom threat signatures.

        Paste your JSON array of signature objects into the textarea.

        Click "Upload Signatures".

        Refer to signatures.json for the expected format.

    Status: Displays the current operational status of the C IDS backend.

        Click "Refresh Status" to get the latest update.

## Customizing Threat Signatures
For the C IDS

Threat signatures are JSON objects. You can modify the signatures.json file directly or upload new signatures via the GUI. Each signature should have:

    "name": A unique name.

    "description": An explanation of the threat.

    "severity": E.g., "HIGH", "MEDIUM", "LOW".

    "condition": A string that corresponds to a condition evaluated in ids_final.c (e.g., "syn_flood_attack", "xmas_scan").

## Example signatures.json structure:

        [
            {
                "name": "SYN Flood Attack",
                "description": "High rate of SYN packets from a single source to a single destination, indicating a SYN flood.",
                "severity": "HIGH",
                "condition": "syn_flood_attack"
            },
            {
                "name": "TCP Port Scan (Low Ports)",
                "description": "Multiple connection attempts to various low-numbered TCP ports (0-1023) on a single host.",
                "severity": "MEDIUM",
                "condition": "tcp_port_scan_low_ports"
            }
        ]

For the Python IDS

Signature rules are defined directly within the DetectionEngine class's load_signature_rules method in the python_ids.py file. Each rule is a dictionary with a description and a condition (a Python lambda function that takes features as input and returns True if the condition is met).

To add or modify rules, you'll need to edit the python_ids.py file directly and rerun the script.
Testing and Triggering Alerts

To see either IDS in action, you need to generate network traffic that matches your defined signatures or exhibits anomalous behavior.

    General Traffic: Simply browse the internet, download files, or stream videos.

    Trigger a SYN Flood (requires hping3 or similar):

    sudo hping3 -S -p 80 --flood <TARGET_IP_ADDRESS>

    (Replace <TARGET_IP_ADDRESS> with an IP address on your network, or 127.0.0.1 for localhost if sniffing on lo or lo0).
    You should see "SYN Flood" alerts.

    Trigger a Port Scan (requires nmap or similar):

    nmap -sS -p 1-1000 <TARGET_IP_ADDRESS>

    This will generate many small packets to different ports, potentially triggering port scan rules.

## Logging
C IDS

    Alerts are logged to the file specified in config.json (default: ids_alerts.log).

    Alerts are also streamed in real-time to the Electron GUI's "Live Logs" tab.

    Console output provides status and debugging information.

Python IDS

    All alerts and informational/debug messages are logged directly to the terminal where the script is running.

    Critical alerts are also written to ids_alerts.log (configurable in AlertSystem).

## Shutting Down
C IDS with Electron GUI

    C Backend: Press Ctrl+C in the terminal where sudo ./ids_final is running.

    Electron GUI: Simply close the application window.

Python IDS

    Press Ctrl+C in the terminal where sudo python3 python_ids.py is running. The script will perform a graceful shutdown.
