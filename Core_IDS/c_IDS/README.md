# Intrusion Detection System (IDS) with Electron GUI

This project provides a simple Intrusion Detection System (IDS) written in C, coupled with a modern graphical user interface (GUI) built using Electron, HTML, CSS, and JavaScript. The IDS monitors network traffic for suspicious patterns based on predefined and custom threat signatures, logging alerts and displaying them in real-time within the GUI.
Features

    Network Packet Sniffing: Utilizes libpcap to capture and analyze live network traffic.

    Threat Detection: Identifies various network attacks (e.g., SYN Flood, Port Scans, ICMP Flood, XMAS/FIN/NULL Scans, RST Flood) based on a set of customizable signatures.

    Configurable Parameters: Easily adjust detection thresholds, logging options, and network interface via config.json.

    Customizable Threat Signatures: Upload new or modified JSON-based threat signatures directly through the GUI without recompiling the C backend.

    Live Alerts Log: View detected alerts streamed in real-time directly in the GUI's "Live Logs" tab.

    IDS Status Monitoring: Check the current operational status of the C backend from the GUI.

    Modern User Interface: An intuitive and responsive Electron-based GUI for easy interaction.

    Extensible C Backend: Designed with a modular structure to allow for easy addition of new detection logic.

## Requirements

To run this IDS, you will need:
For the C Backend (ids_final)

    C Compiler: GCC (GNU Compiler Collection) is recommended.

    libpcap-dev (or equivalent): This library is essential for packet capture.

        Debian/Ubuntu: sudo apt-get install libpcap-dev

        Fedora/RHEL: sudo dnf install libpcap-devel

        macOS (with Homebrew): brew install libpcap

    pthread: POSIX threads library (usually available by default on Linux/macOS).

## For the Electron GUI

    Node.js & npm: Download and install from nodejs.org. npm (Node Package Manager) is included with Node.js.

## Setup Instructions

Follow these steps to set up and run the IDS:

    Navigate to the Project Directory:
    Open your terminal and change to the project's root directory where ids_final.c, main.js, package.json, etc., are located.

    cd path/to/your/IDS/project

    Configure the IDS (Optional):
    Edit config.json to customize parameters like the network interface ("interface": "eth0"), alert log file, and various attack detection rates.

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

    Important: Ensure the "interface" matches your active network interface (e.g., eth0, wlan0, en0, Wi-Fi). You can find this using ifconfig or ip addr.

    Compile the C Backend:
    Compile the ids_final.c and cJSON.c source files using GCC.

    gcc ids_final.c cJSON.c -o ids_final -lpcap -pthread

    This command compiles the C code and links the necessary libraries, creating an executable file named ids_final.

    Install Electron GUI Dependencies:
    Install the Node.js dependencies required for the Electron application.

    npm install

## Running the IDS

To run the IDS, you need to start both the C backend and the Electron GUI.

    Start the C Backend:
    Open a terminal and run the compiled C executable. This often requires superuser privileges to access network interfaces for packet sniffing.

    sudo ./ids_final

    You should see output similar to:

    Configuration loaded. GUI Listen Port: 8888
    Alerts will be logged to ids_alerts.log
    GUI communication server listening on port 8888
    Sniffing on interface eth0...

    Start the Electron GUI:
    Open a separate terminal in the same project directory and start the Electron application.

    npm start

    This will launch the IDS GUI window.

## Using the IDS GUI

Once the GUI is running, navigate through the tabs:

    Home: Provides a dashboard overview (currently placeholder for packet/alert counts).

    Live Logs: This is where live network alerts will appear.

        Click "Start Live Log" to begin streaming alerts from the C backend to the GUI.

        Click "Stop Live Log" to halt the streaming.

    Signatures: Upload custom threat signatures.

        Paste your JSON array of signature objects into the textarea.

        Click "Upload Signatures".

        Refer to signatures.json for the expected format.

    Status: Displays the current status of the IDS C backend.

        Click "Refresh Status" to get the latest update.

## Uploading Custom Threat Signatures

The signatures.json file provides examples of the expected format. Each signature object should have:

    "name": A unique name for the signature.

    "description": A brief explanation of the threat.

    "severity": (e.g., "HIGH", "MEDIUM", "LOW")

    "condition": A string representing the condition that triggers the alert (e.g., "syn_flood_attack", "xmas_scan").

Example signatures.json structure:

        [
            {
                "name": "SYN Flood Attack",
                "description": "High rate of SYN packets...",
                "severity": "HIGH",
                "condition": "syn_flood_attack"
            },
            {
                "name": "XMAS Scan Detected",
                "description": "TCP packet with FIN, URG, and PUSH flags set...",
                "severity": "MEDIUM",
                "condition": "xmas_scan"
            }
        ]

To upload:

    Go to the "Signatures" tab in the GUI.

    Paste your complete JSON array of signatures into the large text area.

    Click the "Upload Signatures" button.
    The status will update to indicate success or failure.

## Troubleshooting

If you encounter issues, check the following:

    C Backend Terminal Output: Watch the terminal where sudo ./ids_final is running for any error messages, especially related to socket connections, send operations, or pcap errors.

    Electron App Console (Main Process): In the Electron app menu, go to View > Toggle Developer Tools (this is usually for the main process). Check the "Console" tab for errors like Error with live log connection or parsing issues.

    Electron App Console (Renderer Process): Press Ctrl+Shift+I (Windows/Linux) or Cmd+Option+I (macOS) in the GUI window. Check the "Console" tab for errors in renderer.js or if logs are being received by the renderer but not displayed (e.g., due to CSS).

    ids_alerts.log: Verify if alerts are being written to this file by the C backend. If they are, but not appearing in the GUI, the issue is with the live log streaming. If not, the issue is with the IDS detection logic or the traffic itself.

    Network Interface: Ensure the interface specified in config.json is correct and active.

    Firewall: Temporarily disable your system's firewall to rule out connection blocking.
