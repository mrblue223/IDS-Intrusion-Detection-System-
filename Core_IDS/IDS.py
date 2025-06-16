from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue
import time
import logging
import json
from datetime import datetime
from sklearn.ensemble import IsolationForest
import numpy as np
from sklearn.exceptions import NotFittedError
import sys

# Configure basic logging for the entire script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PacketCapture:
    """
    Captures network packets using Scapy and puts them into a queue for processing.
    """
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()
        self.capture_thread = None

    def packet_callback(self, packet):
        """
        Callback function for Scapy's sniff. Filters for IP and TCP packets
        and puts them into the queue.
        """
        if IP in packet and TCP in packet:
            # Added for debugging:
            logging.debug(f"Packet received: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")
            self.packet_queue.put(packet)
        else:
            # Added for debugging:
            logging.debug(f"Non-IP/TCP packet received (ignored): {packet.summary()}")


    def start_capture(self, interface="eth0"):
        """
        Starts sniffing packets on the specified interface in a separate thread.
        Requires root/administrator privileges.
        """
        logging.info(f"Starting packet capture on interface: {interface}")
        def capture_thread_target():
            try:
                sniff(iface=interface,
                      prn=self.packet_callback,
                      store=0,
                      stop_filter=lambda x: self.stop_capture.is_set())
            except PermissionError:
                logging.error("Permission denied. You might need to run this script with root/administrator privileges (e.g., sudo python your_script.py).")
                self.stop_capture.set()
            except Exception as e:
                logging.error(f"Error during packet capture: {e}")
                self.stop_capture.set()

        self.capture_thread = threading.Thread(target=capture_thread_target)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        logging.info("Packet capture thread started.")

    def stop(self):
        """
        Stops the packet capture thread.
        """
        logging.info("Stopping packet capture...")
        self.stop_capture.set()
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
            if self.capture_thread.is_alive():
                logging.warning("Packet capture thread did not terminate gracefully.")
        logging.info("Packet capture stopped.")

class TrafficAnalyzer:
    """
    Analyzes network packets to extract features for detection.
    Maintains flow-level statistics.
    """
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        """
        Analyzes a single packet, updates flow statistics, and extracts features.
        """
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
            current_time = packet.time

            if (ip_src, port_src) < (ip_dst, port_dst):
                flow_key = (ip_src, port_src, ip_dst, port_dst)
            else:
                flow_key = (ip_dst, port_dst, ip_src, port_src)

            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            packet_details = {
                'source_ip': ip_src,
                'destination_ip': ip_dst,
                'source_port': port_src,
                'destination_port': port_dst,
                'protocol': 'TCP',
                'packet_length': len(packet)
            }

            features = self.extract_features(packet, stats)
            return features, packet_details
        return None, None

    def extract_features(self, packet, stats):
        """
        Extracts various features from a packet and its flow statistics.
        Handles division by zero for initial flow duration.
        """
        flow_duration = stats['last_time'] - stats['start_time']
        
        if flow_duration == 0:
            packet_rate = stats['packet_count']
            byte_rate = stats['byte_count']
        else:
            packet_rate = stats['packet_count'] / flow_duration
            byte_rate = stats['byte_count'] / flow_duration

        tcp_flags = packet[TCP].flags if TCP in packet else 0
        window_size = packet[TCP].window if TCP in packet else 0

        return {
            'packet_size': len(packet),
            'flow_duration': flow_duration,
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'tcp_flags': tcp_flags,
            'window_size': window_size
        }

class DetectionEngine:
    """
    Performs signature-based and anomaly-based threat detection.
    """
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.05,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data = []

    def load_signature_rules(self):
        """
        Loads predefined signature rules. These can be expanded significantly.
        """
        logging.info("Loading signature rules.")
        return {
            'syn_flood': {
                'description': 'High rate of SYN packets, indicating a SYN flood attempt.',
                'condition': lambda features: (
                    features['tcp_flags'] == 0x02 and
                    features['packet_rate'] > 50 and
                    features['flow_duration'] > 1
                )
            },
            'port_scan_small_packets': {
                'description': 'Numerous small packets to different ports, typical of a port scan.',
                'condition': lambda features: (
                    features['packet_size'] < 60 and
                    features['packet_rate'] > 30 and
                    features['flow_duration'] > 1
                )
            },
        }

    def train_anomaly_detector(self, normal_traffic_data):
        """
        Trains the Isolation Forest model with 'normal' traffic data.
        'normal_traffic_data' should be a list of feature vectors.
        """
        if not normal_traffic_data:
            logging.warning("No normal traffic data provided for anomaly detector training. Detector will not be trained.")
            return

        logging.info(f"Training anomaly detector with {len(normal_traffic_data)} samples.")
        try:
            self.anomaly_detector.fit(np.array(normal_traffic_data))
            logging.info("Anomaly detector trained successfully.")
        except Exception as e:
            logging.error(f"Error training anomaly detector: {e}")

    def detect_threats(self, features):
        """
        Detects threats using both signature-based and anomaly-based methods.
        Returns a list of detected threats.
        """
        threats = []

        # --- Signature-based detection ---
        # Added for debugging:
        logging.debug(f"Evaluating features for signature detection: {features}")
        for rule_name, rule in self.signature_rules.items():
            try:
                if rule['condition'](features):
                    # Added for debugging:
                    logging.debug(f"Signature rule '{rule_name}' condition met!")
                    threats.append({
                        'type': 'signature',
                        'rule_name': rule_name,
                        'description': rule.get('description', 'No description available.'),
                        'confidence': 1.0
                    })
            except Exception as e:
                logging.error(f"Error evaluating signature rule '{rule_name}': {e}")


        # --- Anomaly-based detection ---
        feature_vector = np.array([[
            features.get('packet_size', 0),
            features.get('packet_rate', 0),
            features.get('byte_rate', 0)
        ]])

        try:
            prediction = self.anomaly_detector.predict(feature_vector)[0]
            decision_score = self.anomaly_detector.decision_function(feature_vector)[0]

            if prediction == -1:
                confidence = max(0.1, min(1.0, 1 - (decision_score / -1.5)))
                threats.append({
                    'type': 'anomaly',
                    'score': decision_score,
                    'confidence': confidence,
                    'details': {
                        'feature_vector': feature_vector.tolist()
                    }
                })
        except NotFittedError:
            logging.warning("Anomaly detector is not trained. Skipping anomaly detection.")
        except Exception as e:
            logging.error(f"Error during anomaly detection: {e}")

        return threats

class AlertSystem:
    """
    Handles logging and potentially other actions for detected threats.
    """
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            logging.info(f"Alert system initialized. Alerts will be logged to {log_file}")

    def generate_alert(self, threat, packet_info):
        """
        Generates and logs an alert based on the detected threat and packet information.
        """
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip', 'N/A'),
            'destination_ip': packet_info.get('destination_ip', 'N/A'),
            'source_port': packet_info.get('source_port', 'N/A'),
            'destination_port': packet_info.get('destination_port', 'N/A'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat
        }

        self.logger.warning(json.dumps(alert))
        logging.warning(f"ALERT: {threat['type']} detected from {packet_info.get('source_ip')} to {packet_info.get('destination_ip')} (Confidence: {alert['confidence']:.2f})")


        if threat['confidence'] > 0.8:
            self.logger.critical(
                f"HIGH CONFIDENCE THREAT: {json.dumps(alert)}"
            )
            logging.critical(f"HIGH CONFIDENCE THREAT DETECTED: {threat['type']} from {packet_info.get('source_ip')} to {packet_info.get('destination_ip')}")


def main():
    """
    Main function to orchestrate the IDS components.
    """
    packet_capture = PacketCapture()
    traffic_analyzer = TrafficAnalyzer()
    detection_engine = DetectionEngine()
    alert_system = AlertSystem()

    # Temporarily set overall logging to DEBUG to see more details
    logging.getLogger().setLevel(logging.DEBUG)

    logging.info("Starting training phase for anomaly detector...")
    dummy_normal_data = [
        [150, 10, 1500],
        [60, 5, 300],
        [200, 12, 2400],
        [70, 7, 490],
        [100, 8, 800],
    ]
    detection_engine.train_anomaly_detector(dummy_normal_data)
    logging.info("Training phase complete.")

    # --- Start Packet Capture ---
    # Set the interface to wlan0 based on user's ifconfig output
    if sys.platform.startswith('linux'):
        interface = "wlan0" # <-- Interface explicitly set to wlan0
    elif sys.platform == 'darwin':
        interface = "en0"
    elif sys.platform == 'win32':
        interface = None
        logging.warning("On Windows, you might need to specify the exact interface name (e.g., 'Ethernet 2') or GUID if automatic detection fails.")
    else:
        interface = None

    if interface:
        logging.info(f"Attempting to capture on interface: {interface}. If this fails, try a different interface name.")
    else:
        logging.info("Attempting to auto-detect capture interface. If this fails, please specify it manually in the code.")


    packet_capture.start_capture(interface=interface)

    try:
        logging.info("IDS is running. Press Ctrl+C to stop.")
        while not packet_capture.stop_capture.is_set():
            try:
                packet = packet_capture.packet_queue.get(timeout=1)

                features, packet_details = traffic_analyzer.analyze_packet(packet)

                if features:
                    # Added for debugging:
                    logging.debug(f"Extracted features: {features} for packet from {packet_details.get('source_ip')}")

                    threats = detection_engine.detect_threats(features)
                    if threats:
                        # Added for debugging:
                        logging.info(f"Threat(s) detected: {threats} for packet from {packet_details.get('source_ip')}:{packet_details.get('source_port')} to {packet_details.get('destination_ip')}:{packet_details.get('destination_port')}")
                        for threat in threats:
                            alert_system.generate_alert(threat, packet_details)

            except queue.Empty:
                pass
            except Exception as e:
                logging.error(f"Error processing packet: {e}")

            time.sleep(0.01)

    except KeyboardInterrupt:
        logging.info("Ctrl+C detected. Shutting down IDS.")
    finally:
        packet_capture.stop()
        logging.info("IDS shutdown complete.")

if __name__ == "__main__":
    main()