import argparse
import time
import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import yaml
import os
import signal
import sys

# Custom formatter for cleaner output
class CustomFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.WARNING:
            # For alerts, only show the message without timestamp and level
            return record.getMessage()
        elif record.levelno == logging.INFO:
            # For info messages, include timestamp
            return f"{self.formatTime(record)} - {record.getMessage()}"
        else:
            # For debug and other messages, use full format
            return f"{self.formatTime(record)} - {record.levelname} - {record.getMessage()}"

# Set up logging with custom formatter
logger = logging.getLogger("IDS")
logger.setLevel(logging.INFO)

# File handler with full format
file_handler = logging.FileHandler("ids.log")
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# Console handler with clean format
console_handler = logging.StreamHandler()
console_handler.setFormatter(CustomFormatter('%(asctime)s'))
logger.addHandler(console_handler)

class IDSRule:
    def __init__(self, rule_dict):
        self.name = rule_dict.get('name', 'Unnamed Rule')
        self.description = rule_dict.get('description', '')
        self.severity = rule_dict.get('severity', 'low')
        self.protocol = rule_dict.get('protocol', 'any')
        self.src_ip = rule_dict.get('src_ip', 'any')
        self.src_port = rule_dict.get('src_port', 'any')
        self.dst_ip = rule_dict.get('dst_ip', 'any')
        self.dst_port = rule_dict.get('dst_port', 'any')
        self.content = rule_dict.get('content', [])
        self.icmp_type = rule_dict.get('icmp_type')
        
    def __str__(self):
        return f"Rule: {self.name} ({self.severity}) - {self.description}"

class IDSEngine:
    def __init__(self, rules_file, interface=None, debug=False, quiet=False):
        self.rules = []
        self.interface = interface
        self.debug = debug
        self.quiet = quiet
        self.load_rules(rules_file)
        self.alerts = 0
        self.packets_analyzed = 0
        
        # Port-protocol mappings for common services
        self.port_to_service = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
        }
        
    def load_rules(self, rules_file):
        """Load rules from YAML file"""
        try:
            with open(rules_file, 'r') as f:
                rules_dict = yaml.safe_load(f)
                
            for rule_dict in rules_dict['rules']:
                self.rules.append(IDSRule(rule_dict))
                
            logger.info(f"IDS loaded {len(self.rules)} rules successfully")
            
            if self.debug:
                for i, rule in enumerate(self.rules):
                    logger.debug(f"Rule {i+1}: {rule.name} - Protocol: {rule.protocol}, Src IP: {rule.src_ip}, Dst IP: {rule.dst_ip}")
                
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            sys.exit(1)
    
    def match_ip(self, rule_ip, packet_ip):
        """Match IP address against rule"""
        if rule_ip == 'any':
            return True
        return rule_ip == packet_ip
    
    def match_port(self, rule_port, packet_port):
        """Match port against rule"""
        if rule_port == 'any':
            return True
        return str(rule_port) == str(packet_port)
    
    def match_protocol(self, rule_protocol, packet):
        """Match protocol against rule"""
        if rule_protocol == 'any':
            return True
        if rule_protocol == 'tcp' and TCP in packet:
            return True
        if rule_protocol == 'udp' and UDP in packet:
            return True
        if rule_protocol == 'icmp' and ICMP in packet:
            return True
        return False
    
    def match_icmp_type(self, rule_icmp_type, packet):
        """Match ICMP type if specified"""
        if rule_icmp_type is None:
            return True
        if ICMP in packet:
            return int(packet[ICMP].type) == int(rule_icmp_type)
        return False
    
    def get_payload(self, packet):
        """Extract payload from packet"""
        payload = ""
        
        try:
            if Raw in packet:
                payload = str(packet[Raw].load)
            else:
                # Try to get payload from different layers
                payload = str(bytes(packet.payload))
        except:
            pass
            
        return payload
    
    def match_content(self, rule_contents, packet):
        """Match packet payload against rule content patterns"""
        if not rule_contents:
            return True
            
        payload = self.get_payload(packet)
        if not payload:
            return False
            
        for content in rule_contents:
            if content.lower() in payload.lower():
                return True
        return False
    
    def detect_service_connection(self, packet):
        """Detect new connection attempts to common services"""
        if not TCP in packet:
            return False
            
        # Check if this is a SYN packet (connection establishment)
        if packet[TCP].flags & 0x02:  # SYN flag
            dst_port = packet[TCP].dport
            
            # Check if it's connecting to a known service port
            if dst_port in self.port_to_service:
                return self.port_to_service[dst_port]
                
        return False
    
    def check_packet(self, packet):
        """Check packet against all rules"""
        self.packets_analyzed += 1
        
        if IP not in packet:
            return
        
        # Log packet info only in debug mode
        if self.debug:
            if self.packets_analyzed % 1000 == 0:
                logger.debug(f"Processed {self.packets_analyzed} packets")
                
            if ICMP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                icmp_type = packet[ICMP].type
                logger.debug(f"ICMP packet: {src} -> {dst}, Type: {icmp_type}")
            elif TCP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                
                # Enhanced connection logging for common services
                service = self.detect_service_connection(packet)
                if service:
                    logger.debug(f"New {service} connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    
                    # For specific monitored hosts, always alert on new connections
                    if dst_ip == "10.10.114.132" and not self.quiet:
                        service_name = service.upper()
                        alert_msg = f"⚠️  ALERT: {service_name} Connection Attempt [MEDIUM] - {src_ip} → {dst_ip} (Port {dst_port})"
                        logger.warning(alert_msg)
        
        # Try each rule
        for rule in self.rules:
            # Skip protocol mismatch
            if not self.match_protocol(rule.protocol, packet):
                continue
                
            # Check IP addresses
            if not self.match_ip(rule.src_ip, packet[IP].src):
                continue
                
            if not self.match_ip(rule.dst_ip, packet[IP].dst):
                continue
            
            # Check ports if TCP or UDP
            if TCP in packet:
                if not self.match_port(rule.src_port, packet[TCP].sport):
                    continue
                if not self.match_port(rule.dst_port, packet[TCP].dport):
                    continue
            elif UDP in packet:
                if not self.match_port(rule.src_port, packet[UDP].sport):
                    continue
                if not self.match_port(rule.dst_port, packet[UDP].dport):
                    continue
            
            # Check ICMP type if applicable
            if ICMP in packet:
                if not self.match_icmp_type(rule.icmp_type, packet):
                    continue
            
            # Check content patterns
            if not self.match_content(rule.content, packet):
                continue
            
            # All conditions met, generate alert
            self.generate_alert(rule, packet)
    
    def generate_alert(self, rule, packet):
        """Generate alert for matched rule"""
        self.alerts += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        protocol = "UNKNOWN"
        src_port = "N/A"
        dst_port = "N/A"
        
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Identify common services
            if dst_port in self.port_to_service:
                protocol = self.port_to_service[dst_port]
                
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            # Identify common services
            if dst_port in self.port_to_service:
                protocol = self.port_to_service[dst_port]
                
        elif ICMP in packet:
            protocol = "ICMP"
            icmp_type = packet[ICMP].type
            if icmp_type == 8:
                protocol = "ICMP (Ping)"
            elif icmp_type == 0:
                protocol = "ICMP (Ping Reply)"
        
        # Simple alert message
        alert_msg = f"⚠️  ALERT: {rule.name} [{rule.severity.upper()}] - {src_ip} → {dst_ip}"
        
        if protocol.startswith("TCP") or protocol.startswith("UDP"):
            alert_msg += f" (Port {dst_port})"
        else:
            alert_msg += f" ({protocol})"
        
        logger.warning(alert_msg)
        
        # Detailed info goes to debug log
        if self.debug:
            details = (
                f"Details: {rule.description}\n"
                f"Protocol: {protocol}\n"
                f"Source: {src_ip}:{src_port}\n"
                f"Destination: {dst_ip}:{dst_port}"
            )
            logger.debug(details)
    
    def start_capture(self, count=0):
        """Start capturing packets"""
        logger.info(f"IDS monitoring started on interface {self.interface or 'default'}")
        
        try:
            # Register signal handler for clean exit
            signal.signal(signal.SIGINT, self.signal_handler)
            
            # Start packet capture
            sniff(iface=self.interface, prn=self.check_packet, store=0, count=count)
        except Exception as e:
            logger.error(f"Error: {e}")
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C to exit gracefully"""
        logger.info(f"IDS monitoring stopped. Stats: {self.packets_analyzed} packets analyzed, {self.alerts} alerts generated.")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-r', '--rules', required=True, help='Rules file (YAML)')
    parser.add_argument('-c', '--count', type=int, default=0, 
                        help='Number of packets to capture (0 for infinite)')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Enable debug logging')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Suppress automatic alerts for monitored IP')
    
    args = parser.parse_args()
    
    # Set logger level based on debug flag
    if args.debug:
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
    
    # Initialize and start IDS engine
    ids = IDSEngine(args.rules, args.interface, args.debug, args.quiet)
    ids.start_capture(args.count)

if __name__ == "__main__":
    main()
