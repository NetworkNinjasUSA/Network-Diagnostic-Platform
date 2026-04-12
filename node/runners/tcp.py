"""TCP and SSL diagnostic runners."""
import socket
import ssl
import time
from typing import Optional, Dict, Any
from datetime import datetime


class TCPCheckRunner:
    """Check TCP port connectivity."""
    
    # Common service ports
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP Submission",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP Alt",
        8443: "HTTPS Alt",
        27017: "MongoDB"
    }
    
    def run(self, config: dict) -> dict:
        """Check if TCP port is open and measure connection time."""
        host = config.get("host")
        port = config.get("port")
        timeout = config.get("timeout", 5.0)
        
        if not host:
            return {"error": "Host is required"}
        if not port:
            return {"error": "Port is required"}
        
        # Resolve hostname first
        resolved_ip = None
        try:
            resolved_ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            return {
                "host": host,
                "port": port,
                "open": False,
                "resolved_ip": None,
                "connection_time_ms": None,
                "service": self.COMMON_PORTS.get(port, "Unknown"),
                "error": f"DNS resolution failed: {e}"
            }
        
        # Attempt TCP connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        start_time = time.time()
        
        try:
            result = sock.connect_ex((resolved_ip, port))
            connection_time = (time.time() - start_time) * 1000
            
            if result == 0:
                # Connection successful
                # Try to get banner if available
                banner = None
                try:
                    sock.settimeout(1)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    pass
                
                return {
                    "host": host,
                    "port": port,
                    "open": True,
                    "resolved_ip": resolved_ip,
                    "connection_time_ms": round(connection_time, 2),
                    "service": self.COMMON_PORTS.get(port, "Unknown"),
                    "banner": banner,
                    "error": None
                }
            else:
                return {
                    "host": host,
                    "port": port,
                    "open": False,
                    "resolved_ip": resolved_ip,
                    "connection_time_ms": round(connection_time, 2),
                    "service": self.COMMON_PORTS.get(port, "Unknown"),
                    "error": f"Connection refused (error code: {result})"
                }
                
        except socket.timeout:
            return {
                "host": host,
                "port": port,
                "open": False,
                "resolved_ip": resolved_ip,
                "connection_time_ms": timeout * 1000,
                "service": self.COMMON_PORTS.get(port, "Unknown"),
                "error": "Connection timed out"
            }
        except Exception as e:
            return {
                "host": host,
                "port": port,
                "open": False,
                "resolved_ip": resolved_ip,
                "connection_time_ms": None,
                "service": self.COMMON_PORTS.get(port, "Unknown"),
                "error": str(e)
            }
        finally:
            sock.close()
    
    def scan_common_ports(self, config: dict) -> dict:
        """Scan common ports on a host."""
        host = config.get("host")
        timeout = config.get("timeout", 2.0)
        ports = config.get("ports", list(self.COMMON_PORTS.keys()))
        
        if not host:
            return {"error": "Host is required"}
        
        results = []
        open_ports = []
        
        for port in ports:
            result = self.run({"host": host, "port": port, "timeout": timeout})
            results.append({
                "port": port,
                "service": self.COMMON_PORTS.get(port, "Unknown"),
                "open": result.get("open", False),
                "connection_time_ms": result.get("connection_time_ms")
            })
            if result.get("open"):
                open_ports.append(port)
        
        return {
            "host": host,
            "ports_scanned": len(ports),
            "open_ports": open_ports,
            "results": results
        }


class SSLCheckRunner:
    """Check SSL/TLS certificate and configuration."""
    
    def run(self, config: dict) -> dict:
        """Check SSL certificate for a host."""
        host = config.get("host")
        port = config.get("port", 443)
        timeout = config.get("timeout", 10.0)
        
        if not host:
            return {"error": "Host is required"}
        
        # Create SSL context
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                start_time = time.time()
                
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    connection_time = (time.time() - start_time) * 1000
                    
                    # Get certificate
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Parse certificate details
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    
                    # Parse dates
                    not_before = cert.get('notBefore')
                    not_after = cert.get('notAfter')
                    
                    # Calculate days until expiry
                    days_until_expiry = None
                    if not_after:
                        try:
                            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_until_expiry = (expiry_date - datetime.utcnow()).days
                        except:
                            pass
                    
                    # Get SANs
                    sans = []
                    for san_type, san_value in cert.get('subjectAltName', []):
                        sans.append({"type": san_type, "value": san_value})
                    
                    return {
                        "host": host,
                        "port": port,
                        "valid": True,
                        "connection_time_ms": round(connection_time, 2),
                        "tls_version": version,
                        "cipher": {
                            "name": cipher[0] if cipher else None,
                            "version": cipher[1] if cipher else None,
                            "bits": cipher[2] if cipher else None
                        },
                        "certificate": {
                            "subject": subject,
                            "issuer": issuer,
                            "common_name": subject.get('commonName'),
                            "organization": subject.get('organizationName'),
                            "not_before": not_before,
                            "not_after": not_after,
                            "days_until_expiry": days_until_expiry,
                            "serial_number": cert.get('serialNumber'),
                            "subject_alt_names": sans
                        },
                        "error": None
                    }
                    
        except ssl.SSLCertVerificationError as e:
            return {
                "host": host,
                "port": port,
                "valid": False,
                "connection_time_ms": None,
                "tls_version": None,
                "cipher": None,
                "certificate": None,
                "error": f"Certificate verification failed: {e}"
            }
        except ssl.SSLError as e:
            return {
                "host": host,
                "port": port,
                "valid": False,
                "connection_time_ms": None,
                "tls_version": None,
                "cipher": None,
                "certificate": None,
                "error": f"SSL error: {e}"
            }
        except socket.timeout:
            return {
                "host": host,
                "port": port,
                "valid": False,
                "connection_time_ms": None,
                "tls_version": None,
                "cipher": None,
                "certificate": None,
                "error": "Connection timed out"
            }
        except Exception as e:
            return {
                "host": host,
                "port": port,
                "valid": False,
                "connection_time_ms": None,
                "tls_version": None,
                "cipher": None,
                "certificate": None,
                "error": str(e)
            }
