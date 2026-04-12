"""MTR (My Traceroute) diagnostic runner."""
import subprocess
import json
import re
import socket
from typing import List, Optional
from dataclasses import dataclass
import platform


@dataclass
class MTRHop:
    hop: int
    ip: Optional[str]
    hostname: Optional[str]
    loss_percent: float
    sent: int
    received: int
    rtt_min: Optional[float]
    rtt_avg: Optional[float]
    rtt_max: Optional[float]
    rtt_jitter: Optional[float]


class MTRRunner:
    """Run MTR diagnostics with statistics."""
    
    def run(self, config: dict) -> dict:
        """Execute MTR to target."""
        target = config.get("target")
        protocol = config.get("protocol", "icmp")
        count = config.get("count", 10)
        max_hops = config.get("max_hops", 30)
        timeout = config.get("timeout", 2.0)
        
        if not target:
            return {"error": "Target is required"}
        
        # Resolve target IP
        resolved_ip = None
        try:
            resolved_ip = socket.gethostbyname(target)
        except socket.gaierror:
            pass
        
        system = platform.system().lower()
        
        # Check if mtr is available
        if system == "windows":
            # Windows doesn't have native mtr, fall back to simulated version
            return self._simulate_mtr(target, resolved_ip, count, max_hops, timeout)
        
        try:
            # Try mtr with JSON output first
            cmd = self._build_mtr_cmd(target, protocol, count, max_hops)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=count * max_hops * timeout + 30
            )
            
            if result.returncode == 0:
                return self._parse_mtr_json(result.stdout, target, resolved_ip, count)
            else:
                # Fall back to report mode
                return self._run_mtr_report(target, resolved_ip, protocol, count, max_hops, timeout)
                
        except FileNotFoundError:
            # mtr not installed, simulate with repeated traceroutes
            return self._simulate_mtr(target, resolved_ip, count, max_hops, timeout)
        except subprocess.TimeoutExpired:
            return {
                "target": target,
                "resolved_ip": resolved_ip,
                "hops": [],
                "packet_count": count,
                "error": "MTR timed out"
            }
        except Exception as e:
            return {
                "target": target,
                "resolved_ip": resolved_ip,
                "hops": [],
                "packet_count": count,
                "error": str(e)
            }
    
    def _build_mtr_cmd(self, target: str, protocol: str, count: int, max_hops: int) -> list:
        """Build mtr command."""
        cmd = ["mtr", "--json", "-c", str(count), "-m", str(max_hops)]
        
        if protocol == "tcp":
            cmd.append("--tcp")
        elif protocol == "udp":
            cmd.append("--udp")
        # ICMP is default
        
        cmd.append(target)
        return cmd
    
    def _parse_mtr_json(self, output: str, target: str, resolved_ip: str, count: int) -> dict:
        """Parse mtr JSON output."""
        try:
            data = json.loads(output)
            hops = []
            
            for hub in data.get("report", {}).get("hubs", []):
                hop = MTRHop(
                    hop=hub.get("count", 0),
                    ip=hub.get("host") if hub.get("host") != "???" else None,
                    hostname=hub.get("host") if hub.get("host") != "???" else None,
                    loss_percent=hub.get("Loss%", 0),
                    sent=hub.get("Snt", 0),
                    received=hub.get("Snt", 0) - int(hub.get("Snt", 0) * hub.get("Loss%", 0) / 100),
                    rtt_min=hub.get("Best"),
                    rtt_avg=hub.get("Avg"),
                    rtt_max=hub.get("Wrst"),
                    rtt_jitter=hub.get("StDev")
                )
                hops.append(vars(hop))
            
            return {
                "target": target,
                "resolved_ip": resolved_ip,
                "hops": hops,
                "packet_count": count,
                "error": None
            }
        except json.JSONDecodeError:
            return {
                "target": target,
                "resolved_ip": resolved_ip,
                "hops": [],
                "packet_count": count,
                "error": "Failed to parse MTR output"
            }
    
    def _run_mtr_report(self, target: str, resolved_ip: str, protocol: str, 
                        count: int, max_hops: int, timeout: float) -> dict:
        """Run mtr in report mode and parse text output."""
        cmd = ["mtr", "--report", "--report-wide", "-c", str(count), "-m", str(max_hops)]
        
        if protocol == "tcp":
            cmd.append("--tcp")
        elif protocol == "udp":
            cmd.append("--udp")
        
        cmd.append(target)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=count * timeout + 30)
        
        return self._parse_mtr_report(result.stdout, target, resolved_ip, count)
    
    def _parse_mtr_report(self, output: str, target: str, resolved_ip: str, count: int) -> dict:
        """Parse mtr report text output."""
        hops = []
        lines = output.strip().split('\n')
        
        for line in lines:
            # Skip header lines
            if 'HOST' in line or 'Start' in line or not line.strip():
                continue
            
            # Parse line: "1.|-- gateway  0.0%  10  0.5  0.6  0.5  0.8  0.1"
            match = re.match(
                r'\s*(\d+)\.\|--\s+(\S+)\s+(\d+\.?\d*)%\s+(\d+)\s+(\d+\.?\d*)\s+(\d+\.?\d*)\s+(\d+\.?\d*)\s+(\d+\.?\d*)\s+(\d+\.?\d*)',
                line
            )
            
            if match:
                hop_num, host, loss, sent, last, avg, best, worst, stdev = match.groups()
                
                hop = MTRHop(
                    hop=int(hop_num),
                    ip=host if host != "???" else None,
                    hostname=host if host != "???" else None,
                    loss_percent=float(loss),
                    sent=int(sent),
                    received=int(int(sent) * (100 - float(loss)) / 100),
                    rtt_min=float(best) if best else None,
                    rtt_avg=float(avg) if avg else None,
                    rtt_max=float(worst) if worst else None,
                    rtt_jitter=float(stdev) if stdev else None
                )
                hops.append(vars(hop))
        
        return {
            "target": target,
            "resolved_ip": resolved_ip,
            "hops": hops,
            "packet_count": count,
            "error": None
        }
    
    def _simulate_mtr(self, target: str, resolved_ip: str, count: int, 
                      max_hops: int, timeout: float) -> dict:
        """Simulate MTR using repeated pings when mtr is not available."""
        import time
        
        # First, get the route using traceroute
        from .traceroute import TracerouteRunner
        tr = TracerouteRunner()
        tr_result = tr.run({
            "target": target,
            "max_hops": max_hops,
            "timeout": timeout,
            "resolve_hostnames": True
        })
        
        if tr_result.get("error"):
            return {
                "target": target,
                "resolved_ip": resolved_ip,
                "hops": [],
                "packet_count": count,
                "error": f"Route discovery failed: {tr_result['error']}"
            }
        
        # Now ping each hop multiple times
        hops = []
        for tr_hop in tr_result.get("hops", []):
            hop_ip = tr_hop.get("ip")
            
            if not hop_ip:
                hops.append({
                    "hop": tr_hop.get("hop"),
                    "ip": None,
                    "hostname": None,
                    "loss_percent": 100.0,
                    "sent": count,
                    "received": 0,
                    "rtt_min": None,
                    "rtt_avg": None,
                    "rtt_max": None,
                    "rtt_jitter": None
                })
                continue
            
            # Ping this hop
            rtts = []
            received = 0
            
            for _ in range(min(count, 5)):  # Limit to 5 for simulation
                try:
                    start = time.time()
                    # Simple TCP connect as ping substitute
                    import socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((hop_ip, 80))
                    elapsed = (time.time() - start) * 1000
                    sock.close()
                    
                    if result == 0 or elapsed < timeout * 1000:
                        rtts.append(elapsed)
                        received += 1
                except:
                    pass
            
            sent = min(count, 5)
            loss = ((sent - received) / sent) * 100 if sent > 0 else 100
            
            hops.append({
                "hop": tr_hop.get("hop"),
                "ip": hop_ip,
                "hostname": tr_hop.get("hostname"),
                "loss_percent": loss,
                "sent": sent,
                "received": received,
                "rtt_min": min(rtts) if rtts else None,
                "rtt_avg": sum(rtts) / len(rtts) if rtts else None,
                "rtt_max": max(rtts) if rtts else None,
                "rtt_jitter": self._calc_jitter(rtts) if len(rtts) > 1 else None
            })
        
        return {
            "target": target,
            "resolved_ip": resolved_ip,
            "hops": hops,
            "packet_count": count,
            "error": None,
            "note": "Simulated MTR (mtr not available)"
        }
    
    def _calc_jitter(self, rtts: list) -> float:
        """Calculate jitter from RTT values."""
        if len(rtts) < 2:
            return 0.0
        diffs = [abs(rtts[i] - rtts[i-1]) for i in range(1, len(rtts))]
        return sum(diffs) / len(diffs)
