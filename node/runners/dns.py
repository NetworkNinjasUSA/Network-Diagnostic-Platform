"""DNS diagnostic runner."""
import socket
import time
from typing import Optional, List, Dict, Any


class DNSRunner:
    """Run DNS diagnostics."""
    
    # Public DNS servers for propagation checks
    PUBLIC_DNS_SERVERS = {
        "Google": "8.8.8.8",
        "Google Secondary": "8.8.4.4",
        "Cloudflare": "1.1.1.1",
        "Cloudflare Secondary": "1.0.0.1",
        "OpenDNS": "208.67.222.222",
        "Quad9": "9.9.9.9",
        "Level3": "4.2.2.1",
    }
    
    def lookup(self, config: dict) -> dict:
        """Perform DNS lookup."""
        query = config.get("query")
        record_type = config.get("record_type", "A")
        server = config.get("server")
        timeout = config.get("timeout", 5.0)
        
        if not query:
            return {"error": "Query is required"}
        
        try:
            import dns.resolver
            import dns.reversename
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            
            if server:
                resolver.nameservers = [server]
            
            server_used = server or resolver.nameservers[0]
            
            start_time = time.time()
            
            try:
                answers = resolver.resolve(query, record_type)
                response_time = (time.time() - start_time) * 1000
                
                results = []
                for rdata in answers:
                    result = {
                        "value": str(rdata),
                        "ttl": answers.ttl
                    }
                    
                    # Add type-specific fields
                    if record_type == "MX":
                        result["preference"] = rdata.preference
                        result["exchange"] = str(rdata.exchange)
                    elif record_type == "SOA":
                        result["mname"] = str(rdata.mname)
                        result["rname"] = str(rdata.rname)
                        result["serial"] = rdata.serial
                        result["refresh"] = rdata.refresh
                        result["retry"] = rdata.retry
                        result["expire"] = rdata.expire
                        result["minimum"] = rdata.minimum
                    
                    results.append(result)
                
                return {
                    "query": query,
                    "record_type": record_type,
                    "server": server_used,
                    "answers": results,
                    "response_time_ms": round(response_time, 2),
                    "error": None
                }
                
            except dns.resolver.NXDOMAIN:
                return {
                    "query": query,
                    "record_type": record_type,
                    "server": server_used,
                    "answers": [],
                    "response_time_ms": (time.time() - start_time) * 1000,
                    "error": "Domain does not exist (NXDOMAIN)"
                }
            except dns.resolver.NoAnswer:
                return {
                    "query": query,
                    "record_type": record_type,
                    "server": server_used,
                    "answers": [],
                    "response_time_ms": (time.time() - start_time) * 1000,
                    "error": f"No {record_type} records found"
                }
            except dns.resolver.Timeout:
                return {
                    "query": query,
                    "record_type": record_type,
                    "server": server_used,
                    "answers": [],
                    "response_time_ms": timeout * 1000,
                    "error": "DNS query timed out"
                }
                
        except ImportError:
            # Fallback to basic socket resolution
            return self._basic_lookup(query, record_type, server, timeout)
    
    def _basic_lookup(self, query: str, record_type: str, server: Optional[str], 
                      timeout: float) -> dict:
        """Basic DNS lookup using socket (limited functionality)."""
        if record_type not in ["A", "AAAA"]:
            return {
                "query": query,
                "record_type": record_type,
                "server": server or "system",
                "answers": [],
                "response_time_ms": 0,
                "error": f"Basic lookup only supports A/AAAA records. Install dnspython for full support."
            }
        
        socket.setdefaulttimeout(timeout)
        start_time = time.time()
        
        try:
            if record_type == "A":
                family = socket.AF_INET
            else:
                family = socket.AF_INET6
            
            results = socket.getaddrinfo(query, None, family)
            response_time = (time.time() - start_time) * 1000
            
            answers = []
            seen = set()
            for result in results:
                ip = result[4][0]
                if ip not in seen:
                    seen.add(ip)
                    answers.append({"value": ip, "ttl": "unknown"})
            
            return {
                "query": query,
                "record_type": record_type,
                "server": server or "system",
                "answers": answers,
                "response_time_ms": round(response_time, 2),
                "error": None
            }
            
        except socket.gaierror as e:
            return {
                "query": query,
                "record_type": record_type,
                "server": server or "system",
                "answers": [],
                "response_time_ms": (time.time() - start_time) * 1000,
                "error": str(e)
            }
    
    def reverse_lookup(self, config: dict) -> dict:
        """Perform reverse DNS lookup (PTR record)."""
        ip = config.get("ip")
        timeout = config.get("timeout", 5.0)
        
        if not ip:
            return {"error": "IP address is required"}
        
        try:
            import dns.resolver
            import dns.reversename
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            
            start_time = time.time()
            
            try:
                rev_name = dns.reversename.from_address(ip)
                answers = resolver.resolve(rev_name, "PTR")
                response_time = (time.time() - start_time) * 1000
                
                results = [{"value": str(rdata), "ttl": answers.ttl} for rdata in answers]
                
                return {
                    "ip": ip,
                    "ptr_name": str(rev_name),
                    "answers": results,
                    "response_time_ms": round(response_time, 2),
                    "error": None
                }
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return {
                    "ip": ip,
                    "ptr_name": str(rev_name),
                    "answers": [],
                    "response_time_ms": (time.time() - start_time) * 1000,
                    "error": "No PTR record found"
                }
                
        except ImportError:
            # Fallback to socket
            socket.setdefaulttimeout(timeout)
            start_time = time.time()
            
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                response_time = (time.time() - start_time) * 1000
                
                return {
                    "ip": ip,
                    "ptr_name": None,
                    "answers": [{"value": hostname, "ttl": "unknown"}],
                    "response_time_ms": round(response_time, 2),
                    "error": None
                }
            except socket.herror as e:
                return {
                    "ip": ip,
                    "ptr_name": None,
                    "answers": [],
                    "response_time_ms": (time.time() - start_time) * 1000,
                    "error": str(e)
                }
    
    def propagation_check(self, config: dict) -> dict:
        """Check DNS propagation across multiple public DNS servers."""
        query = config.get("query")
        record_type = config.get("record_type", "A")
        timeout = config.get("timeout", 5.0)
        
        if not query:
            return {"error": "Query is required"}
        
        results = {}
        
        for name, server in self.PUBLIC_DNS_SERVERS.items():
            result = self.lookup({
                "query": query,
                "record_type": record_type,
                "server": server,
                "timeout": timeout
            })
            
            results[name] = {
                "server": server,
                "answers": result.get("answers", []),
                "response_time_ms": result.get("response_time_ms"),
                "error": result.get("error")
            }
        
        # Check consistency
        all_values = []
        for name, result in results.items():
            if result["answers"]:
                values = sorted([a["value"] for a in result["answers"]])
                all_values.append(tuple(values))
        
        consistent = len(set(all_values)) <= 1 if all_values else False
        
        return {
            "query": query,
            "record_type": record_type,
            "results": results,
            "consistent": consistent,
            "unique_responses": len(set(all_values))
        }
