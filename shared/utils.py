"""Common utilities shared between node and hub."""
import re
import secrets
import hashlib
from typing import Optional
from datetime import datetime, timedelta


def generate_token(length: int = 32) -> str:
    """Generate a secure random token."""
    return secrets.token_urlsafe(length)


def generate_api_key() -> str:
    """Generate an API key for node authentication."""
    return f"ndp_{secrets.token_urlsafe(32)}"


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash."""
    import bcrypt
    return bcrypt.checkpw(password.encode(), hashed.encode())


def hash_api_key(api_key: str) -> str:
    """Hash an API key for storage."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def validate_hostname(hostname: str) -> bool:
    """Validate a hostname or IP address."""
    # IPv4
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, hostname):
        parts = hostname.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    
    # IPv6 (simplified)
    if ':' in hostname:
        return True  # Basic check, could be more thorough
    
    # Hostname
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(hostname_pattern, hostname)) and len(hostname) <= 253


def validate_filter_expression(filter_expr: str) -> bool:
    """Validate a tcpdump/BPF filter expression for safety."""
    if not filter_expr:
        return True
    
    # Allowed characters and keywords
    allowed_pattern = r'^[a-zA-Z0-9\s\.\:\-\/\(\)and or not host port net src dst tcp udp icmp arp proto len greater less]+$'
    return bool(re.match(allowed_pattern, filter_expr, re.IGNORECASE))


def sanitize_customer_id(customer_id: str) -> str:
    """Sanitize customer ID for safe storage."""
    # Allow alphanumeric, dashes, underscores
    return re.sub(r'[^a-zA-Z0-9\-_]', '', customer_id)[:100]


def format_bytes(bytes_count: int) -> str:
    """Format bytes into human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024
    return f"{bytes_count:.2f} PB"


def format_duration(seconds: float) -> str:
    """Format duration into human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def calculate_jitter(rtts: list) -> Optional[float]:
    """Calculate jitter from a list of RTT values."""
    if len(rtts) < 2:
        return None
    
    differences = [abs(rtts[i] - rtts[i-1]) for i in range(1, len(rtts))]
    return sum(differences) / len(differences)


def get_client_ip(request) -> str:
    """Extract client IP from request, handling proxies."""
    # Check X-Forwarded-For header
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP in the chain
        return forwarded.split(",")[0].strip()
    
    # Check X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Fall back to direct client
    if request.client:
        return request.client.host
    
    return "unknown"


class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}  # ip -> list of timestamps
    
    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed for given identifier."""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=self.window_seconds)
        
        # Clean old entries
        if identifier in self.requests:
            self.requests[identifier] = [
                ts for ts in self.requests[identifier] 
                if ts > window_start
            ]
        else:
            self.requests[identifier] = []
        
        # Check limit
        if len(self.requests[identifier]) >= self.max_requests:
            return False
        
        # Record request
        self.requests[identifier].append(now)
        return True
    
    def reset(self, identifier: str):
        """Reset rate limit for identifier."""
        if identifier in self.requests:
            del self.requests[identifier]
