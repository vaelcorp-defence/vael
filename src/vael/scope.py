import ipaddress
import socket
from urllib.parse import urlparse
from typing import List, Tuple

class ScopeError(Exception):
    """Raised when a target violates scope rules."""
    pass

class ScopeManager:
    def __init__(self, authorized_targets: List[str]):
        self.authorized_hosts = set()
        self._parse_targets(authorized_targets)

    def _parse_targets(self, targets: List[str]):
        for target in targets:
            parsed = urlparse(target)
            if not parsed.scheme or not parsed.netloc:
                raise ScopeError(f"Invalid target format: {target}. Must include http:// or https://")
            self.authorized_hosts.add(parsed.netloc.split(':')[0].lower())

    def is_authorized(self, url: str) -> bool:
        """
        Checks if a URL is safe to request.
        Rejects internal IPs, localhost, and unauthorized domains.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            return False
            
        hostname = hostname.lower()

        # 1. Check for localhost/loopback references
        if hostname in ("localhost", "127.0.0.1", "::1"):
            # Allow it ONLY if the user explicitly targeted localhost (e.g., local lab testing)
            if hostname in self.authorized_hosts:
                return True
            return False

        # 2. Resolve the hostname to check for internal IPs (SSRF protection)
        try:
            resolved_ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(resolved_ip)
            
            # Block private ranges (e.g., 192.168.x.x, 10.x.x.x), loopback, and link-local
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                # Allow if explicitly authorized (e.g., a specific internal IP is targeted)
                if hostname in self.authorized_hosts or resolved_ip in self.authorized_hosts:
                    pass
                else:
                    raise ScopeError(f"SSRF Protection: {hostname} resolves to a private/internal IP ({resolved_ip})")
        except socket.gaierror:
            # If DNS fails, we can't verify it, so we reject it for safety
            return False

        # 3. Check if the hostname is in our authorized list
        if hostname not in self.authorized_hosts:
            raise ScopeError(f"Unauthorized host: {hostname}. Not in scope.")

        return True

    def validate_redirect(self, original_url: str, redirect_url: str) -> str:
        """
        Validates that a redirect isn't trying to send us to an unauthorized domain.
        """
        orig_host = urlparse(original_url).hostname
        redir_host = urlparse(redirect_url).hostname
        
        if orig_host != redir_host:
            if not self.is_authorized(redirect_url):
                raise ScopeError(f"Redirect blocked: {original_url} tried to redirect to unauthorized {redirect_url}")
        
        return redirect_url
