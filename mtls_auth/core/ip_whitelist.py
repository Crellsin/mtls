"""
IP Whitelist Validator for mTLS authentication.

Validates client IP addresses against IPv4 and IPv6 whitelists at the network layer.
Supports both individual IPs and CIDR ranges.
"""

import ipaddress
import logging
from typing import List, Optional, Union, Set
from pathlib import Path

logger = logging.getLogger(__name__)

class IPWhitelistValidator:
    """Validates IP addresses against configured whitelists."""
    
    def __init__(self, ipv4_whitelist: Optional[List[str]] = None, 
                 ipv6_whitelist: Optional[List[str]] = None,
                 validate_ipv4: bool = True,
                 validate_ipv6: bool = True):
        """
        Initialize IP whitelist validator.
        
        Args:
            ipv4_whitelist: List of IPv4 addresses/CIDR ranges to allow
            ipv6_whitelist: List of IPv6 addresses/CIDR ranges to allow
            validate_ipv4: Whether to validate IPv4 addresses (default: True)
            validate_ipv6: Whether to validate IPv6 addresses (default: True)
        """
        self.validate_ipv4 = validate_ipv4
        self.validate_ipv6 = validate_ipv6
        
        # Parse IPv4 whitelist
        self.ipv4_networks: List[ipaddress.IPv4Network] = []
        if ipv4_whitelist and validate_ipv4:
            self.ipv4_networks = self._parse_networks(ipv4_whitelist, ipaddress.IPv4Network)
            
        # Parse IPv6 whitelist
        self.ipv6_networks: List[ipaddress.IPv6Network] = []
        if ipv6_whitelist and validate_ipv6:
            self.ipv6_networks = self._parse_networks(ipv6_whitelist, ipaddress.IPv6Network)
            
        logger.info(f"IP whitelist initialized: {len(self.ipv4_networks)} IPv4 networks, "
                   f"{len(self.ipv6_networks)} IPv6 networks")
    
    def _parse_networks(self, network_list: List[str], network_class) -> List:
        """Parse list of network strings into network objects."""
        networks = []
        for net_str in network_list:
            try:
                # Check if it's a single IP or a network
                if '/' in net_str:
                    network = network_class(net_str)
                else:
                    # Single IP, convert to a /32 for IPv4 or /128 for IPv6
                    ip = ipaddress.ip_address(net_str)
                    if isinstance(ip, ipaddress.IPv4Address):
                        network = ipaddress.IPv4Network(f"{net_str}/32", strict=False)
                    else:
                        network = ipaddress.IPv6Network(f"{net_str}/128", strict=False)
                networks.append(network)
                logger.debug(f"Added network to whitelist: {network}")
            except ValueError as e:
                logger.warning(f"Invalid network format '{net_str}': {e}")
        return networks
    
    def is_allowed(self, ip_address: str) -> bool:
        """
        Check if an IP address is allowed by the whitelist.
        
        Args:
            ip_address: IP address string (IPv4 or IPv6)
            
        Returns:
            True if allowed, False otherwise.
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check IPv4
            if isinstance(ip, ipaddress.IPv4Address):
                if not self.validate_ipv4:
                    return True  # Skip validation if disabled
                for network in self.ipv4_networks:
                    if ip in network:
                        logger.debug(f"IPv4 address {ip_address} allowed by network {network}")
                        return True
                logger.warning(f"IPv4 address {ip_address} not in whitelist")
                return False
            
            # Check IPv6
            elif isinstance(ip, ipaddress.IPv6Address):
                if not self.validate_ipv6:
                    return True  # Skip validation if disabled
                for network in self.ipv6_networks:
                    if ip in network:
                        logger.debug(f"IPv6 address {ip_address} allowed by network {network}")
                        return True
                logger.warning(f"IPv6 address {ip_address} not in whitelist")
                return False
            
        except ValueError as e:
            logger.error(f"Invalid IP address format '{ip_address}': {e}")
            return False
    
    def validate_connection(self, sock) -> bool:
        """
        Validate the remote peer's IP address from a socket.
        
        Args:
            sock: Socket object
            
        Returns:
            True if allowed, False otherwise.
        """
        try:
            # Get the remote address from the socket
            peer_addr = sock.getpeername()
            if isinstance(peer_addr, tuple):
                ip = peer_addr[0]
                return self.is_allowed(ip)
            else:
                logger.error(f"Unexpected peer address format: {peer_addr}")
                return False
        except (OSError, AttributeError) as e:
            logger.error(f"Failed to get peer address: {e}")
            return False
    
    def add_ipv4_network(self, network_str: str) -> None:
        """Add an IPv4 network to the whitelist."""
        try:
            network = ipaddress.IPv4Network(network_str)
            self.ipv4_networks.append(network)
            logger.info(f"Added IPv4 network to whitelist: {network}")
        except ValueError as e:
            logger.error(f"Invalid IPv4 network '{network_str}': {e}")
            raise
    
    def add_ipv6_network(self, network_str: str) -> None:
        """Add an IPv6 network to the whitelist."""
        try:
            network = ipaddress.IPv6Network(network_str)
            self.ipv6_networks.append(network)
            logger.info(f"Added IPv6 network to whitelist: {network}")
        except ValueError as e:
            logger.error(f"Invalid IPv6 network '{network_str}': {e}")
            raise
    
    def remove_ipv4_network(self, network_str: str) -> bool:
        """Remove an IPv4 network from the whitelist."""
        try:
            network = ipaddress.IPv4Network(network_str)
            for i, net in enumerate(self.ipv4_networks):
                if net == network:
                    self.ipv4_networks.pop(i)
                    logger.info(f"Removed IPv4 network from whitelist: {network}")
                    return True
            logger.warning(f"IPv4 network not found in whitelist: {network}")
            return False
        except ValueError as e:
            logger.error(f"Invalid IPv4 network '{network_str}': {e}")
            return False
    
    def remove_ipv6_network(self, network_str: str) -> bool:
        """Remove an IPv6 network from the whitelist."""
        try:
            network = ipaddress.IPv6Network(network_str)
            for i, net in enumerate(self.ipv6_networks):
                if net == network:
                    self.ipv6_networks.pop(i)
                    logger.info(f"Removed IPv6 network from whitelist: {network}")
                    return True
            logger.warning(f"IPv6 network not found in whitelist: {network}")
            return False
        except ValueError as e:
            logger.error(f"Invalid IPv6 network '{network_str}': {e}")
            return False
    
    def get_ipv4_whitelist(self) -> List[str]:
        """Get current IPv4 whitelist as strings."""
        return [str(network) for network in self.ipv4_networks]
    
    def get_ipv6_whitelist(self) -> List[str]:
        """Get current IPv6 whitelist as strings."""
        return [str(network) for network in self.ipv6_networks]
    
    @classmethod
    def from_yaml_file(cls, yaml_path: Union[str, Path]) -> 'IPWhitelistValidator':
        """
        Create an IPWhitelistValidator from a YAML configuration file.
        
        Args:
            yaml_path: Path to YAML configuration file
            
        Returns:
            Configured IPWhitelistValidator instance.
        """
        try:
            import yaml
            yaml_path = Path(yaml_path)
            
            if not yaml_path.exists():
                raise FileNotFoundError(f"YAML file not found: {yaml_path}")
            
            with open(yaml_path, 'r') as f:
                config = yaml.safe_load(f)
            
            ipv4_whitelist = config.get('ipv4_whitelist', [])
            ipv6_whitelist = config.get('ipv6_whitelist', [])
            validation_settings = config.get('validation', {})
            
            validate_ipv4 = validation_settings.get('validate_ipv4', True)
            validate_ipv6 = validation_settings.get('validate_ipv6', True)
            
            logger.info(f"Loaded IP whitelist from {yaml_path}")
            return cls(
                ipv4_whitelist=ipv4_whitelist,
                ipv6_whitelist=ipv6_whitelist,
                validate_ipv4=validate_ipv4,
                validate_ipv6=validate_ipv6
            )
            
        except ImportError:
            logger.error("PyYAML not installed. Install with: pip install pyyaml")
            raise
        except Exception as e:
            logger.error(f"Failed to load YAML configuration: {e}")
            raise
    
    def __str__(self) -> str:
        """String representation of the whitelist."""
        ipv4_count = len(self.ipv4_networks)
        ipv6_count = len(self.ipv6_networks)
        return (f"IPWhitelistValidator(IPv4: {ipv4_count} networks, "
                f"IPv6: {ipv6_count} networks, validate_ipv4={self.validate_ipv4}, "
                f"validate_ipv6={self.validate_ipv6})")
