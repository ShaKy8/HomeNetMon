"""
Secure command executor to prevent command injection vulnerabilities.
All system commands should go through this module for validation and safe execution.
"""

import logging
import subprocess
import shlex
import re
import ipaddress
from typing import List, Optional, Dict, Any, Tuple
from enum import Enum

logger = logging.getLogger(__name__)

class CommandType(Enum):
    """Allowed command types."""
    PING = "ping"
    FPING = "fping"
    NMAP = "nmap"
    ARP = "arp"
    TRACEROUTE = "traceroute"
    DIG = "dig"
    NSLOOKUP = "nslookup"
    MTR = "mtr"
    SPEEDTEST = "speedtest-cli"

class SecureExecutor:
    """Secure command executor with validation and sanitization."""
    
    # Whitelisted commands and their allowed arguments
    COMMAND_WHITELIST = {
        CommandType.PING: {
            'command': 'ping',
            'allowed_args': ['-c', '-W', '-i', '-s', '-q'],
            'requires_target': True,
            'validate_target': 'ip_or_hostname'
        },
        CommandType.FPING: {
            'command': 'fping',
            'allowed_args': ['-g', '-a', '-q', '-c', '-t', '-r'],
            'requires_target': True,
            'validate_target': 'ip_or_network'
        },
        CommandType.NMAP: {
            'command': 'nmap',
            'allowed_args': ['-sn', '-sP', '-sV', '-O', '-A', '-p', '--open'],
            'requires_target': True,
            'validate_target': 'ip_or_network'
        },
        CommandType.ARP: {
            'command': 'arp',
            'allowed_args': ['-a', '-n', '-d'],
            'requires_target': False,
            'validate_target': None
        },
        CommandType.TRACEROUTE: {
            'command': 'traceroute',
            'allowed_args': ['-m', '-w', '-q', '-n'],
            'requires_target': True,
            'validate_target': 'ip_or_hostname'
        },
        CommandType.DIG: {
            'command': 'dig',
            'allowed_args': ['+short', '+trace', '@'],
            'requires_target': True,
            'validate_target': 'hostname'
        },
        CommandType.NSLOOKUP: {
            'command': 'nslookup',
            'allowed_args': [],
            'requires_target': True,
            'validate_target': 'hostname'
        },
        CommandType.MTR: {
            'command': 'mtr',
            'allowed_args': ['-r', '-c', '-n', '--json', '--csv'],
            'requires_target': True,
            'validate_target': 'ip_or_hostname'
        },
        CommandType.SPEEDTEST: {
            'command': 'speedtest-cli',
            'allowed_args': ['--json', '--csv', '--simple', '--server'],
            'requires_target': False,
            'validate_target': None
        }
    }
    
    def __init__(self, timeout: int = 30, max_output_size: int = 1024 * 1024):
        """Initialize secure executor.
        
        Args:
            timeout: Maximum execution time in seconds
            max_output_size: Maximum output size in bytes
        """
        self.timeout = timeout
        self.max_output_size = max_output_size
        
    def execute(self, command_type: CommandType, target: Optional[str] = None,
                args: Optional[List[str]] = None, timeout: Optional[int] = None) -> Tuple[bool, str, str]:
        """Execute a command securely.
        
        Args:
            command_type: Type of command to execute
            target: Target IP, hostname, or network (if required)
            args: Additional arguments for the command
            timeout: Command timeout (overrides default)
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            # Validate command type
            if command_type not in self.COMMAND_WHITELIST:
                logger.error(f"Command type not whitelisted: {command_type}")
                return False, "", "Command not allowed"
                
            cmd_config = self.COMMAND_WHITELIST[command_type]
            
            # Validate target if required
            if cmd_config['requires_target']:
                if not target:
                    return False, "", "Target required for this command"
                    
                if not self._validate_target(target, cmd_config['validate_target']):
                    return False, "", f"Invalid target: {target}"
                    
            # Build command
            cmd = [cmd_config['command']]
            
            # Add validated arguments
            if args:
                validated_args = self._validate_arguments(args, cmd_config['allowed_args'])
                if validated_args is None:
                    return False, "", "Invalid arguments provided"
                cmd.extend(validated_args)
                
            # Add target if required
            if target and cmd_config['requires_target']:
                cmd.append(target)
                
            # Execute command
            logger.debug(f"Executing secure command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
                check=False,
                shell=False
            )
            
            # Truncate output if too large
            stdout = result.stdout
            stderr = result.stderr
            
            if len(stdout) > self.max_output_size:
                stdout = stdout[:self.max_output_size] + "\n[Output truncated]"
            if len(stderr) > self.max_output_size:
                stderr = stderr[:self.max_output_size] + "\n[Error output truncated]"
                
            success = result.returncode == 0
            return success, stdout, stderr
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out: {command_type}")
            return False, "", "Command timed out"
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return False, "", str(e)
            
    def _validate_target(self, target: str, validation_type: str) -> bool:
        """Validate target based on type.
        
        Args:
            target: Target to validate
            validation_type: Type of validation to perform
            
        Returns:
            True if valid, False otherwise
        """
        if validation_type == 'ip':
            return self._is_valid_ip(target)
        elif validation_type == 'hostname':
            return self._is_valid_hostname(target)
        elif validation_type == 'ip_or_hostname':
            return self._is_valid_ip(target) or self._is_valid_hostname(target)
        elif validation_type == 'ip_or_network':
            return self._is_valid_ip(target) or self._is_valid_network(target)
        elif validation_type == 'network':
            return self._is_valid_network(target)
        else:
            logger.error(f"Unknown validation type: {validation_type}")
            return False
            
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
            
    def _is_valid_network(self, network: str) -> bool:
        """Check if string is a valid network in CIDR notation."""
        try:
            ipaddress.ip_network(network, strict=False)
            return True
        except ValueError:
            return False
            
    def _is_valid_hostname(self, hostname: str) -> bool:
        """Check if string is a valid hostname."""
        if len(hostname) > 255:
            return False
            
        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]
            
        # Hostname regex pattern
        pattern = r"^(?!-)(?:[a-zA-Z0-9-]{1,63}(?<!-)\.)*[a-zA-Z0-9-]{1,63}(?<!-)$"
        return bool(re.match(pattern, hostname))
        
    def _validate_arguments(self, args: List[str], allowed_args: List[str]) -> Optional[List[str]]:
        """Validate command arguments against whitelist.
        
        Args:
            args: Arguments to validate
            allowed_args: List of allowed argument patterns
            
        Returns:
            Validated arguments or None if invalid
        """
        validated = []
        
        i = 0
        while i < len(args):
            arg = args[i]
            
            # Check if argument is allowed
            allowed = False
            for allowed_arg in allowed_args:
                if arg.startswith(allowed_arg):
                    allowed = True
                    validated.append(arg)
                    
                    # Check if this argument expects a value
                    if arg in allowed_args and i + 1 < len(args):
                        # Validate the value (basic sanitization)
                        value = args[i + 1]
                        if not value.startswith('-') and self._is_safe_value(value):
                            validated.append(value)
                            i += 1
                    break
                    
            if not allowed:
                logger.warning(f"Argument not allowed: {arg}")
                return None
                
            i += 1
            
        return validated
        
    def _is_safe_value(self, value: str) -> bool:
        """Check if a value is safe (no command injection attempts)."""
        # Reject values with shell metacharacters
        dangerous_chars = ['|', ';', '&', '$', '`', '(', ')', '<', '>', '\n', '\r', '\\']
        
        for char in dangerous_chars:
            if char in value:
                logger.warning(f"Dangerous character detected in value: {value}")
                return False
                
        # Reject values that look like command substitution
        if '$(' in value or '`' in value:
            logger.warning(f"Command substitution attempt detected: {value}")
            return False
            
        # Reject values with null bytes
        if '\x00' in value:
            logger.warning(f"Null byte detected in value: {value}")
            return False
            
        return True
        
    def ping(self, target: str, count: int = 1, timeout: int = 1) -> Tuple[bool, float]:
        """Execute a secure ping command.
        
        Args:
            target: IP address or hostname to ping
            count: Number of pings to send
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (success, average_response_time_ms)
        """
        success, stdout, stderr = self.execute(
            CommandType.PING,
            target=target,
            args=['-c', str(count), '-W', str(timeout)]
        )
        
        if not success:
            return False, 0.0
            
        # Parse average response time from output
        avg_time = 0.0
        for line in stdout.split('\n'):
            if 'avg' in line or 'average' in line:
                # Extract average time (format varies by OS)
                match = re.search(r'[\d.]+/[\d.]+/([\d.]+)', line)
                if match:
                    avg_time = float(match.group(1))
                    break
                    
        return True, avg_time
        
    def scan_network(self, network: str) -> List[str]:
        """Execute a secure network scan.
        
        Args:
            network: Network to scan in CIDR notation
            
        Returns:
            List of discovered IP addresses
        """
        success, stdout, stderr = self.execute(
            CommandType.FPING,
            target=network,
            args=['-g', '-a', '-q']
        )
        
        if not success:
            logger.warning(f"Network scan failed: {stderr}")
            return []
            
        # Parse IP addresses from output
        ips = []
        for line in stdout.split('\n'):
            line = line.strip()
            if self._is_valid_ip(line):
                ips.append(line)
                
        return ips
        
    def get_arp_table(self) -> List[Dict[str, str]]:
        """Get ARP table entries securely.
        
        Returns:
            List of ARP entries with IP and MAC addresses
        """
        success, stdout, stderr = self.execute(
            CommandType.ARP,
            args=['-a']
        )
        
        if not success:
            logger.warning(f"Failed to get ARP table: {stderr}")
            return []
            
        # Parse ARP entries
        entries = []
        for line in stdout.split('\n'):
            # Match IP and MAC address patterns
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
            
            if ip_match and mac_match:
                entries.append({
                    'ip': ip_match.group(0),
                    'mac': mac_match.group(0).upper()
                })
                
        return entries


# Global secure executor instance
secure_executor = SecureExecutor()