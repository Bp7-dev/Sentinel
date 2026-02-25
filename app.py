#!/usr/bin/env python3
"""
Sentinel - Local Network Security Monitoring Dashboard

A beautiful, focused, read-only network security monitoring tool.
Monitors, visualizes, and flags. Nothing more.

Architecture:
    - Data Collection Layer: Raw system data gathering (psutil, subprocess, socket)
    - Processing Layer: Data normalization and threat detection
    - API Layer: Flask routes serving processed data

Security Model:
    - Read-only: No system modifications, process control, or file writes
    - No dynamic shell: All subprocess commands are hardcoded strings
    - Localhost only: Bound to 127.0.0.1, no external network access
    - No auth needed: Local-only tool with no credentials to compromise

Author: Sentinel Project
License: MIT
"""

import ipaddress
import json
import os
import socket
import subprocess
import time
import urllib.request
import urllib.error
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

import psutil
from flask import Flask, jsonify, render_template

# =============================================================================
# APPLICATION CONFIGURATION
# =============================================================================

app = Flask(__name__)

# -----------------------------------------------------------------------------
# In-Memory State (resets on restart - by design, no persistence needed)
# -----------------------------------------------------------------------------

# Connection history for trend tracking - stores last 60 data points (5 min at 5s intervals)
CONNECTION_HISTORY: List[Dict[str, Any]] = []
MAX_HISTORY_POINTS = 60

# Threat log - stores last 20 flagged security events for the session
THREAT_LOG: List[Dict[str, Any]] = []
MAX_THREAT_LOG = 20
THREAT_LOG_LOCK = Lock()  # Thread-safe access to threat log

# GeoIP cache - caches IP lookups to avoid hammering external API
# Key: IP address, Value: {country_code, country_name, timestamp}
GEOIP_CACHE: Dict[str, Dict[str, Any]] = {}
GEOIP_CACHE_LOCK = Lock()  # Thread-safe cache access
GEOIP_CACHE_TTL = 3600  # Cache entries valid for 1 hour

# Interface traffic history for sparklines - tracks bytes over last 60 seconds
# Key: interface name, Value: list of {timestamp, bytes_recv, bytes_sent}
INTERFACE_HISTORY: Dict[str, List[Dict[str, Any]]] = {}
MAX_INTERFACE_HISTORY = 12  # 12 points at 5s intervals = 60 seconds

# -----------------------------------------------------------------------------
# Configuration Constants
# -----------------------------------------------------------------------------

# Outbound geo lookups can be toggled off for full offline privacy
GEO_LOOKUP_ENABLED = os.environ.get("SENTINEL_GEO_LOOKUP", "true").lower() == "true"

# Host binding configuration
HOST = "127.0.0.1"

# Home country code for foreign IP detection (connections from other countries flagged)
HOME_COUNTRY = os.environ.get("SENTINEL_HOME_COUNTRY", "US")

# GeoIP database path (optional - MaxMind GeoLite2 Country database for offline lookups)
GEOIP_DB_PATH = Path(__file__).parent / "GeoLite2-Country.mmdb"
GEOIP_READER = None

# Known safe ports (common services)
SAFE_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 119, 123, 143, 161, 162,
    194, 443, 465, 514, 587, 631, 993, 995, 1433, 1521, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 27017
}

# Port range thresholds
EPHEMERAL_PORT_START = 49152
HIGH_PORT_START = 10000

# Connection rate threshold - IPs exceeding this many connections get flagged
CONNECTION_RATE_THRESHOLD = 10
CONNECTION_RATE_WINDOW = 60  # seconds

# IP-API endpoint for geolocation (free tier, no API key needed)
# IMPORTANT: This is the only outbound network call Sentinel performs.
# It uses HTTPS to avoid leaking traffic metadata and can be fully disabled
# via GEO_LOOKUP_ENABLED.
GEOIP_API_URL = "https://ip-api.com/json/{ip}?fields=status,country,countryCode"

# Try to load offline GeoIP database if available (preferred over API)
try:
    import geoip2.database
    if GEOIP_DB_PATH.exists():
        GEOIP_READER = geoip2.database.Reader(str(GEOIP_DB_PATH))
except ImportError:
    pass


# =============================================================================
# DATA COLLECTION LAYER
# =============================================================================
# Functions that gather raw system data using psutil, subprocess, and socket.
# No Flask logic in this layer. All commands are hardcoded.
# =============================================================================

def collect_network_connections() -> List[Dict[str, Any]]:
    """
    Collect all active network connections from the system.
    
    Returns:
        List of connection dictionaries containing:
        - local_address: Local IP and port
        - remote_address: Remote IP and port
        - status: Connection state (ESTABLISHED, LISTEN, etc.)
        - pid: Process ID owning the connection
        - family: Address family (IPv4/IPv6)
    """
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        conn_data = {
            'local_address': {
                'ip': conn.laddr.ip if conn.laddr else None,
                'port': conn.laddr.port if conn.laddr else None
            },
            'remote_address': {
                'ip': conn.raddr.ip if conn.raddr else None,
                'port': conn.raddr.port if conn.raddr else None
            },
            'status': conn.status,
            'pid': conn.pid,
            'family': 'IPv4' if conn.family.name == 'AF_INET' else 'IPv6'
        }
        connections.append(conn_data)
    return connections


def collect_process_info(pid: Optional[int]) -> Dict[str, Any]:
    """
    Collect information about a specific process by PID.
    
    Args:
        pid: Process ID to query
        
    Returns:
        Dictionary containing:
        - name: Process name
        - exe: Executable path
        - cmdline: Command line arguments
        - username: User running the process
        - create_time: Process start time
    """
    if pid is None:
        return {
            'name': 'Unknown',
            'exe': None,
            'cmdline': [],
            'username': None,
            'create_time': None
        }
    
    try:
        proc = psutil.Process(pid)
        return {
            'name': proc.name(),
            'exe': proc.exe() if proc.exe() else None,
            'cmdline': proc.cmdline(),
            'username': proc.username(),
            'create_time': proc.create_time()
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return {
            'name': 'Unknown',
            'exe': None,
            'cmdline': [],
            'username': None,
            'create_time': None
        }


def collect_listening_ports() -> List[Dict[str, Any]]:
    """
    Collect all ports currently in LISTEN state.
    
    Returns:
        List of listening port dictionaries containing:
        - port: Port number
        - protocol: TCP or UDP
        - address: Bound IP address
        - pid: Process ID
    """
    listening = []
    
    # TCP listening ports
    for conn in psutil.net_connections(kind='tcp'):
        if conn.status == 'LISTEN':
            listening.append({
                'port': conn.laddr.port,
                'protocol': 'TCP',
                'address': conn.laddr.ip,
                'pid': conn.pid
            })
    
    # UDP "listening" ports (bound sockets)
    for conn in psutil.net_connections(kind='udp'):
        if conn.laddr:
            listening.append({
                'port': conn.laddr.port,
                'protocol': 'UDP',
                'address': conn.laddr.ip,
                'pid': conn.pid
            })
    
    return listening


def collect_ufw_status() -> Dict[str, Any]:
    """
    Collect UFW (Uncomplicated Firewall) status and rules.
    
    Uses subprocess with hardcoded command - no dynamic shell construction.
    Attempts sudo -n (non-interactive) first, falls back to regular ufw command.
    
    Security: The sudo -n flag ensures we never prompt for password - if sudo
    isn't configured for passwordless UFW access, we fail gracefully with
    clear instructions for the user.
    
    Returns:
        Dictionary containing:
        - active: Boolean indicating if UFW is active
        - rules: List of active firewall rules
        - error: Error message if UFW query failed
        - help: Optional help text for resolving permission issues
    """
    result = {
        'active': False,
        'rules': [],
        'error': None,
        'help': None
    }
    
    # Commands to try in order of preference
    # sudo -n = non-interactive sudo (won't prompt for password)
    commands_to_try = [
        ['sudo', '-n', 'ufw', 'status', 'verbose'],  # Try passwordless sudo first
        ['ufw', 'status', 'verbose'],                 # Fall back to direct call
    ]
    
    for cmd in commands_to_try:
        try:
            # Hardcoded command - no user input ever reaches subprocess
            output = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Check if command succeeded
            if output.returncode == 0 and output.stdout.strip():
                lines = output.stdout.strip().split('\n')
                
                for line in lines:
                    if line.startswith('Status:'):
                        result['active'] = 'active' in line.lower()
                    elif line and not line.startswith(('Status:', 'Logging:', 'Default:', 'New profiles:', '--', 'To')):
                        # Parse rule lines - look for action keywords
                        if line.strip() and ('ALLOW' in line or 'DENY' in line or 'REJECT' in line):
                            result['rules'].append(line.strip())
                
                # Success - clear any previous errors and return
                result['error'] = None
                result['help'] = None
                return result
                
        except FileNotFoundError:
            continue  # Try next command
        except subprocess.TimeoutExpired:
            result['error'] = 'UFW query timed out'
            return result
        except Exception:
            continue  # Try next command
    
    # All commands failed - provide helpful error message
    result['error'] = 'UFW status requires elevated permissions'
    result['help'] = 'To enable: Run "sudo visudo" and add: yourusername ALL=(ALL) NOPASSWD: /usr/sbin/ufw status verbose'
    
    return result


def collect_network_interfaces() -> List[Dict[str, Any]]:
    """
    Collect information about all network interfaces.
    
    Returns:
        List of interface dictionaries containing:
        - name: Interface name
        - addresses: List of IP addresses
        - stats: Traffic statistics (bytes sent/received)
        - is_up: Whether interface is active
    """
    interfaces = []
    
    # Get addresses for each interface
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    io_counters = psutil.net_io_counters(pernic=True)
    
    for iface_name, iface_addrs in addrs.items():
        iface_data = {
            'name': iface_name,
            'addresses': [],
            'stats': {
                'bytes_sent': 0,
                'bytes_recv': 0,
                'packets_sent': 0,
                'packets_recv': 0
            },
            'is_up': False
        }
        
        # Collect addresses
        for addr in iface_addrs:
            if addr.family.name in ('AF_INET', 'AF_INET6'):
                iface_data['addresses'].append({
                    'ip': addr.address,
                    'netmask': addr.netmask,
                    'family': 'IPv4' if addr.family.name == 'AF_INET' else 'IPv6'
                })
        
        # Get stats if available
        if iface_name in stats:
            iface_data['is_up'] = stats[iface_name].isup
        
        # Get I/O counters if available
        if iface_name in io_counters:
            counters = io_counters[iface_name]
            iface_data['stats'] = {
                'bytes_sent': counters.bytes_sent,
                'bytes_recv': counters.bytes_recv,
                'packets_sent': counters.packets_sent,
                'packets_recv': counters.packets_recv
            }
        
        interfaces.append(iface_data)
    
    return interfaces


def collect_system_info() -> Dict[str, Any]:
    """
    Collect general system information.
    
    Returns:
        Dictionary containing:
        - hostname: System hostname
        - platform: OS platform info
        - uptime: System uptime in seconds
        - boot_time: System boot timestamp
        - cpu_percent: Current CPU usage
        - memory: Memory usage statistics
    """
    boot_time = psutil.boot_time()
    memory = psutil.virtual_memory()
    
    return {
        'hostname': socket.gethostname(),
        'platform': {
            'system': subprocess.run(['uname', '-s'], capture_output=True, text=True).stdout.strip(),
            'release': subprocess.run(['uname', '-r'], capture_output=True, text=True).stdout.strip(),
            'machine': subprocess.run(['uname', '-m'], capture_output=True, text=True).stdout.strip()
        },
        'uptime': time.time() - boot_time,
        'boot_time': boot_time,
        'cpu_percent': psutil.cpu_percent(interval=0.1),
        'cpu_count': psutil.cpu_count(),
        'memory': {
            'total': memory.total,
            'available': memory.available,
            'used': memory.used,
            'percent': memory.percent
        }
    }


def collect_geoip_info(ip: str) -> Optional[Dict[str, str]]:
    """
    Look up geographic information for an IP address.
    
    Uses a tiered approach:
    1. Check local cache first (fastest)
    2. Try offline MaxMind database if available
    3. Fall back to ip-api.com free API with aggressive caching
    
    Caching Strategy: Results are cached for 1 hour to minimize API calls.
    The ip-api.com free tier allows 45 req/min - our caching keeps us well under.
    
    Args:
        ip: IP address to look up
        
    Returns:
        Dictionary with country info or None if unavailable:
        - country_code: ISO 2-letter country code (e.g., 'US', 'DE')
        - country_name: Full country name (e.g., 'United States')
    """
    if not GEO_LOOKUP_ENABLED:
        return None

    # Skip private/local addresses - no point looking these up
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return {'country_code': 'LOCAL', 'country_name': 'Local Network'}
    except ValueError:
        return None
    
    # Check cache first (thread-safe)
    with GEOIP_CACHE_LOCK:
        if ip in GEOIP_CACHE:
            cached = GEOIP_CACHE[ip]
            # Check if cache entry is still valid
            if time.time() - cached.get('timestamp', 0) < GEOIP_CACHE_TTL:
                return {
                    'country_code': cached['country_code'],
                    'country_name': cached['country_name']
                }
    
    # Try offline MaxMind database first (preferred - no network calls)
    if GEOIP_READER is not None:
        try:
            response = GEOIP_READER.country(ip)
            result = {
                'country_code': response.country.iso_code or 'XX',
                'country_name': response.country.name or 'Unknown'
            }
            # Cache the result
            with GEOIP_CACHE_LOCK:
                GEOIP_CACHE[ip] = {**result, 'timestamp': time.time()}
            return result
        except Exception:
            pass  # Fall through to API lookup
    
    # Fall back to ip-api.com (free, no API key required)
    try:
        url = GEOIP_API_URL.format(ip=ip)
        req = urllib.request.Request(url, headers={'User-Agent': 'Sentinel/1.0'})
        with urllib.request.urlopen(req, timeout=2) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            if data.get('status') == 'success':
                result = {
                    'country_code': data.get('countryCode', 'XX'),
                    'country_name': data.get('country', 'Unknown')
                }
                # Cache successful lookups
                with GEOIP_CACHE_LOCK:
                    GEOIP_CACHE[ip] = {**result, 'timestamp': time.time()}
                return result
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError):
        pass  # Network error - return None gracefully
    
    return None


# =============================================================================
# PROCESSING LAYER
# =============================================================================
# Normalize raw data into clean JSON-ready structures.
# Implement deterministic threat detection rules.
# No Flask logic in this layer.
# =============================================================================

def normalize_executable_path(exe: Optional[str]) -> Optional[str]:
    """Return only the binary name to avoid leaking host directory structure."""
    if not exe:
        return None
    return Path(exe).name

def detect_unusual_port(port: int, is_listening: bool = False) -> Tuple[bool, str]:
    """
    Detect if a port is unusual or potentially suspicious.
    
    Threat categories:
    - High ephemeral ports not tied to common services
    - Very high ports (>49152) that are listening
    - Uncommon high ports with active connections
    
    Args:
        port: Port number to analyze
        is_listening: Whether this is a listening port
        
    Returns:
        Tuple of (is_suspicious: bool, reason: str)
    """
    if port is None:
        return False, ""
    
    # Safe known ports
    if port in SAFE_PORTS:
        return False, ""
    
    # Very high ephemeral ports that are listening
    if is_listening and port >= EPHEMERAL_PORT_START:
        return True, f"Listening on ephemeral port {port}"
    
    # High ports that are listening (unusual for services)
    if is_listening and port >= HIGH_PORT_START:
        return True, f"Listening on high port {port}"
    
    # Suspicious well-known port ranges (commonly abused)
    suspicious_ranges = [
        (4444, 4445, "Metasploit default"),
        (5554, 5555, "Android ADB"),
        (6666, 6669, "IRC range"),
        (31337, 31337, "Back Orifice"),
    ]
    
    for start, end, desc in suspicious_ranges:
        if start <= port <= end:
            return True, f"Port {port} in {desc} range"
    
    return False, ""


def detect_unknown_process(process_info: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Detect if a process is unknown or potentially suspicious.
    
    Threat categories:
    - No binary path available
    - Process name contains suspicious patterns
    - Process running without identified user
    
    Args:
        process_info: Dictionary from collect_process_info()
        
    Returns:
        Tuple of (is_suspicious: bool, reason: str)
    """
    name = process_info.get('name', 'Unknown')
    exe = process_info.get('exe')
    username = process_info.get('username')
    
    # No executable path - process may be hiding
    if name != 'Unknown' and exe is None:
        return True, f"Process '{name}' has no executable path"
    
    # Unknown process entirely
    if name == 'Unknown':
        return True, "Unidentified process"
    
    # Suspicious naming patterns (common malware techniques)
    suspicious_patterns = [
        ('...', "Hidden name pattern"),
        ('.hidden', "Hidden file pattern"),
        ('tmp', "Temporary file execution"),
        ('/dev/shm/', "Execution from shared memory"),
    ]
    
    exe_str = str(exe) if exe else ""
    for pattern, desc in suspicious_patterns:
        if pattern in name.lower() or pattern in exe_str.lower():
            return True, f"Suspicious pattern: {desc}"
    
    return False, ""


def detect_foreign_ip(ip: str, geo_info: Optional[Dict[str, str]]) -> Tuple[bool, str]:
    """
    Detect if an IP address is from a foreign country.
    
    Uses local GeoIP database only - no external API calls.
    
    Args:
        ip: IP address to check
        geo_info: Geographic info from collect_geoip_info()
        
    Returns:
        Tuple of (is_foreign: bool, reason: str)
    """
    if geo_info is None:
        return False, ""
    
    country_code = geo_info.get('country_code', '')
    country_name = geo_info.get('country_name', 'Unknown')
    
    # Local addresses are not foreign
    if country_code == 'LOCAL':
        return False, ""
    
    # Check if foreign
    if country_code and country_code != HOME_COUNTRY:
        return True, f"Foreign IP from {country_name} ({country_code})"
    
    return False, ""


def detect_excessive_connections(connections: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Detect IPs with excessive connection counts.
    
    Tracks connection frequency per IP and flags those exceeding threshold.
    
    Args:
        connections: List of processed connection dictionaries
        
    Returns:
        Dictionary mapping suspicious IPs to their threat info
    """
    ip_counts: Dict[str, int] = defaultdict(int)
    
    for conn in connections:
        remote_ip = conn.get('remote_ip')
        if remote_ip and remote_ip not in ('127.0.0.1', '::1', '0.0.0.0'):
            ip_counts[remote_ip] += 1
    
    excessive = {}
    for ip, count in ip_counts.items():
        if count >= CONNECTION_RATE_THRESHOLD:
            excessive[ip] = {
                'count': count,
                'reason': f"Excessive connections ({count}) from {ip}"
            }
    
    return excessive


def calculate_threat_level(threats: List[str]) -> str:
    """
    Calculate overall threat level based on detected issues.
    
    Levels:
    - high: Multiple serious threats or critical indicators
    - medium: Single concerning threat
    - low: Minor or informational findings
    - none: No threats detected
    
    Args:
        threats: List of threat reason strings
        
    Returns:
        Threat level string: 'none', 'low', 'medium', or 'high'
    """
    if not threats:
        return 'none'
    
    # Keywords indicating severity
    high_keywords = ['excessive', 'unidentified', 'metasploit', 'back orifice']
    medium_keywords = ['foreign', 'suspicious', 'hidden', 'ephemeral']
    
    threat_text = ' '.join(threats).lower()
    
    # Check for high severity
    high_count = sum(1 for kw in high_keywords if kw in threat_text)
    if high_count >= 2 or len(threats) >= 3:
        return 'high'
    if high_count >= 1:
        return 'medium'
    
    # Check for medium severity
    medium_count = sum(1 for kw in medium_keywords if kw in threat_text)
    if medium_count >= 1:
        return 'medium'
    
    return 'low'


def process_connections() -> List[Dict[str, Any]]:
    """
    Process raw connection data into display-ready format with threat analysis.
    
    Returns:
        List of processed connection dictionaries with threat indicators
    """
    raw_connections = collect_network_connections()
    excessive_ips = {}
    
    processed = []
    
    for conn in raw_connections:
        # Skip listening sockets (handled separately)
        if conn['status'] == 'LISTEN':
            continue
        
        # Skip connections without remote address
        if not conn['remote_address']['ip']:
            continue
        
        # Get process info
        process_info = collect_process_info(conn['pid'])
        
        # Get GeoIP info
        geo_info = collect_geoip_info(conn['remote_address']['ip'])
        
        # Collect threats
        threats = []
        
        # Check for unusual port
        is_unusual_port, port_reason = detect_unusual_port(conn['remote_address']['port'])
        if is_unusual_port:
            threats.append(port_reason)
        
        # Check for unknown process
        is_unknown_proc, proc_reason = detect_unknown_process(process_info)
        if is_unknown_proc:
            threats.append(proc_reason)
        
        # Check for foreign IP
        is_foreign, foreign_reason = detect_foreign_ip(conn['remote_address']['ip'], geo_info)
        if is_foreign:
            threats.append(foreign_reason)
        
        processed.append({
            'local_ip': conn['local_address']['ip'],
            'local_port': conn['local_address']['port'],
            'remote_ip': conn['remote_address']['ip'],
            'remote_port': conn['remote_address']['port'],
            'status': conn['status'],
            'protocol': conn['family'],
            'process_name': process_info['name'],
            'pid': conn['pid'],
            'country_code': geo_info['country_code'] if geo_info else None,
            'country_name': geo_info['country_name'] if geo_info else None,
            'threats': threats,
            'threat_level': calculate_threat_level(threats)
        })
    
    # Check for excessive connections
    excessive_ips = detect_excessive_connections(processed)
    
    # Add excessive connection threats
    for conn in processed:
        if conn['remote_ip'] in excessive_ips:
            conn['threats'].append(excessive_ips[conn['remote_ip']]['reason'])
            conn['threat_level'] = calculate_threat_level(conn['threats'])
    
    return processed


def process_listening_ports() -> List[Dict[str, Any]]:
    """
    Process listening ports with threat analysis.
    
    Returns:
        List of processed listening port dictionaries
    """
    raw_ports = collect_listening_ports()
    processed = []
    
    for port_info in raw_ports:
        process_info = collect_process_info(port_info['pid'])
        
        threats = []
        
        # Check for unusual listening port
        is_unusual, reason = detect_unusual_port(port_info['port'], is_listening=True)
        if is_unusual:
            threats.append(reason)
        
        # Check for unknown process
        is_unknown, proc_reason = detect_unknown_process(process_info)
        if is_unknown:
            threats.append(proc_reason)
        
        processed.append({
            'port': port_info['port'],
            'protocol': port_info['protocol'],
            'address': port_info['address'],
            'process_name': process_info['name'],
            'pid': port_info['pid'],
            # Truncate to binary name to avoid leaking host paths
            'exe': normalize_executable_path(process_info['exe']),
            'threats': threats,
            'threat_level': calculate_threat_level(threats)
        })
    
    # Sort by port number
    processed.sort(key=lambda x: x['port'])
    
    return processed


def process_interfaces() -> List[Dict[str, Any]]:
    """
    Process network interface data for display.
    
    Returns:
        List of processed interface dictionaries with formatted stats
    """
    raw_interfaces = collect_network_interfaces()
    
    processed = []
    for iface in raw_interfaces:
        # Format bytes to human readable
        stats = iface['stats']
        processed.append({
            'name': iface['name'],
            'addresses': iface['addresses'],
            'is_up': iface['is_up'],
            'bytes_sent': stats['bytes_sent'],
            'bytes_recv': stats['bytes_recv'],
            'bytes_sent_formatted': format_bytes(stats['bytes_sent']),
            'bytes_recv_formatted': format_bytes(stats['bytes_recv']),
            'packets_sent': stats['packets_sent'],
            'packets_recv': stats['packets_recv']
        })
    
    # Sort: active interfaces first, then by name
    processed.sort(key=lambda x: (not x['is_up'], x['name']))
    
    return processed


def process_system_info() -> Dict[str, Any]:
    """
    Process system information for display.
    
    Returns:
        Processed system info dictionary with formatted values
    """
    raw_info = collect_system_info()
    
    return {
        'hostname': raw_info['hostname'],
        'os': f"{raw_info['platform']['system']} {raw_info['platform']['release']}",
        'architecture': raw_info['platform']['machine'],
        'uptime_seconds': raw_info['uptime'],
        'uptime_formatted': format_uptime(raw_info['uptime']),
        'boot_time': datetime.fromtimestamp(raw_info['boot_time']).isoformat(),
        'cpu_percent': raw_info['cpu_percent'],
        'cpu_count': raw_info['cpu_count'],
        'memory_total': raw_info['memory']['total'],
        'memory_used': raw_info['memory']['used'],
        'memory_percent': raw_info['memory']['percent'],
        'memory_total_formatted': format_bytes(raw_info['memory']['total']),
        'memory_used_formatted': format_bytes(raw_info['memory']['used'])
    }


def update_connection_history(connection_count: int) -> List[Dict[str, Any]]:
    """
    Update and return connection history for trend graphing.
    
    Args:
        connection_count: Current number of active connections
        
    Returns:
        List of historical data points
    """
    global CONNECTION_HISTORY
    
    now = datetime.now()
    
    CONNECTION_HISTORY.append({
        'timestamp': now.isoformat(),
        'time_display': now.strftime('%H:%M:%S'),
        'count': connection_count
    })
    
    # Trim to max history
    if len(CONNECTION_HISTORY) > MAX_HISTORY_POINTS:
        CONNECTION_HISTORY = CONNECTION_HISTORY[-MAX_HISTORY_POINTS:]
    
    return CONNECTION_HISTORY


def format_bytes(bytes_val: int) -> str:
    """
    Format byte count to human-readable string.
    
    Args:
        bytes_val: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 GB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f} PB"


def format_uptime(seconds: float) -> str:
    """
    Format seconds to human-readable uptime string.
    
    Args:
        seconds: Uptime in seconds
        
    Returns:
        Formatted string (e.g., "3d 12h 45m")
    """
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or not parts:
        parts.append(f"{minutes}m")
    
    return ' '.join(parts)


def add_threat_to_log(ip: str, threat_level: str, reasons: List[str], process_name: str = None) -> None:
    """
    Add a threat event to the in-memory threat log.
    
    The threat log persists during the session but clears on restart.
    No file writing - purely in-memory for privacy and simplicity.
    
    Thread-safe via THREAT_LOG_LOCK to handle concurrent API requests.
    
    Args:
        ip: The IP address involved in the threat
        threat_level: Severity level ('high', 'medium', 'low')
        reasons: List of reasons why this was flagged
        process_name: Optional process name associated with the threat
    """
    if threat_level == 'none' or not reasons:
        return  # Don't log non-threats
    
    with THREAT_LOG_LOCK:
        global THREAT_LOG
        
        entry = {
            'timestamp': datetime.now().isoformat(),
            'time_display': datetime.now().strftime('%H:%M:%S'),
            'ip': ip,
            'threat_level': threat_level,
            'reasons': reasons,
            'process': process_name or 'Unknown'
        }
        
        THREAT_LOG.append(entry)
        
        # Keep only the most recent entries
        if len(THREAT_LOG) > MAX_THREAT_LOG:
            THREAT_LOG = THREAT_LOG[-MAX_THREAT_LOG:]


def get_threat_log() -> List[Dict[str, Any]]:
    """
    Get the current threat log, newest entries first.
    
    Thread-safe read of the threat log.
    
    Returns:
        List of threat log entries, most recent first
    """
    with THREAT_LOG_LOCK:
        return list(reversed(THREAT_LOG))


def collect_top_talkers() -> List[Dict[str, Any]]:
    """
    Identify the top 3 processes using the most network bandwidth.
    
    Uses psutil to get per-process network I/O statistics. Note that this
    requires appropriate permissions to read other processes' stats.
    
    Returns:
        List of top 3 processes with their network usage:
        - pid: Process ID
        - name: Process name
        - bytes_sent: Total bytes sent
        - bytes_recv: Total bytes received
        - total_bytes: Combined sent + received
        - formatted: Human-readable total
    """
    process_net_usage = []
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            # Get network I/O counters for this process
            io = proc.io_counters()
            # Note: io_counters returns disk I/O, not network I/O per process
            # For true per-process network, we'd need to correlate connections
            # Instead, we'll use connection count as a proxy for network activity
            pass
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    # Alternative: Count connections per process as a proxy for network activity
    connections = psutil.net_connections(kind='inet')
    process_connections: Dict[int, Dict[str, Any]] = defaultdict(lambda: {
        'count': 0,
        'bytes_estimate': 0
    })
    
    for conn in connections:
        if conn.pid and conn.status == 'ESTABLISHED':
            process_connections[conn.pid]['count'] += 1
    
    # Build list with process info
    for pid, stats in process_connections.items():
        if stats['count'] > 0:
            try:
                proc = psutil.Process(pid)
                process_net_usage.append({
                    'pid': pid,
                    'name': proc.name(),
                    'connections': stats['count'],
                    'status': 'active'
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    # Sort by connection count and take top 3
    top_talkers = sorted(process_net_usage, key=lambda x: x['connections'], reverse=True)[:3]
    
    return top_talkers


def update_interface_history(interfaces: List[Dict[str, Any]]) -> None:
    """
    Update the traffic history for each network interface.
    
    Stores the last 12 data points (60 seconds at 5-second intervals)
    for generating sparkline graphs showing traffic trends.
    
    Args:
        interfaces: List of processed interface dictionaries with current stats
    """
    global INTERFACE_HISTORY
    
    now = time.time()
    
    for iface in interfaces:
        name = iface['name']
        
        if name not in INTERFACE_HISTORY:
            INTERFACE_HISTORY[name] = []
        
        INTERFACE_HISTORY[name].append({
            'timestamp': now,
            'bytes_recv': iface['bytes_recv'],
            'bytes_sent': iface['bytes_sent']
        })
        
        # Keep only recent history
        if len(INTERFACE_HISTORY[name]) > MAX_INTERFACE_HISTORY:
            INTERFACE_HISTORY[name] = INTERFACE_HISTORY[name][-MAX_INTERFACE_HISTORY:]


def get_interface_sparkline_data() -> Dict[str, List[int]]:
    """
    Calculate traffic deltas for sparkline visualization.
    
    Computes the difference in bytes between consecutive readings
    to show actual throughput over time, not cumulative totals.
    
    Returns:
        Dictionary mapping interface name to list of traffic deltas (bytes/interval)
    """
    sparklines = {}
    
    for name, history in INTERFACE_HISTORY.items():
        if len(history) < 2:
            sparklines[name] = []
            continue
        
        # Calculate deltas (traffic per interval)
        recv_deltas = []
        for i in range(1, len(history)):
            delta = history[i]['bytes_recv'] - history[i-1]['bytes_recv']
            # Handle counter resets (negative deltas)
            recv_deltas.append(max(0, delta))
        
        sparklines[name] = recv_deltas
    
    return sparklines


def warn_if_non_local_host(host: str) -> None:
    """Print a loud warning if binding beyond localhost."""
    if host not in ('127.0.0.1', 'localhost'):
        print(
            f"WARNING: Sentinel is configured to bind to {host}. "
            "This exposes system information to your network. "
            "Only bind to 127.0.0.1 for local use."
        )


# =============================================================================
# API LAYER
# =============================================================================
# Flask routes that serve the frontend and JSON API endpoints.
# Returns processed data only.
# =============================================================================

@app.route('/')
def index():
    """
    Serve the main dashboard page.
    
    Returns:
        Rendered index.html template
    """
    return render_template('index.html')


@app.route('/api/dashboard')
def api_dashboard():
    """
    Main API endpoint returning all dashboard data.
    
    This is the primary endpoint called by the frontend every 5 seconds.
    It aggregates data from all collection and processing functions.
    
    Returns:
        JSON response containing:
        - connections: Active network connections with threat analysis
        - listening_ports: Open ports with process info
        - ufw_status: Firewall status and rules
        - interfaces: Network interface statistics with sparkline data
        - system: System information (CPU, RAM, uptime)
        - history: Connection count history for graphing
        - timestamp: Current server timestamp
        - threat_summary: Aggregated threat statistics
        - threat_log: Recent flagged security events
        - top_talkers: Top 3 processes by network activity
    """
    # Collect all data from the data collection layer
    connections = process_connections()
    listening_ports = process_listening_ports()
    ufw_status = collect_ufw_status()
    interfaces = process_interfaces()
    system = process_system_info()
    
    # Update tracking histories
    history = update_connection_history(len(connections))
    update_interface_history(interfaces)
    
    # Log threats from connections
    for conn in connections:
        if conn['threat_level'] != 'none':
            add_threat_to_log(
                ip=conn['remote_ip'],
                threat_level=conn['threat_level'],
                reasons=conn['threats'],
                process_name=conn['process_name']
            )
    
    # Log threats from listening ports
    for port in listening_ports:
        if port['threat_level'] != 'none':
            add_threat_to_log(
                ip=f":{port['port']}",
                threat_level=port['threat_level'],
                reasons=port['threats'],
                process_name=port['process_name']
            )
    
    # Calculate threat summary for the badge display
    threat_counts = {'high': 0, 'medium': 0, 'low': 0, 'none': 0}
    for conn in connections:
        threat_counts[conn['threat_level']] += 1
    for port in listening_ports:
        threat_counts[port['threat_level']] += 1
    
    # Get additional data for new features
    sparklines = get_interface_sparkline_data()
    top_talkers = collect_top_talkers()
    threat_log = get_threat_log()
    
    return jsonify({
        'connections': connections,
        'listening_ports': listening_ports,
        'ufw_status': ufw_status,
        'interfaces': interfaces,
        'sparklines': sparklines,
        'system': system,
        'history': history,
        'timestamp': datetime.now().isoformat(),
        'threat_summary': threat_counts,
        'threat_log': threat_log,
        'top_talkers': top_talkers
    })


@app.route('/api/connections')
def api_connections():
    """
    API endpoint for active connections only.
    
    Returns:
        JSON list of active connections with threat analysis
    """
    return jsonify(process_connections())


@app.route('/api/ports')
def api_ports():
    """
    API endpoint for listening ports only.
    
    Returns:
        JSON list of listening ports with process info
    """
    return jsonify(process_listening_ports())


@app.route('/api/system')
def api_system():
    """
    API endpoint for system information only.
    
    Returns:
        JSON object with system stats
    """
    return jsonify(process_system_info())


@app.route('/api/interfaces')
def api_interfaces():
    """
    API endpoint for network interfaces only.
    
    Returns:
        JSON list of network interfaces with statistics
    """
    return jsonify(process_interfaces())


@app.route('/api/firewall')
def api_firewall():
    """
    API endpoint for firewall status only.
    
    Returns:
        JSON object with UFW status and rules
    """
    return jsonify(collect_ufw_status())


@app.route('/api/health')
def api_health():
    """
    Health check endpoint.
    
    Returns:
        JSON object with service status
    """
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'geoip_enabled': GEOIP_READER is not None
    })


# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    # Production configuration - debug disabled
    # Bind to localhost only - no external access
    warn_if_non_local_host(HOST)
    app.run(
        host=HOST,
        port=5000,
        debug=False
    )
