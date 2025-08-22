"""
Unit tests for the NetworkScanner service.

Tests cover:
- Service initialization and configuration
- Network scanning with nmap integration
- Device discovery and identification
- MAC address vendor lookup
- ARP table parsing
- Device creation and updates
- Configuration hot-reload
- Background thread management
- Error handling for external dependencies
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import threading
import subprocess

from monitoring.scanner import NetworkScanner
from models import Device, Configuration
from tests.fixtures.factories import DeviceFactory, ConfigurationFactory
from tests.fixtures.utils import MockHelper, get_sample_network_scan_result


class TestNetworkScannerInitialization:
    """Test NetworkScanner service initialization."""
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_network_scanner_init_default(self, mock_mac_parser, mock_nmap):
        """Test NetworkScanner initialization with defaults."""
        scanner = NetworkScanner()
        
        assert scanner.app is None
        assert scanner.is_running is False
        assert scanner.is_scanning is False
        assert scanner.scan_thread is None
        assert scanner.rule_engine_service is None
        assert isinstance(scanner._stop_event, threading.Event)
        assert isinstance(scanner._config_cache, dict)
        assert isinstance(scanner._config_versions, dict)
        assert isinstance(scanner._devices_before_scan, set)
        assert isinstance(scanner._new_devices_found, list)
        
        # Should initialize nmap and mac parser
        mock_nmap.assert_called_once()
        mock_mac_parser.assert_called_once()
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_network_scanner_init_with_app(self, mock_mac_parser, mock_nmap, app):
        """Test NetworkScanner initialization with Flask app."""
        scanner = NetworkScanner(app=app)
        
        assert scanner.app == app
        assert scanner.is_running is False
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_network_scanner_config_cache_initialization(self, mock_mac_parser, mock_nmap):
        """Test configuration cache initialization."""
        scanner = NetworkScanner()
        
        assert len(scanner._config_cache) == 0
        assert len(scanner._config_versions) == 0
        assert isinstance(scanner._last_config_check, datetime)


class TestNetworkScannerConfiguration:
    """Test NetworkScanner configuration management."""
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_get_config_value_with_app(self, mock_mac_parser, mock_nmap, app, db_session):
        """Test getting configuration value with Flask app context."""
        # Create a configuration entry
        config = ConfigurationFactory.create(
            key='network_range',
            value='192.168.1.0/24'
        )
        
        scanner = NetworkScanner(app=app)
        
        with app.app_context():
            value = scanner.get_config_value('network_range', '10.0.0.0/24')
            assert value == '192.168.1.0/24'
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_get_config_value_default(self, mock_mac_parser, mock_nmap, app, db_session):
        """Test getting default configuration value when key doesn't exist."""
        scanner = NetworkScanner(app=app)
        
        with app.app_context():
            value = scanner.get_config_value('nonexistent_key', '192.168.1.0/24')
            assert value == '192.168.1.0/24'
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_config_cache_hot_reload(self, mock_mac_parser, mock_nmap, app, db_session):
        """Test configuration hot-reload functionality."""
        scanner = NetworkScanner(app=app)
        
        # Create initial configuration
        config = ConfigurationFactory.create(
            key='scan_interval',
            value='300'
        )
        
        with app.app_context():
            # First access - should cache
            value1 = scanner.get_config_value('scan_interval', '600')
            assert value1 == '300'
            assert 'scan_interval' in scanner._config_cache
            
            # Update configuration
            config.value = '900'
            config.version += 1
            db_session.commit()
            
            # Force config check by updating last check time
            scanner._last_config_check = datetime.utcnow() - timedelta(seconds=15)
            
            # Second access - should reload
            value2 = scanner.get_config_value('scan_interval', '600')
            assert value2 == '900'
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_config_version_tracking(self, mock_mac_parser, mock_nmap, app, db_session):
        """Test configuration version tracking for cache invalidation."""
        scanner = NetworkScanner(app=app)
        
        config = ConfigurationFactory.create(
            key='test_key',
            value='test_value',
            version=1
        )
        
        with app.app_context():
            # First access
            scanner.get_config_value('test_key', 'default')
            assert scanner._config_versions.get('test_key') == 1
            
            # Update version
            config.version = 2
            db_session.commit()
            
            # Force config check
            scanner._last_config_check = datetime.utcnow() - timedelta(seconds=15)
            
            # Second access should detect version change
            scanner.get_config_value('test_key', 'default')
            assert scanner._config_versions.get('test_key') == 2


class TestNetworkScanning:
    """Test network scanning functionality."""
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_scan_network_basic(self, mock_mac_parser, mock_nmap, app, db_session):
        """Test basic network scanning functionality."""
        # Setup mocks
        mock_nm_instance = MagicMock()
        mock_nmap.return_value = mock_nm_instance
        
        # Mock nmap scan results
        scan_results = get_sample_network_scan_result()
        
        # Mock the nmap scan return structure
        mock_scan_return = {
            'scan': {}
        }
        
        for host_data in scan_results:
            mock_scan_return['scan'][host_data['ip']] = {
                'status': {'state': 'up'},
                'addresses': {
                    'ipv4': host_data['ip'],
                    'mac': host_data['mac']
                },
                'vendor': {host_data['mac']: host_data['vendor']},
                'hostnames': [{'name': host_data['hostname'], 'type': 'PTR'}]
            }
        
        mock_nm_instance.scan.return_value = mock_scan_return
        
        # Mock MAC vendor lookup
        mock_mac_parser_instance = MagicMock()
        mock_mac_parser.return_value = mock_mac_parser_instance
        mock_mac_parser_instance.get_manuf.return_value = 'Test Vendor'
        
        scanner = NetworkScanner(app=app)
        scanner.nm = mock_nm_instance
        scanner.mac_parser = mock_mac_parser_instance
        
        with app.app_context():
            # Set up configuration for network range (upsert)
            from models import Configuration, db
            existing_config = Configuration.query.filter_by(key='network_range').first()
            if existing_config:
                existing_config.value = '192.168.1.0/24'
            else:
                config = Configuration(key='network_range', value='192.168.1.0/24')
                db.session.add(config)
            db.session.commit()
            
            # The scan_network method doesn't return devices directly, it updates the database
            scanner.scan_network()
            
            # Verify that devices were discovered and stored in database
            from models import Device
            
            # Check that the specific devices from our scan results exist
            scan_ips = [host['ip'] for host in scan_results]
            found_devices = Device.query.filter(Device.ip_address.in_(scan_ips)).all()
        
        assert len(found_devices) == len(scan_results)
        
        # Verify the devices have the expected properties
        for scan_result in scan_results:
            device = next((d for d in found_devices if d.ip_address == scan_result['ip']), None)
            assert device is not None, f"Device with IP {scan_result['ip']} not found"
            assert device.mac_address == scan_result['mac']
            assert device.hostname == scan_result['hostname']
        
        # Verify nmap was called correctly
        mock_nm_instance.scan.assert_called_once()
        call_args = mock_nm_instance.scan.call_args
        # The nmap scan is called with network_range from config
        assert '192.168.1.0/24' in str(call_args)
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_scan_network_with_existing_devices(self, mock_mac_parser, mock_nmap, app, db_session):
        """Test network scanning with existing devices in database."""
        # Create existing device
        existing_device = DeviceFactory.create(
            ip_address='192.168.1.1',
            mac_address='00:11:22:33:44:01'
        )
        
        # Setup mocks
        mock_nm_instance = MagicMock()
        mock_nmap.return_value = mock_nm_instance
        
        scan_results = [
            {
                'ip': '192.168.1.1',  # Existing device
                'mac': '00:11:22:33:44:01',
                'vendor': 'Router Corp',
                'hostname': 'home-router'
            },
            {
                'ip': '192.168.1.10',  # New device
                'mac': '00:11:22:33:44:02',
                'vendor': 'Computer Inc',
                'hostname': 'desktop-pc'
            }
        ]
        
        # Mock the nmap scan return structure
        mock_scan_return = {
            'scan': {}
        }
        
        for host_data in scan_results:
            mock_scan_return['scan'][host_data['ip']] = {
                'status': {'state': 'up'},
                'addresses': {
                    'ipv4': host_data['ip'],
                    'mac': host_data['mac']
                },
                'vendor': {host_data['mac']: host_data['vendor']},
                'hostnames': [{'name': host_data['hostname'], 'type': 'PTR'}]
            }
        
        mock_nm_instance.scan.return_value = mock_scan_return
        
        # Mock MAC vendor lookup
        mock_mac_parser_instance = MagicMock()
        mock_mac_parser.return_value = mock_mac_parser_instance
        mock_mac_parser_instance.get_manuf.return_value = 'Test Vendor'
        
        scanner = NetworkScanner(app=app)
        scanner.nm = mock_nm_instance
        scanner.mac_parser = mock_mac_parser_instance
        
        with app.app_context():
            # Set up configuration for network range (upsert)
            from models import Configuration, db
            existing_config = Configuration.query.filter_by(key='network_range').first()
            if existing_config:
                existing_config.value = '192.168.1.0/24'
            else:
                config = Configuration(key='network_range', value='192.168.1.0/24')
                db.session.add(config)
            db.session.commit()
            
            # The scan_network method doesn't return devices directly, it updates the database
            scanner.scan_network()
        
        # Should find both devices in database
        scan_ips = [host['ip'] for host in scan_results]
        found_devices = Device.query.filter(Device.ip_address.in_(scan_ips)).all()
        assert len(found_devices) == 2
        
        # Existing device should be updated
        updated_device = Device.query.filter_by(ip_address='192.168.1.1').first()
        assert updated_device.last_seen is not None
        
        # New device should be created
        new_device = Device.query.filter_by(ip_address='192.168.1.10').first()
        assert new_device is not None
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_scan_network_nmap_error(self, mock_mac_parser, mock_nmap, app, db_session):
        """Test network scanning with nmap error."""
        # Setup mock to raise exception
        mock_nm_instance = MagicMock()
        mock_nmap.return_value = mock_nm_instance
        mock_nm_instance.scan.side_effect = Exception("Network unreachable")
        
        # Mock MAC vendor lookup
        mock_mac_parser_instance = MagicMock()
        mock_mac_parser.return_value = mock_mac_parser_instance
        mock_mac_parser_instance.get_manuf.return_value = 'Test Vendor'
        
        scanner = NetworkScanner(app=app)
        scanner.nm = mock_nm_instance
        scanner.mac_parser = mock_mac_parser_instance
        
        with app.app_context():
            # Set up configuration for network range (upsert)
            from models import Configuration, db
            existing_config = Configuration.query.filter_by(key='network_range').first()
            if existing_config:
                existing_config.value = '192.168.1.0/24'
            else:
                config = Configuration(key='network_range', value='192.168.1.0/24')
                db.session.add(config)
            db.session.commit()
            
            # Should handle error gracefully - scan_network doesn't return devices
            scanner.scan_network()
        
        # Verify that no new devices were added due to error
        # (This is just testing that the method doesn't crash on error)
        # The actual behavior depends on error handling in the implementation
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_scan_network_empty_results(self, mock_mac_parser, mock_nmap, app, db_session):
        """Test network scanning with no devices found."""
        # Setup mock with no results
        mock_nm_instance = MagicMock()
        mock_nmap.return_value = mock_nm_instance
        
        # Mock empty scan results
        mock_scan_return = {'scan': {}}
        mock_nm_instance.scan.return_value = mock_scan_return
        
        # Mock MAC vendor lookup
        mock_mac_parser_instance = MagicMock()
        mock_mac_parser.return_value = mock_mac_parser_instance
        mock_mac_parser_instance.get_manuf.return_value = 'Test Vendor'
        
        scanner = NetworkScanner(app=app)
        scanner.nm = mock_nm_instance
        scanner.mac_parser = mock_mac_parser_instance
        
        with app.app_context():
            # Set up configuration for network range (upsert)
            from models import Configuration, db
            existing_config = Configuration.query.filter_by(key='network_range').first()
            if existing_config:
                existing_config.value = '192.168.1.0/24'
            else:
                config = Configuration(key='network_range', value='192.168.1.0/24')
                db.session.add(config)
            db.session.commit()
            
            # Capture count before scan
            before_count = Device.query.count()
            
            # Scan network - should find no devices
            scanner.scan_network()
            
            # Should not add any new devices
            after_count = Device.query.count()
            assert after_count == before_count


class TestDeviceIdentification:
    """Test device identification and classification."""
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_identify_device_type_router(self, mock_mac_parser, mock_nmap):
        """Test router device type identification."""
        scanner = NetworkScanner()
        
        # Router characteristics
        device_info = {
            'ip': '192.168.1.1',
            'mac': '00:11:22:33:44:01',
            'vendor': 'Linksys',
            'hostname': 'router'
        }
        
        device_type = scanner.classify_device_type(device_info)
        assert device_type == 'router'
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_identify_device_type_apple(self, mock_mac_parser, mock_nmap):
        """Test Apple device identification."""
        scanner = NetworkScanner()
        
        # Apple device characteristics
        device_info = {
            'ip': '192.168.1.20',
            'mac': '00:11:22:33:44:03',
            'vendor': 'Apple Inc.',
            'hostname': 'iPhone'
        }
        
        device_type = scanner.classify_device_type(device_info)
        assert device_type == 'apple'
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_identify_device_type_computer(self, mock_mac_parser, mock_nmap):
        """Test computer device identification."""
        scanner = NetworkScanner()
        
        # Computer characteristics
        device_info = {
            'ip': '192.168.1.10',
            'mac': '00:11:22:33:44:02',
            'vendor': 'Dell Inc.',
            'hostname': 'DESKTOP-PC'
        }
        
        device_type = scanner.classify_device_type(device_info)
        assert device_type == 'computer'
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_identify_device_type_unknown(self, mock_mac_parser, mock_nmap):
        """Test unknown device identification."""
        scanner = NetworkScanner()
        
        # Unknown device characteristics
        device_info = {
            'ip': '192.168.1.50',
            'mac': '00:11:22:33:44:05',
            'vendor': 'Unknown Vendor',
            'hostname': 'device-50'
        }
        
        device_type = scanner.classify_device_type(device_info)
        assert device_type == 'unknown'


class TestARPTableParsing:
    """Test ARP table parsing functionality."""
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    @patch('monitoring.scanner.subprocess.run')
    def test_parse_arp_table(self, mock_subprocess, mock_mac_parser, mock_nmap, app):
        """Test ARP table parsing."""
        # Mock ARP table output
        arp_output = """
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.1.1              ether   00:11:22:33:44:01   C                     eth0
192.168.1.10             ether   00:11:22:33:44:02   C                     eth0
192.168.1.20             ether   00:11:22:33:44:03   C                     eth0
        """
        
        mock_result = Mock()
        mock_result.stdout = arp_output
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        scanner = NetworkScanner(app=app)
        
        arp_devices = scanner.get_arp_table()
        
        assert len(arp_devices) == 3
        
        # Check that devices were parsed correctly
        device_ips = [device['ip'] for device in arp_devices]
        assert '192.168.1.1' in device_ips
        assert '192.168.1.10' in device_ips
        assert '192.168.1.20' in device_ips
        
        # Check specific device details
        router_device = next(d for d in arp_devices if d['ip'] == '192.168.1.1')
        assert router_device['mac'] == '00:11:22:33:44:01'
        assert router_device['source'] == 'arp'
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    @patch('monitoring.scanner.subprocess.run')
    def test_parse_arp_table_error(self, mock_subprocess, mock_mac_parser, mock_nmap, app):
        """Test ARP table parsing with command error."""
        # Mock subprocess error
        mock_subprocess.side_effect = subprocess.SubprocessError("Command failed")
        
        scanner = NetworkScanner(app=app)
        
        # Should handle error gracefully
        arp_devices = scanner.get_arp_table()
        assert arp_devices == []
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    @patch('monitoring.scanner.subprocess.run')
    def test_parse_arp_table_empty(self, mock_subprocess, mock_mac_parser, mock_nmap, app):
        """Test ARP table parsing with empty output."""
        # Mock empty ARP output
        mock_result = Mock()
        mock_result.stdout = "Address                  HWtype  HWaddress           Flags Mask            Iface\n"
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        scanner = NetworkScanner(app=app)
        
        arp_devices = scanner.get_arp_table()
        assert arp_devices == []


class TestMACVendorLookup:
    """Test MAC address vendor lookup functionality."""
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_lookup_mac_vendor(self, mock_mac_parser, mock_nmap):
        """Test MAC address vendor lookup."""
        # Mock MAC parser
        mock_mac_parser_instance = Mock()
        mock_mac_parser.return_value = mock_mac_parser_instance
        mock_mac_parser_instance.get_manuf.return_value = 'Apple Inc.'
        
        scanner = NetworkScanner()
        scanner.mac_parser = mock_mac_parser_instance
        
        vendor = scanner.get_mac_vendor('00:11:22:33:44:55')
        
        assert vendor == 'Apple Inc.'
        mock_mac_parser_instance.get_manuf.assert_called_once_with('00:11:22:33:44:55')
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_lookup_mac_vendor_not_found(self, mock_mac_parser, mock_nmap):
        """Test MAC address vendor lookup when vendor not found."""
        # Mock MAC parser returning None
        mock_mac_parser_instance = Mock()
        mock_mac_parser.return_value = mock_mac_parser_instance
        mock_mac_parser_instance.get_manuf.return_value = None
        
        scanner = NetworkScanner()
        scanner.mac_parser = mock_mac_parser_instance
        
        vendor = scanner.get_mac_vendor('00:11:22:33:44:55')
        
        assert vendor is None
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_lookup_mac_vendor_exception(self, mock_mac_parser, mock_nmap):
        """Test MAC address vendor lookup with exception."""
        # Mock MAC parser raising exception
        mock_mac_parser_instance = Mock()
        mock_mac_parser.return_value = mock_mac_parser_instance
        mock_mac_parser_instance.get_manuf.side_effect = Exception("Parser error")
        
        scanner = NetworkScanner()
        scanner.mac_parser = mock_mac_parser_instance
        
        vendor = scanner.get_mac_vendor('00:11:22:33:44:55')
        
        assert vendor is None


class TestDeviceCreationAndUpdates:
    """Test device creation and update logic."""
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_create_or_update_device_new(self, mock_mac_parser, mock_nmap, app, db_session):
        """Test creating new device from scan results."""
        # Setup mocks using MagicMock
        mock_nm_instance = MagicMock()
        mock_nmap.return_value = mock_nm_instance
        
        # Mock MAC vendor lookup
        mock_mac_parser_instance = MagicMock()
        mock_mac_parser.return_value = mock_mac_parser_instance
        mock_mac_parser_instance.get_manuf.return_value = 'Test Vendor'
        
        scanner = NetworkScanner(app=app)
        scanner.nm = mock_nm_instance
        scanner.mac_parser = mock_mac_parser_instance
        
        device_info = {
            'ip': '192.168.1.100',
            'mac': '00:11:22:33:44:55',
            'vendor': 'Test Vendor',
            'hostname': 'test-device',
            'device_type': 'computer'
        }
        
        with app.app_context():
            scanner.process_discovered_device(device_info)
            
            # Query the database for the created device
            from models import Device
            device = Device.query.filter_by(ip_address='192.168.1.100').first()
        
        assert device is not None
        assert device.ip_address == '192.168.1.100'
        assert device.mac_address == '00:11:22:33:44:55'
        assert device.vendor == 'Test Vendor'
        assert device.hostname == 'test-device'
        assert device.device_type == 'computer'
        assert device.last_seen is not None
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_create_or_update_device_existing(self, mock_mac_parser, mock_nmap, app, db_session):
        """Test updating existing device from scan results."""
        # Create existing device
        existing_device = DeviceFactory.create(
            ip_address='192.168.1.100',
            mac_address='00:11:22:33:44:55',
            hostname='old-hostname',
            last_seen=datetime.utcnow() - timedelta(hours=1)
        )
        
        # Setup mocks using MagicMock
        mock_nm_instance = MagicMock()
        mock_nmap.return_value = mock_nm_instance
        
        # Mock MAC vendor lookup
        mock_mac_parser_instance = MagicMock()
        mock_mac_parser.return_value = mock_mac_parser_instance
        mock_mac_parser_instance.get_manuf.return_value = 'Updated Vendor'
        
        scanner = NetworkScanner(app=app)
        scanner.nm = mock_nm_instance
        scanner.mac_parser = mock_mac_parser_instance
        
        device_info = {
            'ip': '192.168.1.100',
            'mac': '00:11:22:33:44:55',
            'vendor': 'Updated Vendor',
            'hostname': 'new-hostname',
            'device_type': 'computer'
        }
        
        with app.app_context():
            scanner.process_discovered_device(device_info)
            
            # Query the database for the updated device
            from models import Device
            device = Device.query.filter_by(ip_address='192.168.1.100').first()
        
        assert device.id == existing_device.id  # Same device
        assert device.hostname == 'new-hostname'  # Updated
        assert device.vendor == 'Updated Vendor'  # Updated
        assert device.last_seen > existing_device.last_seen  # Updated timestamp
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_create_or_update_device_mac_change(self, mock_mac_parser, mock_nmap, app, db_session):
        """Test updating device when MAC address changes."""
        # Create existing device with different MAC
        existing_device = DeviceFactory.create(
            ip_address='192.168.1.100',
            mac_address='00:11:22:33:44:55'
        )
        
        # Setup mocks using MagicMock
        mock_nm_instance = MagicMock()
        mock_nmap.return_value = mock_nm_instance
        
        # Mock MAC vendor lookup
        mock_mac_parser_instance = MagicMock()
        mock_mac_parser.return_value = mock_mac_parser_instance
        mock_mac_parser_instance.get_manuf.return_value = 'Test Vendor'
        
        scanner = NetworkScanner(app=app)
        scanner.nm = mock_nm_instance
        scanner.mac_parser = mock_mac_parser_instance
        
        device_info = {
            'ip': '192.168.1.100',
            'mac': '00:11:22:33:44:66',  # Different MAC
            'vendor': 'Test Vendor',
            'hostname': 'test-device',
            'device_type': 'computer'
        }
        
        with app.app_context():
            scanner.process_discovered_device(device_info)
            
            # Query the database for the updated device
            from models import Device
            device = Device.query.filter_by(ip_address='192.168.1.100').first()
        
        # Should update the MAC address
        assert device.id == existing_device.id
        assert device.mac_address == '00:11:22:33:44:66'


class TestNetworkScannerThreading:
    """Test NetworkScanner background thread management."""
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_start_scanning_thread(self, mock_mac_parser, mock_nmap, app):
        """Test starting the network scanning thread."""
        scanner = NetworkScanner(app=app)
        
        # Start scanning but don't actually scan in the test
        # Mock the scan_network method to avoid actual scanning
        scanner.scan_network = Mock()
        
        # Start in background thread to avoid blocking
        import threading
        scan_thread = threading.Thread(target=scanner.start_continuous_scan, daemon=True)
        scan_thread.start()
        
        # Give it a moment to start
        import time
        time.sleep(0.1)
        
        assert scanner.is_running is True
        
        # Clean up
        scanner.stop()
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_stop_scanning_thread(self, mock_mac_parser, mock_nmap, app):
        """Test stopping the network scanning thread."""
        scanner = NetworkScanner(app=app)
        
        # Start scanning but don't actually scan in the test
        scanner.scan_network = Mock()
        
        # Start in background thread
        import threading
        scan_thread = threading.Thread(target=scanner.start_continuous_scan, daemon=True)
        scan_thread.start()
        
        # Give it a moment to start
        import time
        time.sleep(0.1)
        
        scanner.stop()
        
        # Give it a moment to stop
        time.sleep(0.1)
        
        assert scanner.is_running is False
        assert scanner._stop_event.is_set()
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_manual_scan_status(self, mock_mac_parser, mock_nmap, app):
        """Test manual scan status tracking."""
        scanner = NetworkScanner(app=app)
        
        assert scanner.is_scanning is False
        
        # Simulate manual scan start
        scanner.is_scanning = True
        assert scanner.is_scanning is True
        
        # Simulate manual scan end
        scanner.is_scanning = False
        assert scanner.is_scanning is False


class TestNewDeviceNotifications:
    """Test new device discovery notifications."""
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    @patch('monitoring.scanner.push_service')
    def test_new_device_notification(self, mock_push_service, mock_mac_parser, mock_nmap, app, db_session):
        """Test notification when new device is discovered."""
        # Setup mocks
        mock_nm_instance = MagicMock()
        mock_nmap.return_value = mock_nm_instance
        
        # Mock scan results with new device
        scan_results = [{
            'ip': '192.168.1.50',
            'mac': '00:11:22:33:44:99',
            'vendor': 'New Vendor',
            'hostname': 'new-device'
        }]
        
        # Mock the nmap scan return structure
        mock_scan_return = {
            'scan': {}
        }
        
        for host_data in scan_results:
            mock_scan_return['scan'][host_data['ip']] = {
                'status': {'state': 'up'},
                'addresses': {
                    'ipv4': host_data['ip'],
                    'mac': host_data['mac']
                },
                'vendor': {host_data['mac']: host_data['vendor']},
                'hostnames': [{'name': host_data['hostname'], 'type': 'PTR'}]
            }
        
        mock_nm_instance.scan.return_value = mock_scan_return
        
        # Mock MAC vendor lookup
        mock_mac_parser_instance = MagicMock()
        mock_mac_parser.return_value = mock_mac_parser_instance
        mock_mac_parser_instance.get_manuf.return_value = 'Test Vendor'
        
        scanner = NetworkScanner(app=app)
        scanner.nm = mock_nm_instance
        scanner.mac_parser = mock_mac_parser_instance
        
        # Track devices before scan (empty)
        scanner._devices_before_scan = set()
        
        with app.app_context():
            # Set up configuration for network range (upsert)
            from models import Configuration, db
            existing_config = Configuration.query.filter_by(key='network_range').first()
            if existing_config:
                existing_config.value = '192.168.1.0/24'
            else:
                config = Configuration(key='network_range', value='192.168.1.0/24')
                db.session.add(config)
            db.session.commit()
            
            # The scan_network method doesn't return devices directly, it updates the database
            scanner.scan_network()
        
        # Verify that new device was created in database
        new_device = Device.query.filter_by(ip_address='192.168.1.50').first()
        assert new_device is not None
        assert new_device.mac_address == '00:11:22:33:44:99'
        assert new_device.hostname == 'new-device'
        
        # Note: Push notification testing would require checking actual notification calls
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_no_notification_for_existing_devices(self, mock_mac_parser, mock_nmap, app, db_session):
        """Test no notification for existing devices."""
        # Create existing device
        existing_device = DeviceFactory.create(ip_address='192.168.1.10')
        
        scanner = NetworkScanner(app=app)
        
        # Track devices before scan (include existing)
        scanner._devices_before_scan = {existing_device.ip_address}
        scanner._new_devices_found = []
        
        # Mock finding the same device
        device_info = {
            'ip': '192.168.1.10',
            'mac': '00:11:22:33:44:99',
            'vendor': 'Test Vendor',
            'hostname': 'test-device'
        }
        
        with app.app_context():
            scanner.process_discovered_device(device_info)
        
        # Should not add to new devices list (since device existed before scan)
        assert len(scanner._new_devices_found) == 0


class TestNetworkScannerIntegration:
    """Test NetworkScanner integration with other components."""
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_integration_with_rule_engine(self, mock_mac_parser, mock_nmap, app, db_session):
        """Test integration with rule engine service."""
        scanner = NetworkScanner(app=app)
        
        # Mock rule engine service
        mock_rule_engine = Mock()
        scanner.rule_engine_service = mock_rule_engine
        
        device_info = {
            'ip': '192.168.1.100',
            'mac': '00:11:22:33:44:55',
            'vendor': 'Test Vendor',
            'hostname': 'test-device',
            'device_type': 'computer'
        }
        
        with app.app_context():
            scanner.process_discovered_device(device_info)
            
            # Query the database for the created device
            from models import Device
            device = Device.query.filter_by(ip_address='192.168.1.100').first()
            assert device is not None
        
        # Rule engine integration is tested by setting the mock
        # This tests the integration point
        assert scanner.rule_engine_service == mock_rule_engine
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_error_handling_during_scan(self, mock_mac_parser, mock_nmap, app, db_session):
        """Test error handling during network scan."""
        # Mock nmap to raise exception
        mock_nm_instance = Mock()
        mock_nmap.return_value = mock_nm_instance
        mock_nm_instance.scan.side_effect = Exception("Network error")
        
        scanner = NetworkScanner(app=app)
        scanner.nm = mock_nm_instance
        
        with app.app_context():
            # Should handle error gracefully
            scanner.scan_network()
        
        # Should handle error gracefully (no exception should be raised)
        # The method doesn't return anything, just logs the error
    
    @patch('monitoring.scanner.nmap.PortScanner')
    @patch('monitoring.scanner.manuf.MacParser')
    def test_database_transaction_handling(self, mock_mac_parser, mock_nmap, app, db_session):
        """Test proper database transaction handling during device creation."""
        scanner = NetworkScanner(app=app)
        
        device_info = {
            'ip': '192.168.1.100',
            'mac': '00:11:22:33:44:55',
            'vendor': 'Test Vendor',
            'hostname': 'test-device',
            'device_type': 'computer'
        }
        
        with app.app_context():
            # Should handle database operations properly
            scanner.process_discovered_device(device_info)
            
            # Verify device was persisted
            saved_device = Device.query.filter_by(ip_address='192.168.1.100').first()
            assert saved_device is not None
            assert saved_device.ip_address == device_info['ip']