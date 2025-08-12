import subprocess
import json
import threading
import time
from datetime import datetime
from models import db, Configuration
from flask import current_app
import logging

logger = logging.getLogger(__name__)

class SpeedTestService:
    """Service for running internet speed tests"""
    
    def __init__(self, app=None):
        self.app = app
        self.running = False
        self.last_test_time = None
        self.test_results = []
        self.max_results = 100  # Keep last 100 results
        
    def is_speedtest_available(self):
        """Check if speedtest-cli is available"""
        try:
            result = subprocess.run(['speedtest', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def install_speedtest_cli(self):
        """Attempt to install speedtest-cli"""
        try:
            logger.info("Attempting to install speedtest-cli...")
            result = subprocess.run(['pip', 'install', 'speedtest-cli'], 
                                  capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                logger.info("speedtest-cli installed successfully")
                return True
            else:
                logger.error(f"Failed to install speedtest-cli: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error installing speedtest-cli: {e}")
            return False
    
    def run_speed_test(self, test_type='comprehensive'):
        """
        Run a speed test
        test_type can be 'comprehensive' or 'upload_only'
        """
        if not self.is_speedtest_available():
            if not self.install_speedtest_cli():
                return {
                    'error': 'speedtest-cli not available and could not be installed',
                    'timestamp': datetime.utcnow(),
                    'success': False
                }
        
        try:
            if test_type == 'upload_only':
                # Skip download test for faster results  
                cmd = ['speedtest', '--json', '--no-download']
                timeout = 60
            else:
                # Full test with JSON output (download + upload)
                cmd = ['speedtest', '--json']
                timeout = 180
            
            logger.info(f"Starting speed test ({test_type}) - timeout: {timeout}s...")
            start_time = time.time()
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            if result.returncode != 0:
                return {
                    'error': f'Speed test failed: {result.stderr}',
                    'timestamp': datetime.utcnow(),
                    'success': False
                }
            
            # Parse JSON result
            try:
                data = json.loads(result.stdout)
                # Convert from bits per second to megabits per second
                data['download_mbps'] = round((data.get('download', 0) or 0) / 1_000_000, 2)
                data['upload_mbps'] = round((data.get('upload', 0) or 0) / 1_000_000, 2)
                data['simple_mode'] = False
            except json.JSONDecodeError:
                # Fallback to simple parsing for --simple mode
                lines = result.stdout.strip().split('\n')
                data = {
                    'download': 0,
                    'upload': 0,
                    'ping': 0,
                    'simple_mode': True
                }
                for line in lines:
                    if 'Download:' in line:
                        # Extract "129.01" from "Download: 129.01 Mbit/s"
                        speed_str = line.split(':')[1].strip().split()[0]
                        data['download'] = float(speed_str)
                        data['download_mbps'] = float(speed_str)  # Already in Mbps for simple mode
                    elif 'Upload:' in line:
                        # Extract "97.03" from "Upload: 97.03 Mbit/s"  
                        speed_str = line.split(':')[1].strip().split()[0]
                        data['upload'] = float(speed_str)
                        data['upload_mbps'] = float(speed_str)  # Already in Mbps for simple mode
                    elif 'Ping:' in line:
                        # Extract "22.484" from "Ping: 22.484 ms"
                        ping_str = line.split(':')[1].strip().split()[0]
                        data['ping'] = float(ping_str)
            
            end_time = time.time()
            test_duration = end_time - start_time
            
            # Process results
            result_data = {
                'timestamp': datetime.utcnow(),
                'success': True,
                'test_type': test_type,
                'duration': round(test_duration, 2),
                'download_mbps': data.get('download_mbps', 0),
                'upload_mbps': data.get('upload_mbps', 0), 
                'ping_ms': round(data.get('ping', 0) or 0, 2),
                'server': {
                    'name': data.get('server', {}).get('name', 'Unknown'),
                    'location': f"{data.get('server', {}).get('city', 'Unknown')}, {data.get('server', {}).get('country', 'Unknown')}",
                    'sponsor': data.get('server', {}).get('sponsor', 'Unknown'),
                    'distance': round(data.get('server', {}).get('d', 0), 2)
                },
                'client': {
                    'ip': data.get('client', {}).get('ip', 'Unknown'),
                    'isp': data.get('client', {}).get('isp', 'Unknown'),
                    'location': f"{data.get('client', {}).get('city', 'Unknown')}, {data.get('client', {}).get('country', 'Unknown')}"
                },
                'raw_data': data
            }
            
            # Store result
            self.test_results.append(result_data)
            
            # Keep only the most recent results
            if len(self.test_results) > self.max_results:
                self.test_results = self.test_results[-self.max_results:]
            
            self.last_test_time = result_data['timestamp']
            
            logger.info(f"Speed test completed: {result_data['download_mbps']} Mbps down, {result_data['upload_mbps']} Mbps up, {result_data['ping_ms']} ms ping")
            
            return result_data
            
        except subprocess.TimeoutExpired:
            timeout_msg = f'Speed test timed out after {timeout // 60} minute{"s" if timeout >= 120 else ""}'
            return {
                'error': timeout_msg,
                'timestamp': datetime.utcnow(),
                'success': False
            }
        except Exception as e:
            logger.error(f"Error running speed test: {e}")
            return {
                'error': f'Speed test error: {str(e)}',
                'timestamp': datetime.utcnow(),
                'success': False
            }
    
    def get_recent_results(self, limit=10):
        """Get recent speed test results"""
        return sorted(self.test_results, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    def get_speed_statistics(self, hours=24):
        """Get speed test statistics for the given period"""
        cutoff = datetime.utcnow().timestamp() - (hours * 3600)
        
        recent_results = [
            result for result in self.test_results 
            if result['success'] and result['timestamp'].timestamp() > cutoff
        ]
        
        if not recent_results:
            return {
                'count': 0,
                'avg_download': 0,
                'avg_upload': 0,
                'avg_ping': 0,
                'max_download': 0,
                'max_upload': 0,
                'min_ping': 0
            }
        
        downloads = [r['download_mbps'] for r in recent_results]
        uploads = [r['upload_mbps'] for r in recent_results]
        pings = [r['ping_ms'] for r in recent_results if r['ping_ms'] > 0]
        
        return {
            'count': len(recent_results),
            'avg_download': round(sum(downloads) / len(downloads), 2),
            'avg_upload': round(sum(uploads) / len(uploads), 2),
            'avg_ping': round(sum(pings) / len(pings), 2) if pings else 0,
            'max_download': round(max(downloads), 2),
            'max_upload': round(max(uploads), 2),
            'min_ping': round(min(pings), 2) if pings else 0,
            'period_hours': hours
        }
    
    def start_automatic_testing(self, interval_hours=6):
        """Start automatic speed testing"""
        if self.running:
            logger.warning("Speed test service already running")
            return
        
        self.running = True
        
        def run_periodic_tests():
            while self.running:
                try:
                    # Check if automatic testing is enabled
                    if self.app:
                        with self.app.app_context():
                            auto_test_enabled = Configuration.get_value('speedtest_auto_enabled', 'false').lower() == 'true'
                            if not auto_test_enabled:
                                time.sleep(300)  # Check again in 5 minutes
                                continue
                    
                    # Run speed test
                    logger.info("Running automatic speed test...")
                    result = self.run_speed_test('comprehensive')
                    
                    if result['success']:
                        logger.info(f"Automatic speed test completed: {result['download_mbps']} Mbps down")
                    else:
                        logger.error(f"Automatic speed test failed: {result.get('error', 'Unknown error')}")
                    
                    # Wait for next test
                    time.sleep(interval_hours * 3600)
                    
                except Exception as e:
                    logger.error(f"Error in automatic speed testing: {e}")
                    time.sleep(3600)  # Wait 1 hour on error
        
        # Start background thread
        test_thread = threading.Thread(target=run_periodic_tests, daemon=True, name='SpeedTestService')
        test_thread.start()
        
        logger.info(f"Speed test service started (interval: {interval_hours} hours)")
    
    def stop_automatic_testing(self):
        """Stop automatic speed testing"""
        self.running = False
        logger.info("Speed test service stopped")
    
    def get_service_status(self):
        """Get service status information"""
        return {
            'available': self.is_speedtest_available(),
            'running': self.running,
            'last_test': self.last_test_time.isoformat() + 'Z' if self.last_test_time else None,
            'total_results': len(self.test_results),
            'service_name': 'HomeNetMon Speed Test Service'
        }

# Global speed test service instance
speed_test_service = SpeedTestService()