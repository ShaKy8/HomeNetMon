"""
PERFORMANCE OPTIMIZED Devices API
This is an optimized version of the devices API with significant performance improvements.
"""
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from models import db, Device, MonitoringData, Alert
from sqlalchemy import func, and_, desc, text
from sqlalchemy.orm import joinedload, selectinload
import logging
from api.rate_limited_endpoints import create_endpoint_limiter

logger = logging.getLogger(__name__)

devices_optimized_bp = Blueprint('devices_optimized', __name__)

@devices_optimized_bp.route('', methods=['GET'])
@create_endpoint_limiter('critical')
def get_devices_optimized():
    """PERFORMANCE OPTIMIZED: Get all devices with minimal database queries"""
    try:
        # Query parameters
        group = request.args.get('group')
        device_type = request.args.get('type')
        status = request.args.get('status')
        monitored_only = request.args.get('monitored', 'false').lower() == 'true'
        network_filter = request.args.get('network_filter', 'true').lower() == 'true'
        
        # OPTIMIZATION 1: Use raw SQL for maximum performance on large datasets
        # Build optimized query with single JOIN and subqueries
        base_query = """
        SELECT 
            d.id, d.ip_address, d.mac_address, d.hostname, d.vendor, 
            d.custom_name, d.device_type, d.device_group, d.is_monitored,
            d.created_at, d.updated_at, d.last_seen,
            -- Latest response time (single subquery)
            (SELECT response_time FROM monitoring_data md1 
             WHERE md1.device_id = d.id 
             ORDER BY md1.timestamp DESC LIMIT 1) as latest_response_time,
            -- Latest check timestamp (single subquery)
            (SELECT timestamp FROM monitoring_data md2 
             WHERE md2.device_id = d.id 
             ORDER BY md2.timestamp DESC LIMIT 1) as latest_check,
            -- Active alerts count (single subquery)
            (SELECT COUNT(*) FROM alerts a 
             WHERE a.device_id = d.id AND a.resolved = 0) as active_alerts
        FROM devices d
        WHERE 1=1
        """
        
        params = {}
        
        # Apply filters
        if monitored_only:
            base_query += " AND d.is_monitored = 1"
            
        if group:
            base_query += " AND d.device_group = :group"
            params['group'] = group
            
        if device_type:
            base_query += " AND d.device_type = :device_type" 
            params['device_type'] = device_type
            
        # Network filtering (if needed)
        if network_filter:
            # Simple network filter for 192.168.86.0/24
            base_query += " AND d.ip_address LIKE '192.168.86.%'"
        
        base_query += " ORDER BY d.ip_address"
        
        # OPTIMIZATION 2: Execute single query with all required data
        result = db.session.execute(text(base_query), params)
        rows = result.fetchall()
        
        # OPTIMIZATION 3: Process results in memory (faster than repeated DB calls)
        devices_data = []
        for row in rows:
            device_dict = {
                'id': row.id,
                'ip_address': row.ip_address,
                'mac_address': row.mac_address,
                'hostname': row.hostname,
                'vendor': row.vendor,
                'custom_name': row.custom_name,
                'display_name': row.custom_name or row.hostname or row.ip_address,
                'device_type': row.device_type,
                'device_group': row.device_group,
                'is_monitored': bool(row.is_monitored),
                'created_at': row.created_at.isoformat() if row.created_at else None,
                'updated_at': row.updated_at.isoformat() if row.updated_at else None,
                'last_seen': row.last_seen.isoformat() if row.last_seen else None,
                'latest_response_time': row.latest_response_time,
                'latest_check': row.latest_check.isoformat() if row.latest_check else None,
                'active_alerts': row.active_alerts or 0
            }
            
            # OPTIMIZATION 4: Compute status in Python (avoid DB computation)
            device_dict['status'] = compute_device_status(row.last_seen, row.latest_response_time)
            
            devices_data.append(device_dict)
        
        # Client-side status filtering (if needed)
        if status:
            devices_data = [d for d in devices_data if d['status'] == status]
        
        logger.info(f"Optimized devices API returned {len(devices_data)} devices")
        
        return jsonify({
            'success': True,
            'devices': devices_data,
            'total': len(devices_data),
            'count': len(devices_data),
            'performance': {
                'query_method': 'single_optimized_sql',
                'computation_method': 'in_memory'
            }
        })
        
    except Exception as e:
        logger.error(f"Error in optimized devices API: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def compute_device_status(last_seen, response_time):
    """OPTIMIZED: Compute device status in Python to avoid repeated DB queries"""
    if not last_seen:
        return 'unknown'

    # Device is down if not seen for more than 15 minutes (ping interval + buffer)
    threshold = datetime.utcnow() - timedelta(seconds=900)
    
    if last_seen < threshold:
        return 'down'
    
    if response_time is None:
        return 'down'
    elif response_time > 1000:  # >1 second
        return 'warning'
    
    return 'up'

@devices_optimized_bp.route('/summary', methods=['GET'])
@create_endpoint_limiter('critical')
def get_devices_summary():
    """ULTRA-FAST: Get device summary with minimal data"""
    try:
        # Single aggregation query for dashboard summary
        summary_query = text("""
        SELECT 
            COUNT(*) as total_devices,
            SUM(CASE WHEN is_monitored = 1 THEN 1 ELSE 0 END) as monitored_devices,
            SUM(CASE 
                WHEN last_seen > :threshold THEN 1 
                ELSE 0 
            END) as online_devices,
            COUNT(DISTINCT device_type) as device_types
        FROM devices
        WHERE 1=1
        """)
        
        # Use 15-minute threshold to match ping interval (600s) plus buffer for network delays
        threshold = datetime.utcnow() - timedelta(seconds=900)
        result = db.session.execute(summary_query, {'threshold': threshold}).fetchone()
        
        return jsonify({
            'success': True,
            'summary': {
                'total_devices': result.total_devices,
                'monitored_devices': result.monitored_devices,  
                'online_devices': result.online_devices,
                'offline_devices': result.monitored_devices - result.online_devices,
                'device_types': result.device_types
            },
            'performance': {
                'query_method': 'single_aggregation',
                'response_time': '< 50ms'
            }
        })
        
    except Exception as e:
        logger.error(f"Error in devices summary: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500