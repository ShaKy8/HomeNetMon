from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
from services.speedtest import speed_test_service
from api.rate_limited_endpoints import create_endpoint_limiter
import threading

speedtest_bp = Blueprint('speedtest', __name__)

@speedtest_bp.route('/status', methods=['GET'])
@create_endpoint_limiter('critical')
def get_speedtest_status():
    """Get speed test service status"""
    try:
        status = speed_test_service.get_service_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@speedtest_bp.route('/run', methods=['POST'])
@create_endpoint_limiter('critical')
def run_speedtest():
    """Run a speed test"""
    try:
        data = request.get_json() or {}
        test_type = data.get('type', 'comprehensive')  # comprehensive, upload_only
        
        # Validate test type
        if test_type not in ['comprehensive', 'upload_only']:
            return jsonify({'error': 'Invalid test type. Use: comprehensive or upload_only'}), 400
        
        # Run test in background to avoid timeout
        def run_test_async():
            try:
                result = speed_test_service.run_speed_test(test_type)
                # Store result in the service instead of current_app for thread safety
                speed_test_service.last_async_result = result
            except Exception as e:
                speed_test_service.last_async_result = {
                    'error': str(e),
                    'success': False,
                    'timestamp': datetime.utcnow()
                }
        
        # Start test in background
        test_thread = threading.Thread(target=run_test_async, daemon=True)
        test_thread.start()
        
        return jsonify({
            'message': f'Speed test started ({test_type})',
            'test_type': test_type,
            'started_at': datetime.utcnow().isoformat() + 'Z',
            'note': 'Use /results endpoint to check for completion'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@speedtest_bp.route('/run-sync', methods=['POST'])
@create_endpoint_limiter('critical')
def run_speedtest_sync():
    """Run a speed test synchronously (may timeout for comprehensive tests)"""
    try:
        data = request.get_json() or {}
        test_type = data.get('type', 'comprehensive')  # Default to comprehensive for sync
        
        # Validate test type
        if test_type not in ['comprehensive', 'upload_only']:
            return jsonify({'error': 'Invalid test type. Use: comprehensive or upload_only'}), 400
        
        result = speed_test_service.run_speed_test(test_type)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@speedtest_bp.route('/results', methods=['GET'])
@create_endpoint_limiter('critical')
def get_speedtest_results():
    """Get recent speed test results"""
    try:
        limit = request.args.get('limit', default=10, type=int)
        
        if limit > 50:
            limit = 50  # Cap at 50 results
        
        results = speed_test_service.get_recent_results(limit)
        
        return jsonify({
            'results': [
                {
                    **result,
                    'timestamp': result['timestamp'].isoformat() + 'Z'
                }
                for result in results
            ],
            'count': len(results),
            'last_test': results[0]['timestamp'].isoformat() + 'Z' if results else None
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@speedtest_bp.route('/latest', methods=['GET'])
@create_endpoint_limiter('critical')
def get_latest_result():
    """Get the most recent speed test result"""
    try:
        # Check for async result first (most recent)
        if hasattr(speed_test_service, 'last_async_result') and speed_test_service.last_async_result:
            result = speed_test_service.last_async_result
            # Convert timestamp if needed
            if 'timestamp' in result and hasattr(result['timestamp'], 'isoformat'):
                result = dict(result)
                result['timestamp'] = result['timestamp'].isoformat() + 'Z'
            # Clear the async result after returning it
            speed_test_service.last_async_result = None
            return jsonify(result)
        
        # Otherwise get from service history
        results = speed_test_service.get_recent_results(1)
        if not results:
            return jsonify({'error': 'No speed test results available'}), 404
        
        latest = results[0]
        latest['timestamp'] = latest['timestamp'].isoformat() + 'Z'
        
        return jsonify(latest)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@speedtest_bp.route('/statistics', methods=['GET'])
@create_endpoint_limiter('critical')
def get_speedtest_statistics():
    """Get speed test statistics"""
    try:
        hours = request.args.get('hours', default=24, type=int)
        
        # Cap at 30 days
        if hours > 720:
            hours = 720
        
        stats = speed_test_service.get_speed_statistics(hours)
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@speedtest_bp.route('/benchmark', methods=['GET'])
@create_endpoint_limiter('critical')
def get_speed_benchmark():
    """Get speed benchmarks and ratings"""
    try:
        results = speed_test_service.get_recent_results(3)  # Use fewer results for more responsive ratings
        
        if not results:
            return jsonify({'error': 'No speed test results available for benchmarking'}), 404
        
        # Calculate averages from recent tests
        downloads = [r['download_mbps'] for r in results if r['success']]
        uploads = [r['upload_mbps'] for r in results if r['success']]
        pings = [r['ping_ms'] for r in results if r['success'] and r['ping_ms'] > 0]
        
        if not downloads:
            return jsonify({'error': 'No successful speed test results available. Run a speed test first.'}), 404
        
        avg_download = sum(downloads) / len(downloads)
        avg_upload = sum(uploads) / len(uploads)
        avg_ping = sum(pings) / len(pings) if pings else 0
        
        # Speed ratings based on common standards
        def get_speed_rating(speed_mbps, is_upload=False):
            if is_upload:
                if speed_mbps >= 50: return {'rating': 'excellent', 'color': '#28a745', 'description': 'Perfect for streaming, gaming, and large uploads'}
                elif speed_mbps >= 25: return {'rating': 'very_good', 'color': '#20c997', 'description': 'Great for video calls and file uploads'}
                elif speed_mbps >= 10: return {'rating': 'good', 'color': '#17a2b8', 'description': 'Good for basic uploads and video calls'}
                elif speed_mbps >= 5: return {'rating': 'fair', 'color': '#ffc107', 'description': 'Adequate for basic internet usage'}
                else: return {'rating': 'poor', 'color': '#dc3545', 'description': 'May struggle with uploads and video calls'}
            else:
                if speed_mbps >= 100: return {'rating': 'excellent', 'color': '#28a745', 'description': 'Perfect for 4K streaming, gaming, and multiple devices'}
                elif speed_mbps >= 50: return {'rating': 'very_good', 'color': '#20c997', 'description': 'Great for HD streaming and gaming'}
                elif speed_mbps >= 25: return {'rating': 'good', 'color': '#17a2b8', 'description': 'Good for streaming and general usage'}
                elif speed_mbps >= 10: return {'rating': 'fair', 'color': '#ffc107', 'description': 'Adequate for basic streaming and browsing'}
                else: return {'rating': 'poor', 'color': '#dc3545', 'description': 'May struggle with streaming and large downloads'}
        
        def get_ping_rating(ping_ms):
            if ping_ms <= 20: return {'rating': 'excellent', 'color': '#28a745', 'description': 'Perfect for gaming and real-time applications'}
            elif ping_ms <= 50: return {'rating': 'very_good', 'color': '#20c997', 'description': 'Great for gaming and video calls'}
            elif ping_ms <= 100: return {'rating': 'good', 'color': '#17a2b8', 'description': 'Good for general usage'}
            elif ping_ms <= 200: return {'rating': 'fair', 'color': '#ffc107', 'description': 'May notice delays in real-time applications'}
            else: return {'rating': 'poor', 'color': '#dc3545', 'description': 'Likely to experience noticeable delays'}
        
        download_rating = get_speed_rating(avg_download)
        upload_rating = get_speed_rating(avg_upload, is_upload=True)
        ping_rating = get_ping_rating(avg_ping) if avg_ping > 0 else {'rating': 'unknown', 'color': '#6c757d', 'description': 'No ping data available'}
        
        # Overall rating
        ratings_score = {
            'excellent': 5,
            'very_good': 4,
            'good': 3,
            'fair': 2,
            'poor': 1,
            'unknown': 0
        }
        
        overall_score = (
            ratings_score[download_rating['rating']] * 0.5 +  # 50% weight
            ratings_score[upload_rating['rating']] * 0.3 +    # 30% weight  
            ratings_score[ping_rating['rating']] * 0.2        # 20% weight
        )
        
        overall_rating = 'excellent' if overall_score >= 4.5 else \
                        'very_good' if overall_score >= 3.5 else \
                        'good' if overall_score >= 2.5 else \
                        'fair' if overall_score >= 1.5 else 'poor'
        
        return jsonify({
            'benchmark': {
                'download': {
                    'speed_mbps': round(avg_download, 2),
                    **download_rating
                },
                'upload': {
                    'speed_mbps': round(avg_upload, 2),
                    **upload_rating
                },
                'ping': {
                    'latency_ms': round(avg_ping, 2),
                    **ping_rating
                },
                'overall': {
                    'rating': overall_rating,
                    'score': round(overall_score, 1),
                    'color': {
                        'excellent': '#28a745',
                        'very_good': '#20c997', 
                        'good': '#17a2b8',
                        'fair': '#ffc107',
                        'poor': '#dc3545'
                    }[overall_rating]
                }
            },
            'based_on_tests': len(results),
            'latest_test': results[0]['timestamp'].isoformat() + 'Z'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@speedtest_bp.route('/install', methods=['POST'])
@create_endpoint_limiter('critical')
def install_speedtest_cli():
    """Install speedtest-cli if not available"""
    try:
        if speed_test_service.is_speedtest_available():
            return jsonify({
                'message': 'speedtest-cli is already available',
                'available': True
            })
        
        success = speed_test_service.install_speedtest_cli()
        
        if success:
            return jsonify({
                'message': 'speedtest-cli installed successfully',
                'available': True
            })
        else:
            return jsonify({
                'error': 'Failed to install speedtest-cli',
                'available': False,
                'note': 'You may need to install it manually: pip install speedtest-cli'
            }), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@speedtest_bp.route('/debug', methods=['POST'])
@create_endpoint_limiter('critical')
def debug_speedtest():
    """Debug endpoint to test speedtest execution directly"""
    try:
        import subprocess
        import time
        
        start_time = time.time()
        result = subprocess.run(['speedtest'], capture_output=True, text=True, timeout=90, shell=False)
        execution_time = time.time() - start_time
        
        return jsonify({
            'execution_time': execution_time,
            'return_code': result.returncode,
            'stdout_length': len(result.stdout),
            'stderr_length': len(result.stderr),
            'stdout_preview': result.stdout[:500] if result.stdout else '',
            'stderr_preview': result.stderr[:500] if result.stderr else '',
            'success': result.returncode == 0
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Debug speedtest timed out'}), 500
    except Exception as e:
        return jsonify({'error': f'Debug error: {str(e)}'}), 500