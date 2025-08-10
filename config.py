import os
import yaml
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Config:
    BASE_DIR = Path(__file__).parent.absolute()
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f"sqlite:///{BASE_DIR}/homeNetMon.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Network Configuration
    NETWORK_RANGE = os.environ.get('NETWORK_RANGE', '192.168.86.0/24')
    PING_INTERVAL = int(os.environ.get('PING_INTERVAL', '30'))
    SCAN_INTERVAL = int(os.environ.get('SCAN_INTERVAL', '300'))
    
    # Monitoring Settings
    PING_TIMEOUT = float(os.environ.get('PING_TIMEOUT', '3.0'))
    MAX_WORKERS = int(os.environ.get('MAX_WORKERS', '50'))
    DATA_RETENTION_DAYS = int(os.environ.get('DATA_RETENTION_DAYS', '30'))
    
    # Web Interface
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', '5000'))
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Alert Settings
    SMTP_SERVER = os.environ.get('SMTP_SERVER')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
    SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', 'True').lower() == 'true'
    ALERT_FROM_EMAIL = os.environ.get('ALERT_FROM_EMAIL')
    ALERT_TO_EMAILS = os.environ.get('ALERT_TO_EMAILS', '').split(',') if os.environ.get('ALERT_TO_EMAILS') else []
    
    # Webhook Settings
    WEBHOOK_URL = os.environ.get('WEBHOOK_URL')
    WEBHOOK_TIMEOUT = int(os.environ.get('WEBHOOK_TIMEOUT', '10'))
    
    # Push Notification Settings (Ntfy)
    NTFY_TOPIC = os.environ.get('NTFY_TOPIC')
    NTFY_SERVER = os.environ.get('NTFY_SERVER', 'https://ntfy.sh')
    NTFY_USERNAME = os.environ.get('NTFY_USERNAME')
    NTFY_PASSWORD = os.environ.get('NTFY_PASSWORD')
    NTFY_ENABLED = os.environ.get('NTFY_ENABLED', 'False').lower() == 'true'
    
    @classmethod
    def load_from_file(cls, config_file='config.yaml'):
        config_path = cls.BASE_DIR / config_file
        if config_path.exists():
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)
                
            # Update class attributes with YAML data
            for key, value in config_data.items():
                if hasattr(cls, key.upper()):
                    setattr(cls, key.upper(), value)
    
    @classmethod
    def save_to_file(cls, config_file='config.yaml'):
        config_path = cls.BASE_DIR / config_file
        config_data = {
            'network_range': cls.NETWORK_RANGE,
            'ping_interval': cls.PING_INTERVAL,
            'scan_interval': cls.SCAN_INTERVAL,
            'ping_timeout': cls.PING_TIMEOUT,
            'max_workers': cls.MAX_WORKERS,
            'data_retention_days': cls.DATA_RETENTION_DAYS,
            'host': cls.HOST,
            'port': cls.PORT,
            'debug': cls.DEBUG,
            'smtp_server': cls.SMTP_SERVER,
            'smtp_port': cls.SMTP_PORT,
            'smtp_username': cls.SMTP_USERNAME,
            'smtp_use_tls': cls.SMTP_USE_TLS,
            'alert_from_email': cls.ALERT_FROM_EMAIL,
            'alert_to_emails': cls.ALERT_TO_EMAILS,
            'webhook_url': cls.WEBHOOK_URL,
            'webhook_timeout': cls.WEBHOOK_TIMEOUT,
        }
        
        with open(config_path, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False, indent=2)

# Load configuration from file if it exists
Config.load_from_file()