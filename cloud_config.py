# HomeNetMon Cloud Configuration Management
import os
import json
import yaml
import boto3
import base64
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from datetime import datetime, timedelta
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
import asyncio
from kubernetes import client, config as k8s_config
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)

class ConfigProvider(Enum):
    """Configuration provider types"""
    KUBERNETES_CONFIGMAP = "kubernetes_configmap"
    KUBERNETES_SECRET = "kubernetes_secret"
    AWS_PARAMETER_STORE = "aws_parameter_store"
    AWS_SECRETS_MANAGER = "aws_secrets_manager"
    AZURE_KEY_VAULT = "azure_key_vault"
    GCP_SECRET_MANAGER = "gcp_secret_manager"
    HASHICORP_VAULT = "hashicorp_vault"
    ENVIRONMENT_VARIABLES = "environment_variables"
    FILE_SYSTEM = "file_system"
    CONSUL = "consul"
    ETCD = "etcd"

@dataclass
class ConfigSource:
    """Configuration source definition"""
    provider: ConfigProvider
    path: str
    namespace: Optional[str] = None
    region: Optional[str] = None
    vault_addr: Optional[str] = None
    vault_token: Optional[str] = None
    refresh_interval: int = 300  # seconds
    cache_ttl: int = 600  # seconds
    encryption_key: Optional[str] = None
    priority: int = 100  # lower number = higher priority

@dataclass 
class ConfigValue:
    """Configuration value with metadata"""
    key: str
    value: Any
    source: ConfigProvider
    last_updated: datetime
    checksum: str
    encrypted: bool = False
    sensitive: bool = False

class CloudConfigManager:
    """Comprehensive cloud configuration management"""
    
    def __init__(self, sources: List[ConfigSource] = None):
        self.sources = sources or []
        self.config_cache: Dict[str, ConfigValue] = {}
        self.watchers: Dict[str, List[callable]] = {}
        self.refresh_timers: Dict[str, threading.Timer] = {}
        self.executor = ThreadPoolExecutor(max_workers=5)
        self._lock = threading.RLock()
        
        # Initialize cloud provider clients
        self._init_cloud_clients()
        self._init_kubernetes_client()
        
        # Load initial configuration
        self.refresh_all_configs()
        
    def _init_cloud_clients(self):
        """Initialize cloud provider clients"""
        try:
            # AWS clients
            self.ssm_client = boto3.client('ssm')
            self.secrets_manager_client = boto3.client('secretsmanager')
            logger.info("AWS clients initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize AWS clients: {e}")
            self.ssm_client = None
            self.secrets_manager_client = None
            
        try:
            # GCP clients (would need google-cloud-secret-manager)
            # from google.cloud import secretmanager
            # self.gcp_client = secretmanager.SecretManagerServiceClient()
            pass
        except Exception as e:
            logger.warning(f"Failed to initialize GCP clients: {e}")
            
        try:
            # Azure clients (would need azure-keyvault-secrets)
            # from azure.keyvault.secrets import SecretClient
            # self.azure_client = SecretClient(vault_url, credential)
            pass
        except Exception as e:
            logger.warning(f"Failed to initialize Azure clients: {e}")
    
    def _init_kubernetes_client(self):
        """Initialize Kubernetes client"""
        try:
            # Try in-cluster config first
            k8s_config.load_incluster_config()
            logger.info("Using in-cluster Kubernetes configuration")
        except k8s_config.ConfigException:
            try:
                # Fall back to local kubeconfig
                k8s_config.load_kube_config()
                logger.info("Using local Kubernetes configuration")
            except k8s_config.ConfigException as e:
                logger.warning(f"Failed to load Kubernetes configuration: {e}")
                self.k8s_v1 = None
                return
                
        self.k8s_v1 = client.CoreV1Api()
        logger.info("Kubernetes client initialized")
    
    def add_source(self, source: ConfigSource):
        """Add a configuration source"""
        with self._lock:
            self.sources.append(source)
            self.sources.sort(key=lambda s: s.priority)
            
        # Start watching this source
        self._start_watching_source(source)
        
        # Load initial config from this source
        self._load_config_from_source(source)
    
    def remove_source(self, provider: ConfigProvider, path: str):
        """Remove a configuration source"""
        with self._lock:
            self.sources = [s for s in self.sources 
                          if not (s.provider == provider and s.path == path)]
        
        # Stop watching
        source_key = f"{provider.value}:{path}"
        if source_key in self.refresh_timers:
            self.refresh_timers[source_key].cancel()
            del self.refresh_timers[source_key]
    
    def get_config(self, key: str, default: Any = None, decrypt: bool = True) -> Any:
        """Get configuration value with fallback to sources"""
        with self._lock:
            # Check cache first
            if key in self.config_cache:
                config_value = self.config_cache[key]
                if config_value.encrypted and decrypt:
                    return self._decrypt_value(config_value.value)
                return config_value.value
            
            # Try loading from sources
            for source in self.sources:
                try:
                    value = self._load_single_config(source, key)
                    if value is not None:
                        return value
                except Exception as e:
                    logger.warning(f"Failed to load {key} from {source.provider}: {e}")
                    continue
                    
            return default
    
    def set_config(self, key: str, value: Any, provider: ConfigProvider = None, 
                  encrypt: bool = False, sensitive: bool = False):
        """Set configuration value"""
        if encrypt:
            encrypted_value = self._encrypt_value(value)
        else:
            encrypted_value = value
            
        checksum = hashlib.sha256(str(value).encode()).hexdigest()
        
        config_value = ConfigValue(
            key=key,
            value=encrypted_value,
            source=provider or ConfigProvider.ENVIRONMENT_VARIABLES,
            last_updated=datetime.utcnow(),
            checksum=checksum,
            encrypted=encrypt,
            sensitive=sensitive
        )
        
        with self._lock:
            self.config_cache[key] = config_value
            
        # Notify watchers
        self._notify_watchers(key, value)
        
        # Optionally persist to source
        if provider:
            self._persist_to_source(key, config_value, provider)
    
    def watch_config(self, key: str, callback: callable):
        """Watch for configuration changes"""
        with self._lock:
            if key not in self.watchers:
                self.watchers[key] = []
            self.watchers[key].append(callback)
    
    def unwatch_config(self, key: str, callback: callable):
        """Stop watching configuration changes"""
        with self._lock:
            if key in self.watchers:
                self.watchers[key].remove(callback)
                if not self.watchers[key]:
                    del self.watchers[key]
    
    def refresh_all_configs(self):
        """Refresh all configurations from sources"""
        for source in self.sources:
            self.executor.submit(self._load_config_from_source, source)
    
    def _load_config_from_source(self, source: ConfigSource):
        """Load configuration from a specific source"""
        try:
            if source.provider == ConfigProvider.KUBERNETES_CONFIGMAP:
                self._load_from_k8s_configmap(source)
            elif source.provider == ConfigProvider.KUBERNETES_SECRET:
                self._load_from_k8s_secret(source)
            elif source.provider == ConfigProvider.AWS_PARAMETER_STORE:
                self._load_from_aws_parameter_store(source)
            elif source.provider == ConfigProvider.AWS_SECRETS_MANAGER:
                self._load_from_aws_secrets_manager(source)
            elif source.provider == ConfigProvider.ENVIRONMENT_VARIABLES:
                self._load_from_environment(source)
            elif source.provider == ConfigProvider.FILE_SYSTEM:
                self._load_from_file_system(source)
            else:
                logger.warning(f"Unsupported config provider: {source.provider}")
                
        except Exception as e:
            logger.error(f"Failed to load config from {source.provider}:{source.path}: {e}")
    
    def _load_from_k8s_configmap(self, source: ConfigSource):
        """Load configuration from Kubernetes ConfigMap"""
        if not self.k8s_v1:
            return
            
        try:
            namespace = source.namespace or 'default'
            configmap = self.k8s_v1.read_namespaced_config_map(
                name=source.path,
                namespace=namespace
            )
            
            if configmap.data:
                for key, value in configmap.data.items():
                    self._update_config_cache(key, value, source)
                    
        except ApiException as e:
            if e.status != 404:  # Don't log 404 errors
                logger.error(f"Failed to read ConfigMap {source.path}: {e}")
    
    def _load_from_k8s_secret(self, source: ConfigSource):
        """Load configuration from Kubernetes Secret"""
        if not self.k8s_v1:
            return
            
        try:
            namespace = source.namespace or 'default'
            secret = self.k8s_v1.read_namespaced_secret(
                name=source.path,
                namespace=namespace
            )
            
            if secret.data:
                for key, value in secret.data.items():
                    # Decode base64 encoded secret data
                    decoded_value = base64.b64decode(value).decode('utf-8')
                    self._update_config_cache(key, decoded_value, source, sensitive=True)
                    
        except ApiException as e:
            if e.status != 404:
                logger.error(f"Failed to read Secret {source.path}: {e}")
    
    def _load_from_aws_parameter_store(self, source: ConfigSource):
        """Load configuration from AWS Parameter Store"""
        if not self.ssm_client:
            return
            
        try:
            # Get parameters by path
            paginator = self.ssm_client.get_paginator('get_parameters_by_path')
            
            for page in paginator.paginate(
                Path=source.path,
                Recursive=True,
                WithDecryption=True
            ):
                for param in page['Parameters']:
                    # Remove path prefix from parameter name
                    key = param['Name'].replace(source.path, '').lstrip('/')
                    value = param['Value']
                    
                    sensitive = param['Type'] == 'SecureString'
                    self._update_config_cache(key, value, source, sensitive=sensitive)
                    
        except Exception as e:
            logger.error(f"Failed to load from Parameter Store {source.path}: {e}")
    
    def _load_from_aws_secrets_manager(self, source: ConfigSource):
        """Load configuration from AWS Secrets Manager"""
        if not self.secrets_manager_client:
            return
            
        try:
            response = self.secrets_manager_client.get_secret_value(
                SecretId=source.path
            )
            
            secret_string = response['SecretString']
            
            # Try to parse as JSON
            try:
                secret_data = json.loads(secret_string)
                if isinstance(secret_data, dict):
                    for key, value in secret_data.items():
                        self._update_config_cache(key, value, source, sensitive=True)
                else:
                    # Single value secret
                    key = source.path.split('/')[-1]
                    self._update_config_cache(key, secret_string, source, sensitive=True)
            except json.JSONDecodeError:
                # Not JSON, treat as single value
                key = source.path.split('/')[-1]
                self._update_config_cache(key, secret_string, source, sensitive=True)
                
        except Exception as e:
            logger.error(f"Failed to load from Secrets Manager {source.path}: {e}")
    
    def _load_from_environment(self, source: ConfigSource):
        """Load configuration from environment variables"""
        # Load all environment variables or specific prefix
        env_vars = dict(os.environ)
        
        if source.path:
            # Filter by prefix
            prefix = source.path.rstrip('_') + '_'
            filtered_vars = {
                k.replace(prefix, ''): v 
                for k, v in env_vars.items() 
                if k.startswith(prefix)
            }
        else:
            filtered_vars = env_vars
            
        for key, value in filtered_vars.items():
            self._update_config_cache(key, value, source)
    
    def _load_from_file_system(self, source: ConfigSource):
        """Load configuration from file system"""
        try:
            file_path = source.path
            
            if file_path.endswith(('.yaml', '.yml')):
                with open(file_path, 'r') as f:
                    data = yaml.safe_load(f)
            elif file_path.endswith('.json'):
                with open(file_path, 'r') as f:
                    data = json.load(f)
            else:
                # Plain text file
                with open(file_path, 'r') as f:
                    data = {os.path.basename(file_path): f.read().strip()}
            
            if isinstance(data, dict):
                for key, value in data.items():
                    self._update_config_cache(key, value, source)
                    
        except Exception as e:
            logger.error(f"Failed to load from file {source.path}: {e}")
    
    def _load_single_config(self, source: ConfigSource, key: str) -> Any:
        """Load a single configuration value from source"""
        if source.provider == ConfigProvider.ENVIRONMENT_VARIABLES:
            env_key = f"{source.path}_{key}" if source.path else key
            return os.getenv(env_key)
        
        # For other providers, we'd need to implement single-key lookup
        # For now, trigger full reload
        self._load_config_from_source(source)
        
        with self._lock:
            if key in self.config_cache:
                return self.config_cache[key].value
        
        return None
    
    def _update_config_cache(self, key: str, value: Any, source: ConfigSource, 
                           sensitive: bool = False):
        """Update configuration cache with new value"""
        checksum = hashlib.sha256(str(value).encode()).hexdigest()
        
        config_value = ConfigValue(
            key=key,
            value=value,
            source=source.provider,
            last_updated=datetime.utcnow(),
            checksum=checksum,
            encrypted=False,
            sensitive=sensitive
        )
        
        with self._lock:
            # Check if value changed
            old_value = self.config_cache.get(key)
            if old_value and old_value.checksum == checksum:
                return  # No change
                
            self.config_cache[key] = config_value
            
        # Notify watchers of change
        self._notify_watchers(key, value)
        
        logger.debug(f"Updated config: {key} from {source.provider.value}")
    
    def _notify_watchers(self, key: str, value: Any):
        """Notify watchers of configuration changes"""
        with self._lock:
            watchers = self.watchers.get(key, [])
            
        for callback in watchers:
            try:
                callback(key, value)
            except Exception as e:
                logger.error(f"Error in config watcher callback: {e}")
    
    def _start_watching_source(self, source: ConfigSource):
        """Start watching a configuration source for changes"""
        if source.refresh_interval <= 0:
            return
            
        def refresh_source():
            self._load_config_from_source(source)
            # Schedule next refresh
            timer = threading.Timer(source.refresh_interval, refresh_source)
            timer.daemon = True
            timer.start()
            
            source_key = f"{source.provider.value}:{source.path}"
            self.refresh_timers[source_key] = timer
        
        # Start initial timer
        timer = threading.Timer(source.refresh_interval, refresh_source)
        timer.daemon = True
        timer.start()
        
        source_key = f"{source.provider.value}:{source.path}"
        self.refresh_timers[source_key] = timer
    
    def _encrypt_value(self, value: str) -> str:
        """Encrypt configuration value"""
        # Implement encryption logic here
        # For now, just base64 encode
        return base64.b64encode(str(value).encode()).decode()
    
    def _decrypt_value(self, encrypted_value: str) -> str:
        """Decrypt configuration value"""
        # Implement decryption logic here
        # For now, just base64 decode
        try:
            return base64.b64decode(encrypted_value).decode()
        except Exception:
            return encrypted_value  # Return as-is if not encrypted
    
    def _persist_to_source(self, key: str, config_value: ConfigValue, 
                          provider: ConfigProvider):
        """Persist configuration value to source"""
        # Implementation would depend on the provider
        # This is a placeholder for write-back functionality
        logger.info(f"Persisting {key} to {provider.value}")
    
    def get_all_configs(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Get all configuration values"""
        with self._lock:
            result = {}
            for key, config_value in self.config_cache.items():
                if config_value.sensitive and not include_sensitive:
                    result[key] = "***SENSITIVE***"
                else:
                    value = config_value.value
                    if config_value.encrypted:
                        value = self._decrypt_value(value)
                    result[key] = value
            return result
    
    def export_config(self, format: str = 'json') -> str:
        """Export configuration in specified format"""
        configs = self.get_all_configs(include_sensitive=False)
        
        if format.lower() == 'json':
            return json.dumps(configs, indent=2, default=str)
        elif format.lower() in ['yaml', 'yml']:
            return yaml.dump(configs, default_flow_style=False)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def health_check(self) -> Dict[str, Any]:
        """Check health of configuration sources"""
        health = {
            'status': 'healthy',
            'sources': {},
            'cache_size': len(self.config_cache),
            'last_refresh': datetime.utcnow().isoformat()
        }
        
        for source in self.sources:
            source_key = f"{source.provider.value}:{source.path}"
            try:
                # Test connectivity to source
                if source.provider == ConfigProvider.KUBERNETES_CONFIGMAP:
                    if self.k8s_v1:
                        health['sources'][source_key] = 'healthy'
                    else:
                        health['sources'][source_key] = 'unavailable'
                elif source.provider == ConfigProvider.AWS_PARAMETER_STORE:
                    if self.ssm_client:
                        health['sources'][source_key] = 'healthy'
                    else:
                        health['sources'][source_key] = 'unavailable'
                else:
                    health['sources'][source_key] = 'unknown'
                    
            except Exception as e:
                health['sources'][source_key] = f'error: {str(e)}'
                health['status'] = 'degraded'
        
        return health
    
    def cleanup(self):
        """Cleanup resources"""
        # Cancel all timers
        for timer in self.refresh_timers.values():
            timer.cancel()
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        logger.info("Cloud config manager cleaned up")


# Factory function for easy initialization
def create_cloud_config_manager() -> CloudConfigManager:
    """Create and configure cloud config manager based on environment"""
    sources = []
    
    # Kubernetes sources (if running in cluster)
    if os.getenv('KUBERNETES_SERVICE_HOST'):
        sources.extend([
            ConfigSource(
                provider=ConfigProvider.KUBERNETES_CONFIGMAP,
                path='homenetmon-config',
                namespace=os.getenv('POD_NAMESPACE', 'homenetmon'),
                refresh_interval=300,
                priority=10
            ),
            ConfigSource(
                provider=ConfigProvider.KUBERNETES_SECRET,
                path='homenetmon-secrets',
                namespace=os.getenv('POD_NAMESPACE', 'homenetmon'),
                refresh_interval=600,
                priority=5
            )
        ])
    
    # AWS sources (if AWS credentials available)
    if os.getenv('AWS_ACCESS_KEY_ID') or os.getenv('AWS_PROFILE'):
        sources.extend([
            ConfigSource(
                provider=ConfigProvider.AWS_PARAMETER_STORE,
                path='/homenetmon/',
                region=os.getenv('AWS_REGION', 'us-west-2'),
                refresh_interval=300,
                priority=20
            )
        ])
    
    # Environment variables (always available)
    sources.append(
        ConfigSource(
            provider=ConfigProvider.ENVIRONMENT_VARIABLES,
            path='HOMENETMON',  # prefix
            refresh_interval=0,  # No refresh needed
            priority=30
        )
    )
    
    # File system config (if exists)
    config_file = os.getenv('HOMENETMON_CONFIG_FILE', '/etc/homenetmon/config.yaml')
    if os.path.exists(config_file):
        sources.append(
            ConfigSource(
                provider=ConfigProvider.FILE_SYSTEM,
                path=config_file,
                refresh_interval=60,
                priority=40
            )
        )
    
    return CloudConfigManager(sources)


# Global instance
_config_manager = None

def get_config_manager() -> CloudConfigManager:
    """Get global configuration manager instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = create_cloud_config_manager()
    return _config_manager

def get_config(key: str, default: Any = None) -> Any:
    """Convenience function to get configuration value"""
    return get_config_manager().get_config(key, default)

def set_config(key: str, value: Any, **kwargs):
    """Convenience function to set configuration value"""
    return get_config_manager().set_config(key, value, **kwargs)

def watch_config(key: str, callback: callable):
    """Convenience function to watch configuration changes"""
    return get_config_manager().watch_config(key, callback)