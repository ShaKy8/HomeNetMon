/**
 * HomeNetMon SDK TypeScript Definitions
 * 
 * @version 1.0.0
 */

export interface SDKConfig {
    baseUrl?: string;
    apiVersion?: string;
    apiKey?: string;
    sessionToken?: string;
    timeout?: number;
    retryAttempts?: number;
    retryDelay?: number;
    enableCompression?: boolean;
    enableOffline?: boolean;
    syncInterval?: number;
    debugMode?: boolean;
}

export interface Device {
    id: number;
    display_name: string;
    ip_address: string;
    mac_address: string;
    device_type: string;
    status: 'up' | 'down' | 'unknown';
    last_seen: string | null;
    uptime_percentage: number;
    latest_response_time: number;
    active_alerts: number;
    device_group: string | null;
    created_at: string;
    vendor: string | null;
    description?: string;
    monitoring_enabled?: boolean;
}

export interface DeviceMetrics {
    avg_response_time: number;
    min_response_time: number;
    max_response_time: number;
    avg_packet_loss: number;
    total_checks: number;
    period_hours: number;
}

export interface DeviceDetails extends Device {
    recent_metrics: MonitoringData[];
    recent_alerts: Alert[];
    performance_summary: PerformanceSummary | null;
    metrics?: DeviceMetrics;
}

export interface MonitoringData {
    timestamp: string;
    response_time: number;
    packet_loss: number;
    status: string;
}

export interface Alert {
    id: number;
    device_id: number;
    severity: 'low' | 'medium' | 'high' | 'critical';
    message: string;
    created_at: string;
    acknowledged: boolean;
    acknowledged_at?: string;
    acknowledged_by?: string;
}

export interface PerformanceSummary {
    uptime_percentage: number;
    total_checks: number;
    status_distribution: Record<string, {count: number; percentage: number}>;
    period_hours: number;
}

export interface DevicesResponse {
    success: boolean;
    devices: Device[];
    pagination: {
        page: number;
        per_page: number;
        total: number;
        pages: number;
        has_prev: boolean;
        has_next: boolean;
    };
    filters: {
        status?: string;
        device_type?: string;
        search?: string;
    };
    timestamp: string;
}

export interface DeviceResponse {
    success: boolean;
    device: DeviceDetails;
    timestamp: string;
}

export interface NetworkSummary {
    total_devices: number;
    status_distribution: Record<string, {count: number; percentage: number}>;
    alert_summary: Record<string, number>;
    network_performance: {
        avg_response_time: number;
        period: string;
    };
    problematic_devices: Array<{
        id: number;
        name: string;
        ip: string;
        alerts: number;
        status: string;
    }>;
}

export interface NetworkSummaryResponse {
    success: boolean;
    summary: NetworkSummary;
    timestamp: string;
    cache_duration: number;
}

export interface DeltaSync {
    devices?: {
        updated: Device[];
        count: number;
    };
    alerts?: {
        new: Alert[];
        updated: Alert[];
        new_count: number;
        updated_count: number;
    };
    monitoring?: {
        data: MonitoringData[];
        count: number;
    };
}

export interface DeltaSyncResponse {
    success: boolean;
    delta: DeltaSync;
    sync_timestamp: string;
    last_sync: string;
    has_more: boolean;
}

export interface OfflineAction {
    type: string;
    timestamp: string;
    id: string;
    [key: string]: any;
}

export interface BatchSyncResponse {
    success: boolean;
    results: Array<{
        index: number;
        success: boolean;
        result?: any;
        error?: string;
        operation?: string;
    }>;
    processed: number;
    successful: number;
    failed: number;
    timestamp: string;
}

export interface MobileConfig {
    app_version: string;
    api_version: string;
    features: {
        push_notifications: boolean;
        offline_mode: boolean;
        real_time_sync: boolean;
        device_control: boolean;
    };
    sync_intervals: {
        devices: number;
        alerts: number;
        monitoring: number;
    };
    ui_config: {
        theme: string;
        card_layout: string;
        show_charts: boolean;
        refresh_indicator: boolean;
    };
    limits: {
        max_devices_per_request: number;
        max_monitoring_points: number;
        cache_duration: number;
    };
}

export interface MobileConfigResponse {
    success: boolean;
    config: MobileConfig;
    user: {
        username: string;
        role: string;
        permissions: string[];
    };
    timestamp: string;
}

export interface LoginResponse {
    success?: boolean;
    user?: {
        id: string;
        username: string;
        role: string;
    };
    session_token?: string;
    expires_at?: string;
    requires_mfa?: boolean;
    user_id?: string;
    error?: string;
}

export interface GetDevicesOptions {
    page?: number;
    perPage?: number;
    status?: string;
    deviceType?: string;
    search?: string;
    includeMetrics?: boolean;
}

export interface GetDeviceOptions {
    hours?: number;
}

export interface GetAlertsOptions {
    page?: number;
    perPage?: number;
    severity?: string;
    acknowledged?: boolean;
    deviceId?: number;
    since?: string;
}

export interface DeltaSyncOptions {
    includeDevices?: boolean;
    includeAlerts?: boolean;
    includeMonitoring?: boolean;
}

export type EventType = 
    | 'authenticated'
    | 'authenticationError'
    | 'logout'
    | 'online'
    | 'offline'
    | 'devicesUpdated'
    | 'alertsUpdated'
    | 'monitoringUpdated'
    | 'offlineAction'
    | 'offlineSyncComplete'
    | 'autoSyncComplete'
    | 'autoSyncError';

export type EventCallback<T = any> = (data?: T) => void;

export interface APIResponse {
    success: boolean;
    error?: string;
    code?: string;
    message?: string;
    [key: string]: any;
}

declare class HomeNetMonSDK {
    public baseUrl: string;
    public apiVersion: string;
    public apiKey: string | null;
    public sessionToken: string | null;
    public config: Required<SDKConfig>;
    public isOnline: boolean;
    public lastSyncTime: string | null;
    public syncInProgress: boolean;
    public offlineQueue: OfflineAction[];

    constructor(config?: SDKConfig);

    // Authentication
    login(username: string, password: string, mfaToken?: string | null, rememberMe?: boolean): Promise<LoginResponse>;
    logout(): Promise<void>;
    setApiKey(apiKey: string): void;
    isAuthenticated(): boolean;

    // Device Management
    getDevices(options?: GetDevicesOptions): Promise<DevicesResponse>;
    getDevice(deviceId: number, options?: GetDeviceOptions): Promise<DeviceResponse>;
    pingDevice(deviceId: number): Promise<APIResponse>;
    updateDevice(deviceId: number, updates: Partial<Device>): Promise<APIResponse>;

    // Alert Management
    getAlerts(options?: GetAlertsOptions): Promise<APIResponse>;
    acknowledgeAlert(alertId: number): Promise<APIResponse>;

    // Real-time Data Sync
    getDeltaSync(options?: DeltaSyncOptions): Promise<DeltaSyncResponse>;
    syncOfflineQueue(): Promise<BatchSyncResponse>;
    getNetworkSummary(cacheMinutes?: number): Promise<NetworkSummaryResponse>;

    // Configuration
    getMobileConfig(): Promise<MobileConfigResponse>;
    updateConfig(newConfig: Partial<SDKConfig>): void;

    // Offline Support
    queueOfflineAction(type: string, data: Record<string, any>): APIResponse;
    getCachedDevices(): Device[];
    isDataAvailableOffline(type: string, id?: number): boolean;

    // Event Management
    on<T = any>(event: EventType, callback: EventCallback<T>): void;
    off<T = any>(event: EventType, callback: EventCallback<T>): void;
    emit<T = any>(event: EventType, data?: T): void;

    // Utility
    destroy(): void;
}

export default HomeNetMonSDK;
export { HomeNetMonSDK };