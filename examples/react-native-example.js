/**
 * HomeNetMon React Native Integration Example
 * 
 * This example demonstrates how to integrate HomeNetMon SDK
 * into a React Native application with offline support,
 * real-time updates, and mobile-optimized UI.
 */

import React, { useState, useEffect, useContext, createContext } from 'react';
import {
    View,
    Text,
    FlatList,
    TouchableOpacity,
    StyleSheet,
    RefreshControl,
    Alert,
    StatusBar,
    SafeAreaView,
    ActivityIndicator,
    TextInput,
    Switch
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import NetInfo from '@react-native-community/netinfo';
import { HomeNetMonSDK } from '../sdk/homenetmon-sdk';

// ============================================================================
// SDK Context and Provider
// ============================================================================

const HomeNetMonContext = createContext();

export const HomeNetMonProvider = ({ children, config }) => {
    const [sdk, setSdk] = useState(null);
    const [isOnline, setIsOnline] = useState(true);
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [user, setUser] = useState(null);

    useEffect(() => {
        initializeSDK();
        setupNetworkListener();
    }, []);

    const initializeSDK = async () => {
        try {
            // Get stored config
            const storedConfig = await AsyncStorage.getItem('homenetmon_config');
            const defaultConfig = {
                baseUrl: 'https://your-homenetmon-instance.com',
                enableOffline: true,
                syncInterval: 30000,
                debugMode: __DEV__,
                ...config,
                ...(storedConfig ? JSON.parse(storedConfig) : {})
            };

            const sdkInstance = new HomeNetMonSDK(defaultConfig);

            // Setup event listeners
            sdkInstance.on('authenticated', (userData) => {
                setIsAuthenticated(true);
                setUser(userData);
            });

            sdkInstance.on('logout', () => {
                setIsAuthenticated(false);
                setUser(null);
            });

            sdkInstance.on('online', () => {
                setIsOnline(true);
            });

            sdkInstance.on('offline', () => {
                setIsOnline(false);
            });

            setSdk(sdkInstance);

        } catch (error) {
            console.error('Failed to initialize SDK:', error);
        }
    };

    const setupNetworkListener = () => {
        const unsubscribe = NetInfo.addEventListener(state => {
            setIsOnline(state.isConnected);
        });

        return () => unsubscribe();
    };

    return (
        <HomeNetMonContext.Provider value={{
            sdk,
            isOnline,
            isAuthenticated,
            user
        }}>
            {children}
        </HomeNetMonContext.Provider>
    );
};

export const useHomeNetMon = () => {
    const context = useContext(HomeNetMonContext);
    if (!context) {
        throw new Error('useHomeNetMon must be used within HomeNetMonProvider');
    }
    return context;
};

// ============================================================================
// Login Screen Component
// ============================================================================

const LoginScreen = ({ onLoginSuccess }) => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [serverUrl, setServerUrl] = useState('');
    const { sdk } = useHomeNetMon();

    const handleLogin = async () => {
        if (!username || !password) {
            Alert.alert('Error', 'Please enter username and password');
            return;
        }

        setLoading(true);

        try {
            // Update server URL if provided
            if (serverUrl && serverUrl !== sdk.baseUrl) {
                sdk.baseUrl = serverUrl;
                await AsyncStorage.setItem('homenetmon_config', JSON.stringify({ baseUrl: serverUrl }));
            }

            const response = await sdk.login(username, password);

            if (response.requires_mfa) {
                // Handle MFA flow
                handleMFARequired(response.user_id);
            } else if (response.success) {
                onLoginSuccess();
            } else {
                Alert.alert('Login Failed', response.error || 'Invalid credentials');
            }

        } catch (error) {
            Alert.alert('Login Error', error.message);
        } finally {
            setLoading(false);
        }
    };

    const handleMFARequired = (userId) => {
        Alert.prompt(
            'Two-Factor Authentication',
            'Enter your 6-digit verification code:',
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Verify',
                    onPress: async (mfaCode) => {
                        try {
                            const response = await sdk.login(username, password, mfaCode);
                            if (response.success) {
                                onLoginSuccess();
                            } else {
                                Alert.alert('Verification Failed', 'Invalid verification code');
                            }
                        } catch (error) {
                            Alert.alert('Verification Error', error.message);
                        }
                    }
                }
            ],
            'plain-text'
        );
    };

    return (
        <SafeAreaView style={styles.container}>
            <View style={styles.loginContainer}>
                <Text style={styles.title}>HomeNetMon</Text>
                
                <TextInput
                    style={styles.input}
                    placeholder="Server URL (optional)"
                    value={serverUrl}
                    onChangeText={setServerUrl}
                    autoCapitalize="none"
                    autoCorrect={false}
                />

                <TextInput
                    style={styles.input}
                    placeholder="Username"
                    value={username}
                    onChangeText={setUsername}
                    autoCapitalize="none"
                    autoCorrect={false}
                />

                <TextInput
                    style={styles.input}
                    placeholder="Password"
                    value={password}
                    onChangeText={setPassword}
                    secureTextEntry
                />

                <TouchableOpacity
                    style={[styles.loginButton, loading && styles.loginButtonDisabled]}
                    onPress={handleLogin}
                    disabled={loading}
                >
                    {loading ? (
                        <ActivityIndicator color="white" />
                    ) : (
                        <Text style={styles.loginButtonText}>Login</Text>
                    )}
                </TouchableOpacity>
            </View>
        </SafeAreaView>
    );
};

// ============================================================================
// Device List Component
// ============================================================================

const DeviceList = () => {
    const [devices, setDevices] = useState([]);
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [filter, setFilter] = useState('all');
    const { sdk, isOnline } = useHomeNetMon();

    useEffect(() => {
        loadDevices();
        setupRealTimeUpdates();
    }, []);

    const loadDevices = async (showLoading = true) => {
        try {
            if (showLoading) setLoading(true);

            const response = await sdk.getDevices({
                includeMetrics: true,
                status: filter === 'all' ? undefined : filter
            });

            if (response.success) {
                setDevices(response.devices);
            } else if (!isOnline) {
                // Load cached devices when offline
                const cachedDevices = sdk.getCachedDevices();
                setDevices(cachedDevices);
            }

        } catch (error) {
            console.error('Failed to load devices:', error);
            
            // Try to load cached data on error
            if (!isOnline) {
                const cachedDevices = sdk.getCachedDevices();
                setDevices(cachedDevices);
            }
        } finally {
            setLoading(false);
            setRefreshing(false);
        }
    };

    const setupRealTimeUpdates = () => {
        sdk.on('devicesUpdated', (updatedDevices) => {
            setDevices(prevDevices => {
                const deviceMap = new Map(prevDevices.map(d => [d.id, d]));
                
                updatedDevices.updated.forEach(device => {
                    deviceMap.set(device.id, device);
                });
                
                return Array.from(deviceMap.values());
            });
        });
    };

    const handleRefresh = () => {
        setRefreshing(true);
        loadDevices(false);
    };

    const handleDevicePress = async (device) => {
        try {
            const response = await sdk.getDevice(device.id, { hours: 24 });
            
            // Navigate to device details screen
            // Navigation.navigate('DeviceDetails', { device: response.device });
            
        } catch (error) {
            Alert.alert('Error', 'Failed to load device details');
        }
    };

    const handlePingDevice = async (deviceId) => {
        try {
            const response = await sdk.pingDevice(deviceId);
            
            if (response.success) {
                Alert.alert('Success', response.message);
            } else {
                Alert.alert('Error', response.error || 'Failed to ping device');
            }
        } catch (error) {
            Alert.alert('Error', 'Failed to ping device');
        }
    };

    const renderDeviceItem = ({ item: device }) => (
        <TouchableOpacity
            style={styles.deviceCard}
            onPress={() => handleDevicePress(device)}
        >
            <View style={styles.deviceHeader}>
                <Text style={styles.deviceName}>{device.display_name}</Text>
                <View style={[styles.statusIndicator, { backgroundColor: getStatusColor(device.status) }]} />
            </View>
            
            <Text style={styles.deviceIp}>{device.ip_address}</Text>
            
            <View style={styles.deviceStats}>
                <Text style={styles.deviceStat}>
                    Uptime: {device.uptime_percentage}%
                </Text>
                <Text style={styles.deviceStat}>
                    Response: {device.latest_response_time}ms
                </Text>
            </View>
            
            {device.active_alerts > 0 && (
                <View style={styles.alertBadge}>
                    <Text style={styles.alertText}>{device.active_alerts} alerts</Text>
                </View>
            )}
            
            <TouchableOpacity
                style={styles.pingButton}
                onPress={() => handlePingDevice(device.id)}
            >
                <Text style={styles.pingButtonText}>Ping</Text>
            </TouchableOpacity>
        </TouchableOpacity>
    );

    const getStatusColor = (status) => {
        switch (status) {
            case 'up': return '#4CAF50';
            case 'down': return '#F44336';
            default: return '#FF9800';
        }
    };

    if (loading) {
        return (
            <View style={styles.centerContainer}>
                <ActivityIndicator size="large" color="#007AFF" />
                <Text style={styles.loadingText}>Loading devices...</Text>
            </View>
        );
    }

    return (
        <View style={styles.container}>
            <View style={styles.header}>
                <Text style={styles.headerTitle}>Devices</Text>
                <View style={styles.connectionStatus}>
                    <View style={[styles.connectionDot, { backgroundColor: isOnline ? '#4CAF50' : '#F44336' }]} />
                    <Text style={styles.connectionText}>{isOnline ? 'Online' : 'Offline'}</Text>
                </View>
            </View>

            <View style={styles.filterContainer}>
                <TouchableOpacity
                    style={[styles.filterButton, filter === 'all' && styles.filterButtonActive]}
                    onPress={() => setFilter('all')}
                >
                    <Text style={styles.filterText}>All</Text>
                </TouchableOpacity>
                <TouchableOpacity
                    style={[styles.filterButton, filter === 'up' && styles.filterButtonActive]}
                    onPress={() => setFilter('up')}
                >
                    <Text style={styles.filterText}>Online</Text>
                </TouchableOpacity>
                <TouchableOpacity
                    style={[styles.filterButton, filter === 'down' && styles.filterButtonActive]}
                    onPress={() => setFilter('down')}
                >
                    <Text style={styles.filterText}>Offline</Text>
                </TouchableOpacity>
            </View>

            <FlatList
                data={devices}
                renderItem={renderDeviceItem}
                keyExtractor={(item) => item.id.toString()}
                refreshControl={
                    <RefreshControl
                        refreshing={refreshing}
                        onRefresh={handleRefresh}
                        colors={['#007AFF']}
                    />
                }
                contentContainerStyle={styles.deviceList}
            />
        </View>
    );
};

// ============================================================================
// Settings Component
// ============================================================================

const SettingsScreen = () => {
    const [offlineMode, setOfflineMode] = useState(true);
    const [syncInterval, setSyncInterval] = useState(30);
    const [notifications, setNotifications] = useState(true);
    const { sdk, user } = useHomeNetMon();

    useEffect(() => {
        loadSettings();
    }, []);

    const loadSettings = async () => {
        try {
            const config = await sdk.getMobileConfig();
            if (config.success) {
                setOfflineMode(config.config.features.offline_mode);
                setSyncInterval(config.config.sync_intervals.devices);
                setNotifications(config.config.features.push_notifications);
            }
        } catch (error) {
            console.error('Failed to load settings:', error);
        }
    };

    const updateSettings = () => {
        sdk.updateConfig({
            enableOffline: offlineMode,
            syncInterval: syncInterval * 1000
        });
    };

    const handleLogout = async () => {
        Alert.alert(
            'Logout',
            'Are you sure you want to logout?',
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Logout',
                    onPress: async () => {
                        await sdk.logout();
                    }
                }
            ]
        );
    };

    return (
        <SafeAreaView style={styles.container}>
            <View style={styles.settingsContainer}>
                <Text style={styles.settingsTitle}>Settings</Text>

                <View style={styles.userInfo}>
                    <Text style={styles.userName}>{user?.username}</Text>
                    <Text style={styles.userRole}>{user?.role}</Text>
                </View>

                <View style={styles.settingItem}>
                    <Text style={styles.settingLabel}>Offline Mode</Text>
                    <Switch
                        value={offlineMode}
                        onValueChange={(value) => {
                            setOfflineMode(value);
                            updateSettings();
                        }}
                    />
                </View>

                <View style={styles.settingItem}>
                    <Text style={styles.settingLabel}>Push Notifications</Text>
                    <Switch
                        value={notifications}
                        onValueChange={setNotifications}
                    />
                </View>

                <View style={styles.settingItem}>
                    <Text style={styles.settingLabel}>Sync Interval (seconds)</Text>
                    <TextInput
                        style={styles.settingInput}
                        value={syncInterval.toString()}
                        onChangeText={(text) => setSyncInterval(parseInt(text) || 30)}
                        keyboardType="numeric"
                    />
                </View>

                <TouchableOpacity style={styles.logoutButton} onPress={handleLogout}>
                    <Text style={styles.logoutButtonText}>Logout</Text>
                </TouchableOpacity>
            </View>
        </SafeAreaView>
    );
};

// ============================================================================
// Main App Component
// ============================================================================

const App = () => {
    const [currentScreen, setCurrentScreen] = useState('login');
    const { isAuthenticated } = useHomeNetMon();

    useEffect(() => {
        if (isAuthenticated) {
            setCurrentScreen('devices');
        } else {
            setCurrentScreen('login');
        }
    }, [isAuthenticated]);

    const renderScreen = () => {
        switch (currentScreen) {
            case 'login':
                return <LoginScreen onLoginSuccess={() => setCurrentScreen('devices')} />;
            case 'devices':
                return <DeviceList />;
            case 'settings':
                return <SettingsScreen />;
            default:
                return <DeviceList />;
        }
    };

    return (
        <HomeNetMonProvider>
            <StatusBar barStyle="dark-content" backgroundColor="white" />
            {renderScreen()}
        </HomeNetMonProvider>
    );
};

// ============================================================================
// Styles
// ============================================================================

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#f5f5f5',
    },
    centerContainer: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
    },
    loginContainer: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
        padding: 20,
        backgroundColor: 'white',
    },
    title: {
        fontSize: 32,
        fontWeight: 'bold',
        color: '#007AFF',
        marginBottom: 40,
    },
    input: {
        width: '100%',
        height: 50,
        borderWidth: 1,
        borderColor: '#ddd',
        borderRadius: 8,
        paddingHorizontal: 15,
        marginBottom: 15,
        backgroundColor: 'white',
    },
    loginButton: {
        width: '100%',
        height: 50,
        backgroundColor: '#007AFF',
        borderRadius: 8,
        justifyContent: 'center',
        alignItems: 'center',
        marginTop: 10,
    },
    loginButtonDisabled: {
        backgroundColor: '#ccc',
    },
    loginButtonText: {
        color: 'white',
        fontSize: 16,
        fontWeight: 'bold',
    },
    header: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: 20,
        backgroundColor: 'white',
        borderBottomWidth: 1,
        borderBottomColor: '#eee',
    },
    headerTitle: {
        fontSize: 24,
        fontWeight: 'bold',
        color: '#333',
    },
    connectionStatus: {
        flexDirection: 'row',
        alignItems: 'center',
    },
    connectionDot: {
        width: 8,
        height: 8,
        borderRadius: 4,
        marginRight: 5,
    },
    connectionText: {
        fontSize: 12,
        color: '#666',
    },
    filterContainer: {
        flexDirection: 'row',
        padding: 15,
        backgroundColor: 'white',
    },
    filterButton: {
        paddingHorizontal: 15,
        paddingVertical: 8,
        borderRadius: 20,
        backgroundColor: '#f0f0f0',
        marginRight: 10,
    },
    filterButtonActive: {
        backgroundColor: '#007AFF',
    },
    filterText: {
        fontSize: 14,
        color: '#333',
    },
    deviceList: {
        padding: 10,
    },
    deviceCard: {
        backgroundColor: 'white',
        borderRadius: 12,
        padding: 15,
        marginBottom: 10,
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.1,
        shadowRadius: 4,
        elevation: 3,
    },
    deviceHeader: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 5,
    },
    deviceName: {
        fontSize: 16,
        fontWeight: 'bold',
        color: '#333',
    },
    statusIndicator: {
        width: 12,
        height: 12,
        borderRadius: 6,
    },
    deviceIp: {
        fontSize: 14,
        color: '#666',
        marginBottom: 10,
    },
    deviceStats: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        marginBottom: 10,
    },
    deviceStat: {
        fontSize: 12,
        color: '#666',
    },
    alertBadge: {
        backgroundColor: '#FF3B30',
        paddingHorizontal: 8,
        paddingVertical: 4,
        borderRadius: 12,
        alignSelf: 'flex-start',
        marginBottom: 10,
    },
    alertText: {
        color: 'white',
        fontSize: 12,
        fontWeight: 'bold',
    },
    pingButton: {
        backgroundColor: '#007AFF',
        paddingHorizontal: 15,
        paddingVertical: 8,
        borderRadius: 8,
        alignSelf: 'flex-end',
    },
    pingButtonText: {
        color: 'white',
        fontSize: 12,
        fontWeight: 'bold',
    },
    loadingText: {
        marginTop: 10,
        fontSize: 16,
        color: '#666',
    },
    settingsContainer: {
        flex: 1,
        padding: 20,
        backgroundColor: 'white',
    },
    settingsTitle: {
        fontSize: 24,
        fontWeight: 'bold',
        color: '#333',
        marginBottom: 30,
    },
    userInfo: {
        backgroundColor: '#f8f9fa',
        padding: 15,
        borderRadius: 8,
        marginBottom: 20,
    },
    userName: {
        fontSize: 18,
        fontWeight: 'bold',
        color: '#333',
    },
    userRole: {
        fontSize: 14,
        color: '#666',
        marginTop: 5,
    },
    settingItem: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingVertical: 15,
        borderBottomWidth: 1,
        borderBottomColor: '#eee',
    },
    settingLabel: {
        fontSize: 16,
        color: '#333',
    },
    settingInput: {
        borderWidth: 1,
        borderColor: '#ddd',
        borderRadius: 4,
        paddingHorizontal: 10,
        paddingVertical: 5,
        width: 80,
        textAlign: 'center',
    },
    logoutButton: {
        backgroundColor: '#FF3B30',
        padding: 15,
        borderRadius: 8,
        alignItems: 'center',
        marginTop: 30,
    },
    logoutButtonText: {
        color: 'white',
        fontSize: 16,
        fontWeight: 'bold',
    },
});

export default App;