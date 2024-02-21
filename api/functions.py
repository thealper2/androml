import androguard
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

import numpy as np
import pandas as pd
import re
import hashlib

permissions_list = [
'SEND_SMS', 'READ_PHONE_STATE', 'GET_ACCOUNTS', 'RECEIVE_SMS',
'READ_SMS', 'USE_CREDENTIALS', 'MANAGE_ACCOUNTS', 'WRITE_SMS',
'READ_SYNC_SETTINGS', 'AUTHENTICATE_ACCOUNTS',
'WRITE_HISTORY_BOOKMARKS', 'INSTALL_PACKAGES', 'CAMERA',
'WRITE_SYNC_SETTINGS', 'READ_HISTORY_BOOKMARKS', 'INTERNET',
'RECORD_AUDIO', 'NFC', 'ACCESS_LOCATION_EXTRA_COMMANDS',
'WRITE_APN_SETTINGS', 'BIND_REMOTEVIEWS', 'READ_PROFILE',
'MODIFY_AUDIO_SETTINGS', 'READ_SYNC_STATS', 'BROADCAST_STICKY',
'WAKE_LOCK', 'RECEIVE_BOOT_COMPLETED', 'RESTART_PACKAGES',
'BLUETOOTH', 'READ_CALENDAR', 'READ_CALL_LOG',
'SUBSCRIBED_FEEDS_WRITE', 'READ_EXTERNAL_STORAGE', 'VIBRATE',
'ACCESS_NETWORK_STATE', 'SUBSCRIBED_FEEDS_READ',
'CHANGE_WIFI_MULTICAST_STATE', 'WRITE_CALENDAR', 'MASTER_CLEAR',
'UPDATE_DEVICE_STATS', 'WRITE_CALL_LOG', 'DELETE_PACKAGES',
'GET_TASKS', 'GLOBAL_SEARCH', 'DELETE_CACHE_FILES',
'WRITE_USER_DICTIONARY', 'REORDER_TASKS', 'WRITE_PROFILE',
'SET_WALLPAPER', 'BIND_INPUT_METHOD', 'READ_SOCIAL_STREAM',
'READ_USER_DICTIONARY', 'PROCESS_OUTGOING_CALLS',
'CALL_PRIVILEGED', 'BIND_WALLPAPER', 'RECEIVE_WAP_PUSH', 'DUMP',
'BATTERY_STATS', 'ACCESS_COARSE_LOCATION', 'SET_TIME',
'WRITE_SOCIAL_STREAM', 'WRITE_SETTINGS', 'REBOOT',
'BLUETOOTH_ADMIN', 'BIND_DEVICE_ADMIN', 'WRITE_GSERVICES',
'KILL_BACKGROUND_PROCESSES', 'STATUS_BAR', 'PERSISTENT_ACTIVITY',
'CHANGE_NETWORK_STATE', 'RECEIVE_MMS', 'SET_TIME_ZONE',
'CONTROL_LOCATION_UPDATES', 'BROADCAST_WAP_PUSH',
'BIND_ACCESSIBILITY_SERVICE', 'ADD_VOICEMAIL', 'CALL_PHONE',
'BIND_APPWIDGET', 'FLASHLIGHT', 'READ_LOGS', 'SET_PROCESS_LIMIT',
'MOUNT_UNMOUNT_FILESYSTEMS', 'BIND_TEXT_SERVICE',
'INSTALL_LOCATION_PROVIDER', 'SYSTEM_ALERT_WINDOW',
'MOUNT_FORMAT_FILESYSTEMS', 'CHANGE_CONFIGURATION',
'CLEAR_APP_USER_DATA', 'CHANGE_WIFI_STATE', 'READ_FRAME_BUFFER',
'ACCESS_SURFACE_FLINGER', 'BROADCAST_SMS', 'EXPAND_STATUS_BAR',
'INTERNAL_SYSTEM_WINDOW', 'SET_ACTIVITY_WATCHER', 'WRITE_CONTACTS',
'BIND_VPN_SERVICE', 'DISABLE_KEYGUARD', 'ACCESS_MOCK_LOCATION',
'GET_PACKAGE_SIZE', 'MODIFY_PHONE_STATE',
'CHANGE_COMPONENT_ENABLED_STATE', 'CLEAR_APP_CACHE',
'SET_ORIENTATION', 'READ_CONTACTS', 'DEVICE_POWER',
'HARDWARE_TEST', 'ACCESS_WIFI_STATE', 'WRITE_EXTERNAL_STORAGE',
'ACCESS_FINE_LOCATION', 'SET_WALLPAPER_HINTS',
'SET_PREFERRED_APPLICATIONS', 'WRITE_SECURE_SETTINGS'
]

api_call_signatures = [
'transact', 'onServiceConnected', 'bindService', 'attachInterface',
'ServiceConnection', 'android.os.Binder',
'Ljava.lang.Class.getCanonicalName', 'Ljava.lang.Class.getMethods',
'Ljava.lang.Class.cast', 'Ljava.net.URLDecoder',
'android.content.pm.Signature', 'android.telephony.SmsManager',
'getBinder', 'ClassLoader',
'Landroid.content.Context.registerReceiver',
'Ljava.lang.Class.getField',
'Landroid.content.Context.unregisterReceiver',
'Ljava.lang.Class.getDeclaredField', 'getCallingUid',
'Ljavax.crypto.spec.SecretKeySpec',
'android.content.pm.PackageInfo', 'KeySpec',
'TelephonyManager.getLine1Number', 'DexClassLoader',
'HttpGet.init', 'SecretKey', 'Ljava.lang.Class.getMethod',
'System.loadLibrary', 'android.intent.action.SEND',
'Ljavax.crypto.Cipher', 'android.telephony.gsm.SmsManager',
'TelephonyManager.getSubscriberId', 'Runtime.getRuntime',
'Ljava.lang.Object.getClass', 'Ljava.lang.Class.forName', 'Binder',
'IBinder', 'android.os.IBinder', 'createSubprocess',
'URLClassLoader', 'abortBroadcast', 'TelephonyManager.getDeviceId',
'getCallingPid', 'Ljava.lang.Class.getPackage',
'Ljava.lang.Class.getDeclaredClasses', 'PathClassLoader',
'TelephonyManager.getSimSerialNumber', 'Runtime.load',
'TelephonyManager.getCallState',
'TelephonyManager.getSimCountryIso', 'sendMultipartTextMessage',
'PackageInstaller', 'sendDataMessage', 'HttpPost.init',
'Ljava.lang.Class.getClasses', 'TelephonyManager.isNetworkRoaming',
'HttpUriRequest', 'divideMessage', 'Runtime.exec',
'TelephonyManager.getNetworkOperator', 'MessengerService',
'IRemoteService', 'SET_ALARM', 'ACCOUNT_MANAGER',
'TelephonyManager.getSimOperator', 'onBind', 'Process.start',
'Context.bindService', 'ProcessBuilder',
'Ljava.lang.Class.getResource', 'defineClass', 'findClass',
'Runtime.loadLibrary'
]

intents = [
'android.intent.action.BOOT_COMPLETED',
'android.intent.action.PACKAGE_REPLACED',
'android.intent.action.SEND_MULTIPLE',
'android.intent.action.TIME_SET',
'android.intent.action.PACKAGE_REMOVED',
'android.intent.action.TIMEZONE_CHANGED',
'android.intent.action.ACTION_POWER_DISCONNECTED',
'android.intent.action.PACKAGE_ADDED',
'android.intent.action.ACTION_SHUTDOWN',
'android.intent.action.PACKAGE_DATA_CLEARED',
'android.intent.action.PACKAGE_CHANGED',
'android.intent.action.NEW_OUTGOING_CALL',
'android.intent.action.SENDTO', 'android.intent.action.CALL',
'android.intent.action.SCREEN_ON',
'android.intent.action.BATTERY_OKAY',
'android.intent.action.PACKAGE_RESTARTED',
'android.intent.action.CALL_BUTTON',
'android.intent.action.SCREEN_OFF', 'intent.action.RUN',
'android.intent.action.SET_WALLPAPER',
'android.intent.action.BATTERY_LOW',
'android.intent.action.ACTION_POWER_CONNECTED'
]

keywords = ['mount', 'chmod', 'remount', 'chown', '/system/bin', '/system/app']

columns = [
'filename', 'transact', 'onServiceConnected', 'bindService',
'attachInterface', 'ServiceConnection', 'android.os.Binder', 'SEND_SMS',
'Ljava.lang.Class.getCanonicalName', 'Ljava.lang.Class.getMethods', 'Ljava.lang.Class.cast',
'Ljava.net.URLDecoder', 'android.content.pm.Signature', 'android.telephony.SmsManager',
'READ_PHONE_STATE', 'getBinder', 'ClassLoader', 'Landroid.content.Context.registerReceiver',
'Ljava.lang.Class.getField', 'Landroid.content.Context.unregisterReceiver', 'GET_ACCOUNTS',
'RECEIVE_SMS', 'Ljava.lang.Class.getDeclaredField', 'READ_SMS', 'getCallingUid',
'Ljavax.crypto.spec.SecretKeySpec', 'android.intent.action.BOOT_COMPLETED', 'USE_CREDENTIALS',
'MANAGE_ACCOUNTS', 'android.content.pm.PackageInfo', 'KeySpec', 'TelephonyManager.getLine1Number',
'DexClassLoader', 'HttpGet.init', 'SecretKey', 'Ljava.lang.Class.getMethod',
'System.loadLibrary', 'android.intent.action.SEND', 'Ljavax.crypto.Cipher',
'WRITE_SMS', 'READ_SYNC_SETTINGS', 'AUTHENTICATE_ACCOUNTS', 'android.telephony.gsm.SmsManager', 
'WRITE_HISTORY_BOOKMARKS', 'TelephonyManager.getSubscriberId', 'mount', 'INSTALL_PACKAGES',
'Runtime.getRuntime', 'CAMERA', 'Ljava.lang.Object.getClass', 'WRITE_SYNC_SETTINGS',
'READ_HISTORY_BOOKMARKS', 'Ljava.lang.Class.forName', 'INTERNET', 'android.intent.action.PACKAGE_REPLACED',
'Binder', 'android.intent.action.SEND_MULTIPLE', 'RECORD_AUDIO', 'IBinder', 'android.os.IBinder',
'createSubprocess', 'NFC', 'ACCESS_LOCATION_EXTRA_COMMANDS', 'URLClassLoader', 'WRITE_APN_SETTINGS',
'abortBroadcast', 'BIND_REMOTEVIEWS', 'android.intent.action.TIME_SET', 'READ_PROFILE', 'TelephonyManager.getDeviceId',
'MODIFY_AUDIO_SETTINGS', 'getCallingPid', 'READ_SYNC_STATS', 'BROADCAST_STICKY', 'android.intent.action.PACKAGE_REMOVED',
'android.intent.action.TIMEZONE_CHANGED', 'WAKE_LOCK', 'RECEIVE_BOOT_COMPLETED', 'RESTART_PACKAGES',
'Ljava.lang.Class.getPackage', 'chmod', 'Ljava.lang.Class.getDeclaredClasses', 'android.intent.action.ACTION_POWER_DISCONNECTED',
'android.intent.action.PACKAGE_ADDED', 'PathClassLoader', 'TelephonyManager.getSimSerialNumber', 'Runtime.load',
'TelephonyManager.getCallState', 'BLUETOOTH', 'READ_CALENDAR', 'READ_CALL_LOG', 'SUBSCRIBED_FEEDS_WRITE', 'READ_EXTERNAL_STORAGE',
'TelephonyManager.getSimCountryIso', 'sendMultipartTextMessage', 'PackageInstaller', 'VIBRATE', 'remount', 'android.intent.action.ACTION_SHUTDOWN',
'sendDataMessage', 'ACCESS_NETWORK_STATE', 'chown', 'HttpPost.init', 'Ljava.lang.Class.getClasses', 'SUBSCRIBED_FEEDS_READ',
'TelephonyManager.isNetworkRoaming', 'CHANGE_WIFI_MULTICAST_STATE', 'WRITE_CALENDAR', 'android.intent.action.PACKAGE_DATA_CLEARED',
'MASTER_CLEAR', 'HttpUriRequest', 'UPDATE_DEVICE_STATS', 'WRITE_CALL_LOG', 'DELETE_PACKAGES', 'GET_TASKS', 'GLOBAL_SEARCH',
'DELETE_CACHE_FILES', 'WRITE_USER_DICTIONARY', 'android.intent.action.PACKAGE_CHANGED', 'android.intent.action.NEW_OUTGOING_CALL',
'REORDER_TASKS', 'WRITE_PROFILE', 'SET_WALLPAPER', 'BIND_INPUT_METHOD', 'divideMessage', 'READ_SOCIAL_STREAM', 'READ_USER_DICTIONARY',
'PROCESS_OUTGOING_CALLS', 'CALL_PRIVILEGED', 'Runtime.exec', 'BIND_WALLPAPER', 'RECEIVE_WAP_PUSH', 'DUMP', 'BATTERY_STATS',
'ACCESS_COARSE_LOCATION', 'SET_TIME', 'android.intent.action.SENDTO', 'WRITE_SOCIAL_STREAM', 'WRITE_SETTINGS', 'REBOOT',
'BLUETOOTH_ADMIN', 'TelephonyManager.getNetworkOperator', '/system/bin', 'MessengerService', 'BIND_DEVICE_ADMIN',
'WRITE_GSERVICES', 'IRemoteService', 'KILL_BACKGROUND_PROCESSES', 'SET_ALARM', 'ACCOUNT_MANAGER', '/system/app',
'android.intent.action.CALL', 'STATUS_BAR', 'TelephonyManager.getSimOperator', 'PERSISTENT_ACTIVITY', 'CHANGE_NETWORK_STATE',
'onBind', 'Process.start', 'android.intent.action.SCREEN_ON', 'Context.bindService', 'RECEIVE_MMS', 'SET_TIME_ZONE',
'android.intent.action.BATTERY_OKAY', 'CONTROL_LOCATION_UPDATES', 'BROADCAST_WAP_PUSH', 'BIND_ACCESSIBILITY_SERVICE',
'ADD_VOICEMAIL', 'CALL_PHONE', 'ProcessBuilder', 'BIND_APPWIDGET', 'FLASHLIGHT', 'READ_LOGS', 'Ljava.lang.Class.getResource',
'defineClass', 'SET_PROCESS_LIMIT', 'android.intent.action.PACKAGE_RESTARTED', 'MOUNT_UNMOUNT_FILESYSTEMS', 'BIND_TEXT_SERVICE',
'INSTALL_LOCATION_PROVIDER', 'android.intent.action.CALL_BUTTON', 'android.intent.action.SCREEN_OFF', 'findClass',
'SYSTEM_ALERT_WINDOW', 'MOUNT_FORMAT_FILESYSTEMS', 'CHANGE_CONFIGURATION', 'CLEAR_APP_USER_DATA',
'intent.action.RUN', 'android.intent.action.SET_WALLPAPER', 'CHANGE_WIFI_STATE', 'READ_FRAME_BUFFER', 'ACCESS_SURFACE_FLINGER',
'Runtime.loadLibrary', 'BROADCAST_SMS', 'EXPAND_STATUS_BAR', 'INTERNAL_SYSTEM_WINDOW', 'android.intent.action.BATTERY_LOW',
'SET_ACTIVITY_WATCHER', 'WRITE_CONTACTS', 'android.intent.action.ACTION_POWER_CONNECTED', 'BIND_VPN_SERVICE', 'DISABLE_KEYGUARD',
'ACCESS_MOCK_LOCATION', 'GET_PACKAGE_SIZE', 'MODIFY_PHONE_STATE', 'CHANGE_COMPONENT_ENABLED_STATE', 'CLEAR_APP_CACHE', 'SET_ORIENTATION',
'READ_CONTACTS', 'DEVICE_POWER', 'HARDWARE_TEST', 'ACCESS_WIFI_STATE', 'WRITE_EXTERNAL_STORAGE', 'ACCESS_FINE_LOCATION',
'SET_WALLPAPER_HINTS', 'SET_PREFERRED_APPLICATIONS', 'WRITE_SECURE_SETTINGS'
]

def preprocess_data(file_path, filename):
    df = pd.DataFrame(columns=columns)
    df.loc[0, "filename"] = filename

    a = APK(file_path)
    d = DalvikVMFormat(a.get_dex())

    permissions = a.get_permissions()
    manifest = a.get_android_manifest_xml()
    intent_filters = manifest.findall(".//intent-filter")

    found_permissions = []
    found_api_signatures = []
    found_intents = []
    found_keywords = []

    for permission in permissions:
        permissions = permission.split(".")[-1]
        if permission in permissions_list:
            found_permissions.append(permission)

    for permission in permissions_list:
        if permission in found_permissions:
            df[permission] = 1
        else:
            df[permission] = 0

    for method in d.get_methods():
        for api_call in api_call_signatures:
            if re.search(api_call, method.get_descriptor()):
                found_api_signatures.append(api_call)

    for api_call in api_call_signatures:
        if api_call in found_api_signatures:
            df[api_call] = 1
        else:
            df[api_call] = 0

    for intent_filter in intent_filters:
        action_elements = intent_filter.findall(".//action")
        for action_element in action_elements:
            action_value = action_element.get("{http://schemas.android.com/apk/res/android}name")
            for intent in intents:
                if re.search(intent, action_value):
                    found_intents.append(intent)

    for intent in intents:
        if intent in found_intents:
            df[intent] = 1
        else:
            df[intent] = 0

    for method in d.get_methods():
        for keyword in keywords:
            try:
                if re.search(keyword, method.get_code().get_instruction()):
                    found_keywords.append(keyword)

            except:
                pass

    for keyword in keywords:
        if keyword in found_keywords:
            df[keyword] = 1
        else:
            df[keyword] = 0

    dropped = df.drop("filename", axis=1)
    return dropped

def result_jsons(df, file_path, label):
    intent_json = {}
    for intent in intents:
       intent_json[intent.split('.')[-1]] = str(df.loc[0, intent])

    permission_json = {}
    for permission in permissions_list:
        permission_json[permission] = str(df.loc[0, permission])

    keyword_json = {}
    for keyword in keywords:
        keyword_json[keyword] = str(df.loc[0, keyword])
    
    signature_json = {}
    for signature in api_call_signatures:
        signature_json[signature] = str(df.loc[0, signature])

    md5_hash = hashlib.md5(open(file_path, "rb").read()).hexdigest()
    sha1_hash = hashlib.sha1(open(file_path, "rb").read()).hexdigest()

    hash_json = {}
    hash_json= {
        "MD5": md5_hash,
        "SHA1": sha1_hash
    }

    result_json = {
        "intent_json": intent_json,
        "permission_json": permission_json,
        "keyword_json": keyword_json,
        "signature_json": signature_json,
        "hash_json": hash_json,
        "label": label
    }

    return result_json