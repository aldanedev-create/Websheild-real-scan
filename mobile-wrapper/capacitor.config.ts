import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.webshield.scanner',
  appName: 'WebShield Scanner',
  webDir: 'dist',
  server: {
    androidScheme: 'https',
    iosScheme: 'https',
    cleartext: false
  },
  android: {
    buildOptions: {
      keystorePath: process.env.CAPACITOR_ANDROID_KEYSTORE_PATH || '',
      keystoreAlias: process.env.CAPACITOR_ANDROID_KEYSTORE_ALIAS || '',
      keystorePassword: process.env.CAPACITOR_ANDROID_KEYSTORE_PASSWORD || '',
      keyPassword: process.env.CAPACITOR_ANDROID_KEY_PASSWORD || ''
    },
    allowMixedContent: false,
    captureInput: true,
    webContentsDebuggingEnabled: false
  },
  ios: {
    scheme: 'WebShield Scanner',
    cordovaSwiftVersion: '5.0',
    contentInset: 'automatic'
  },
  plugins: {
    SplashScreen: {
      launchShowDuration: 3000,
      launchAutoHide: true,
      backgroundColor: '#0a0a1a',
      androidSplashResourceName: 'splash',
      androidScaleType: 'CENTER_CROP',
      showSpinner: false,
      splashFullScreen: true,
      splashImmersive: true
    },
    StatusBar: {
      style: 'dark',
      backgroundColor: '#0a0a1a',
      overlaysWebView: false
    },
    PushNotifications: {
      presentationOptions: ['badge', 'sound', 'alert']
    },
    Storage: {
      encrypted: true
    }
  },
  cordova: {
    preferences: {
      ScrollEnabled: 'false',
      BackupWebStorage: 'none',
      SplashMaintainAspectRatio: 'true',
      FadeSplashScreenDuration: '300',
      SplashShowOnlyFirstTime: 'false',
      SplashScreen: 'screen',
      SplashScreenDelay: '3000'
    }
  }
};

export default config;
