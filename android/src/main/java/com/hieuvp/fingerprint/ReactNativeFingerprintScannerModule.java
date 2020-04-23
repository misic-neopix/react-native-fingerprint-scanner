package com.hieuvp.fingerprint;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.biometric.BiometricPrompt.PromptInfo;
import androidx.fragment.app.FragmentActivity;

import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.module.annotations.ReactModule;
import com.facebook.react.modules.core.DeviceEventManagerModule.RCTDeviceEventEmitter;
import com.wei.android.lib.fingerprintidentify.FingerprintIdentify;
import com.wei.android.lib.fingerprintidentify.base.BaseFingerprint.ExceptionListener;
import com.wei.android.lib.fingerprintidentify.base.BaseFingerprint.IdentifyListener;

import java.security.Key;
import java.security.KeyStore;
import java.security.spec.InvalidParameterSpecException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

// for Samsung/MeiZu compat, Android v16-23

@ReactModule(name = "ReactNativeFingerprintScanner")
public class ReactNativeFingerprintScannerModule
        extends ReactContextBaseJavaModule
        implements LifecycleEventListener {
    public static final int MAX_AVAILABLE_TIMES = Integer.MAX_VALUE;
    public static final String TYPE_BIOMETRICS = "Biometrics";
    public static final String TYPE_FINGERPRINT_LEGACY = "Fingerprint";
    private static final String MASTER_KEY_ALIAS = "MASTER_KEY";
    private static final int KEY_SIZE = 256;
    private static final String DATA_KEY = "DATA_KEY";

    private final ReactApplicationContext mReactContext;
    private BiometricPrompt biometricPrompt;

    // for Samsung/MeiZu compat, Android v16-23
    private FingerprintIdentify mFingerprintIdentify;

    public ReactNativeFingerprintScannerModule(ReactApplicationContext reactContext) {
        super(reactContext);
        mReactContext = reactContext;
    }

    @Override
    public String getName() {
        return "ReactNativeFingerprintScanner";
    }

    @Override
    public void onHostResume() {
    }

    @Override
    public void onHostPause() {
    }

    @Override
    public void onHostDestroy() {
        this.release();
    }

    private int currentAndroidVersion() {
        return Build.VERSION.SDK_INT;
    }

    private boolean requiresLegacyAuthentication() {
        return currentAndroidVersion() < 23;
    }

    public class AuthCallback extends BiometricPrompt.AuthenticationCallback {
        private Promise promise;
        private String data;
        private final boolean isEncrypt;

        public AuthCallback(final Promise promise, final String data, final boolean isEncrypt) {
            super();
            this.promise = promise;
            this.data = data;
            this.isEncrypt = isEncrypt;
        }

        @Override
        public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
            super.onAuthenticationError(errorCode, errString);
            this.promise.reject(biometricPromptErrName(errorCode), TYPE_BIOMETRICS);
        }

        @Override
        public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
            BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();
            if (cryptoObject != null && cryptoObject.getCipher() != null) {
                try {
                    String code;
                    if (isEncrypt) {
                        byte[] encoded = new String(Base64.encode(data.getBytes(), Base64.NO_WRAP)).getBytes();
                        Cipher cipher = cryptoObject.getCipher();
                        code = new String(cipher.doFinal(encoded));
                    } else {
                        byte[] bytes = cryptoObject.getCipher().doFinal(data.getBytes());
                        code = new String(Base64.decode(bytes, Base64.NO_WRAP));
                    }
                    Log.i("mile", "mile + " + code);
                    this.promise.resolve(code);
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                }
            }
            this.promise.reject("FingerprintNotValid", "");
            super.onAuthenticationSucceeded(result);
        }
    }

    public BiometricPrompt getBiometricPrompt(final Promise promise, final String data, final boolean isEncrypt) {
        // memoize so can be accessed to cancel
        if (biometricPrompt != null) {
            return biometricPrompt;
        }

        // listen for onHost* methods
        mReactContext.addLifecycleEventListener(this);

        AuthCallback authCallback = new AuthCallback(promise, data, isEncrypt);
        FragmentActivity fragmentActivity = (FragmentActivity) getCurrentActivity();
        Executor executor = Executors.newSingleThreadExecutor();

        biometricPrompt = new BiometricPrompt(
                fragmentActivity,
                executor,
                authCallback
        );

        return biometricPrompt;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void biometricAuthenticate(final String description, final String data, final boolean saving, final Promise promise) {
        UiThreadUtil.runOnUiThread(
                new Runnable() {
                    @Override
                    public void run() {
                        BiometricPrompt bioPrompt = getBiometricPrompt(promise, data, saving);

                        PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                                .setDeviceCredentialAllowed(false)
                                .setConfirmationRequired(false)
                                .setNegativeButtonText("Cancel")
                                .setTitle(description)
                                .build();

                        try {
                            Cipher cipher = getCipher(saving);
                            BiometricPrompt.CryptoObject crypto = new BiometricPrompt.CryptoObject(cipher);
                            bioPrompt.authenticate(promptInfo, crypto);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private Cipher getCipher(boolean isEncrypt) throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (!ks.containsAlias(MASTER_KEY_ALIAS)) {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(MASTER_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(KEY_SIZE)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(-1);

            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                builder.setUnlockedDeviceRequired(true);            // these methods require API min 28
            }

            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
                builder.setInvalidatedByBiometricEnrollment(true);  // this method requires API min 24
            }
            keyGenerator.init(builder.build());
            keyGenerator.generateKey();
        }
        Key key = ks.getKey(MASTER_KEY_ALIAS, null);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SharedPreferences sharedPrefs = getReactApplicationContext()
                .getSharedPreferences("biometrics_shared_prefs", Context.MODE_PRIVATE);
        if (isEncrypt) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            IvParameterSpec ivParams = cipher.getParameters().getParameterSpec(IvParameterSpec.class);
            String iv = new String(Base64.encode(ivParams.getIV(), Base64.NO_WRAP));
            sharedPrefs
                    .edit()
                    .putString("biometrics_iv", iv)
                    .apply();
        } else {
            byte[] bs = sharedPrefs.getString("biometrics_iv", "").getBytes();
            IvParameterSpec params = new IvParameterSpec(Base64.decode(bs, Base64.NO_WRAP));
            cipher.init(Cipher.DECRYPT_MODE, key, params);
        }
        return cipher;
    }

    // the below constants are consistent across BiometricPrompt and BiometricManager
    private String biometricPromptErrName(int errCode) {
        switch (errCode) {
            case BiometricPrompt.ERROR_CANCELED:
                return "SystemCancel";
            case BiometricPrompt.ERROR_HW_NOT_PRESENT:
                return "FingerprintScannerNotSupported";
            case BiometricPrompt.ERROR_HW_UNAVAILABLE:
                return "FingerprintScannerNotAvailable";
            case BiometricPrompt.ERROR_LOCKOUT:
                return "DeviceLocked";
            case BiometricPrompt.ERROR_LOCKOUT_PERMANENT:
                return "DeviceLocked";
            case BiometricPrompt.ERROR_NEGATIVE_BUTTON:
                return "UserCancel";
            case BiometricPrompt.ERROR_NO_BIOMETRICS:
                return "FingerprintScannerNotEnrolled";
            case BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL:
                return "PasscodeNotSet";
            case BiometricPrompt.ERROR_NO_SPACE:
                return "DeviceOutOfMemory";
            case BiometricPrompt.ERROR_TIMEOUT:
                return "AuthenticationTimeout";
            case BiometricPrompt.ERROR_UNABLE_TO_PROCESS:
                return "AuthenticationProcessFailed";
            case BiometricPrompt.ERROR_USER_CANCELED:  // actually 'user elected another auth method'
                return "UserFallback";
            case BiometricPrompt.ERROR_VENDOR:
                // hardware-specific error codes
                return "HardwareError";
            default:
                return "FingerprintScannerUnknownError";
        }
    }

    private String getSensorError() {
        BiometricManager biometricManager = BiometricManager.from(mReactContext);
        int authResult = biometricManager.canAuthenticate();

        if (authResult == BiometricManager.BIOMETRIC_SUCCESS) {
            return null;
        }
        if (authResult == BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE) {
            return "FingerprintScannerNotSupported";
        } else if (authResult == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED) {
            return "FingerprintScannerNotEnrolled";
        } else if (authResult == BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE) {
            return "FingerprintScannerNotAvailable";
        }

        return null;
    }

    @SuppressLint("NewApi")
    @ReactMethod
    public void authenticate(String description, String data, boolean saving, final Promise promise) {
        if (requiresLegacyAuthentication()) {
            legacyAuthenticate(data, promise);
        } else {
            final String errorName = getSensorError();
            if (errorName != null) {
                promise.reject(errorName, TYPE_BIOMETRICS);
                ReactNativeFingerprintScannerModule.this.release();
                return;
            }

            biometricAuthenticate(description, data, saving, promise);
        }
    }

    @ReactMethod
    public void release() {
        if (requiresLegacyAuthentication()) {
            getFingerprintIdentify().cancelIdentify();
            mFingerprintIdentify = null;
        }

        // consistent across legacy and current API
        if (biometricPrompt != null) {
            biometricPrompt.cancelAuthentication();  // if release called from eg React
        }
        biometricPrompt = null;
        mReactContext.removeLifecycleEventListener(this);
    }

    @ReactMethod
    public void isSensorAvailable(final Promise promise) {
        if (requiresLegacyAuthentication()) {
            String errorMessage = legacyGetErrorMessage();
            if (errorMessage != null) {
                promise.reject(errorMessage, TYPE_FINGERPRINT_LEGACY);
            } else {
                promise.resolve(TYPE_FINGERPRINT_LEGACY);
            }
            return;
        }

        // current API
        String errorName = getSensorError();
        if (errorName != null) {
            promise.reject(errorName, TYPE_BIOMETRICS);
        } else {
            promise.resolve(TYPE_BIOMETRICS);
        }
    }


    // for Samsung/MeiZu compat, Android v16-23
    private FingerprintIdentify getFingerprintIdentify() {
        if (mFingerprintIdentify != null) {
            return mFingerprintIdentify;
        }
        mReactContext.addLifecycleEventListener(this);
        mFingerprintIdentify = new FingerprintIdentify(mReactContext);
        mFingerprintIdentify.setSupportAndroidL(true);
        mFingerprintIdentify.setExceptionListener(
                new ExceptionListener() {
                    @Override
                    public void onCatchException(Throwable exception) {
                        mReactContext.removeLifecycleEventListener(ReactNativeFingerprintScannerModule.this);
                    }
                }
        );
        mFingerprintIdentify.init();
        return mFingerprintIdentify;
    }

    private String legacyGetErrorMessage() {
        if (!getFingerprintIdentify().isHardwareEnable()) {
            return "FingerprintScannerNotSupported";
        } else if (!getFingerprintIdentify().isRegisteredFingerprint()) {
            return "FingerprintScannerNotEnrolled";
        } else if (!getFingerprintIdentify().isFingerprintEnable()) {
            return "FingerprintScannerNotAvailable";
        }

        return null;
    }


    private void legacyAuthenticate(final String data, final Promise promise) {
        final String errorMessage = legacyGetErrorMessage();
        if (errorMessage != null) {
            promise.reject(errorMessage, TYPE_FINGERPRINT_LEGACY);
            ReactNativeFingerprintScannerModule.this.release();
            return;
        }

        getFingerprintIdentify().resumeIdentify();
        getFingerprintIdentify().startIdentify(MAX_AVAILABLE_TIMES, new IdentifyListener() {
            @Override
            public void onSucceed() {
                promise.resolve(data);
                ReactNativeFingerprintScannerModule.this.release();
            }

            @Override
            public void onNotMatch(int availableTimes) {
                mReactContext.getJSModule(RCTDeviceEventEmitter.class)
                        .emit("FINGERPRINT_SCANNER_AUTHENTICATION", "AuthenticationNotMatch");
            }

            @Override
            public void onFailed(boolean isDeviceLocked) {
                if (isDeviceLocked) {
                    promise.reject("AuthenticationFailed", "DeviceLocked");
                } else {
                    promise.reject("AuthenticationFailed", TYPE_FINGERPRINT_LEGACY);
                }
                ReactNativeFingerprintScannerModule.this.release();
            }

            @Override
            public void onStartFailedByDeviceLocked() {
                // the first start failed because the device was locked temporarily
                promise.reject("AuthenticationFailed", "DeviceLocked");
            }
        });
    }
}
