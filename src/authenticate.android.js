import {
    DeviceEventEmitter,
    NativeModules,
    Platform,
} from 'react-native';
import createError from './createError';

const {ReactNativeFingerprintScanner} = NativeModules;

const authCurrent = (description, data, saving, resolve, reject) => {
    ReactNativeFingerprintScanner.authenticate(description, data, saving)
        .then((data) => {
            resolve(data);
            console.log('mile auth success in lib', error)
        })
        .catch((error) => {
            // translate errors
            console.log('mile auth error in lib', error)
            reject(createError(error.code, error.message));
        });
}

const authLegacy = (onAttempt, data, saving, resolve, reject) => {
    DeviceEventEmitter.addListener('FINGERPRINT_SCANNER_AUTHENTICATION', (name) => {
        if (name === 'AuthenticationNotMatch' && typeof onAttempt === 'function') {
            onAttempt(createError(name));
        }
    });

    ReactNativeFingerprintScanner.authenticate(null, data, saving)
        .then((data) => {
            DeviceEventEmitter.removeAllListeners('FINGERPRINT_SCANNER_AUTHENTICATION');
            resolve(data);
        })
        .catch((error) => {
            DeviceEventEmitter.removeAllListeners('FINGERPRINT_SCANNER_AUTHENTICATION');
            reject(createError(error.code, error.message));
        });
}

const nullOnAttempt = () => null;

export default ({description, data, saving, onAttempt}) => {
    return new Promise((resolve, reject) => {
        if (!description) {
            description = "Log In";
        }
        if (!onAttempt) {
            onAttempt = nullOnAttempt;
        }

        if (Platform.Version < 23) {
            return authLegacy(onAttempt, data, saving, resolve, reject);
        }

        return authCurrent(description, data, saving, resolve, reject);
    });
}
