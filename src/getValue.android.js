import {DeviceEventEmitter, NativeModules, Platform} from 'react-native';
import createError from './createError';

const {ReactNativeFingerprintScanner} = NativeModules;

export default ({code}) => {
    return new Promise((resolve, reject) => {
        ReactNativeFingerprintScanner.getValue(code)
            .then((value) => resolve(value))
            .catch(error => reject(createError((error && error.code) ? error.code : 'GetPasscodeError', 'Passcode')));
    });
}
