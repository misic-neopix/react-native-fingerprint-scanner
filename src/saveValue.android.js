import {DeviceEventEmitter, NativeModules, Platform} from 'react-native';
import createError from './createError';

const {ReactNativeFingerprintScanner} = NativeModules;

export default ({code, value}) => {
    return new Promise((resolve, reject) => {
        ReactNativeFingerprintScanner.saveValue(code, value)
            .then((success) => resolve(success))
            .catch(error => reject(createError('PasscodeSaveFailed', 'PasscodeSaveFailed')));
    });
}
