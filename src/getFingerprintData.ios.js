import { NativeModules } from 'react-native';
import createError from "./createError";

const { ReactNativeFingerprintScanner } = NativeModules;

export default () => {
    return new Promise((resolve, reject) => {
        ReactNativeFingerprintScanner.getFingerprintData( (error, data) => {
            if (error) {
                return reject(createError('AuthenticationProcessFailed', 'AuthenticationProcessFailed'))
            } else {
                return resolve(data)
            }
        });
    });
}
