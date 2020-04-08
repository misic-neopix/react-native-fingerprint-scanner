import { NativeModules } from 'react-native';
import createError from "./createError";

const { ReactNativeFingerprintScanner } = NativeModules;

export default () => {
    return new Promise((resolve, reject) => {
        ReactNativeFingerprintScanner.getFingerprintData( error, data => {
            if (error || !data) {
                return reject(createError(ERRORS.AuthenticationProcessFailed, ERRORS.AuthenticationProcessFailed))
            } else if  {
                return resolve(data)
            }
        });
    });
}
