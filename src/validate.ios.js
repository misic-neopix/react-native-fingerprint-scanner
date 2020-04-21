import { NativeModules } from 'react-native';
import createError from "./createError";

const { ReactNativeFingerprintScanner } = NativeModules;

export default ({ oldState }) => {
    return new Promise((resolve, reject) => {
        ReactNativeFingerprintScanner.validate(oldState, (error, success) => {
            if (success) {
                return resolve(true)
            } else {
                return reject(createError('AuthenticationNotMatch', 'AuthenticationNotMatch'))
            }
        });
    });
}
