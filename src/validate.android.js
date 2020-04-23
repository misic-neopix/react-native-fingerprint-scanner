import { NativeModules } from 'react-native';

const { ReactNativeFingerprintScanner } = NativeModules;

export default ({ oldState }) => {
    return new Promise((resolve) => {
        ReactNativeFingerprintScanner.validate(oldState, (error, success) => {
            if (success) {
                return resolve(true)
            } else {
                return reject(createError('AuthenticationNotMatch', 'AuthenticationNotMatch'))
            }
        });
    });
}
