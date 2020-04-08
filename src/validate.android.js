import { NativeModules } from 'react-native';

const { ReactNativeFingerprintScanner } = NativeModules;

export default ({ oldState }) => {
    return new Promise((resolve) => {
        resolve(true)
    });
}
