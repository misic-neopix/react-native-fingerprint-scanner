import { NativeModules } from 'react-native';
import createError from "./createError";

const { ReactNativeFingerprintScanner } = NativeModules;

export default () => {
    return new Promise((resolve) => {
        resolve("hello world")
    });
}
