// Copies the Android library (packages/android) into android-lib/, which this package ships and
// Expo autolinking includes as Gradle project :pushharbor-android (expo-module.config.json).
// Runs on `prepare`, so local installs and `npm pack` always carry the current library.
import { cpSync, mkdirSync, rmSync } from 'node:fs';

const src = new URL('../../android/', import.meta.url);
const dest = new URL('../android-lib/', import.meta.url);

rmSync(dest, { recursive: true, force: true });
mkdirSync(dest, { recursive: true });
cpSync(new URL('build.gradle', src), new URL('build.gradle', dest));
cpSync(new URL('src/main', src), new URL('src/main', dest), { recursive: true });
