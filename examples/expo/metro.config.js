// The module is linked from ../../packages/expo: let Metro see it, but never resolve from its own
// node_modules (dev dependencies), so react, react-native and expo exist once, from this app.
const path = require('path');
const { getDefaultConfig } = require('expo/metro-config');

const pkg = path.resolve(__dirname, '../../packages/expo');
const config = getDefaultConfig(__dirname);
config.watchFolders = [pkg];
config.resolver.nodeModulesPaths = [path.resolve(__dirname, 'node_modules')];
config.resolver.blockList = [new RegExp(`${path.join(pkg, 'node_modules').replace(/[/\\]/g, '[/\\\\]')}[/\\\\].*`)];
module.exports = config;
