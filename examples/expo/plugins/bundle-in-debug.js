// Bundles the JS into debug builds too, so the example runs without Metro (local E2E runs).
const { withAppBuildGradle } = require('expo/config-plugins');

module.exports = (config) =>
  withAppBuildGradle(config, (c) => {
    if (!c.modResults.contents.includes('debuggableVariants = []')) {
      c.modResults.contents = c.modResults.contents.replace(/react \{/, 'react {\n    debuggableVariants = []');
    }
    return c;
  });
