import { StatusBar } from 'expo-status-bar';
import { useCallback, useEffect, useState } from 'react';
import { Button, PermissionsAndroid, ScrollView, StyleSheet, Text } from 'react-native';
import Spike from './modules/pushharbor-spike';

export default function App() {
  const [token, setToken] = useState('loading…');
  const [stats, setStats] = useState(Spike.getStats());
  const keys = Spike.getKeys();

  const refresh = useCallback(() => setStats(Spike.getStats()), []);

  useEffect(() => {
    PermissionsAndroid.request(PermissionsAndroid.PERMISSIONS.POST_NOTIFICATIONS);
    Spike.getToken().then(setToken, (e: Error) => setToken(`error: ${e.message}`));
  }, []);

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.h}>Pushharbor Android spike (PH-20)</Text>
      <Text style={styles.label}>FCM token</Text>
      <Text selectable style={styles.mono}>{token}</Text>
      <Text style={styles.label}>p256dh</Text>
      <Text selectable style={styles.mono}>{keys.p256dh}</Text>
      <Text style={styles.label}>auth</Text>
      <Text selectable style={styles.mono}>{keys.auth}</Text>
      <Text style={styles.label}>Delivery stats</Text>
      <Text style={styles.mono}>{JSON.stringify(stats, null, 2)}</Text>
      <Button title="Refresh stats" onPress={refresh} />
      <StatusBar style="auto" />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { padding: 24, paddingTop: 64, gap: 6 },
  h: { fontSize: 18, fontWeight: '600', marginBottom: 12 },
  label: { fontWeight: '600', marginTop: 10 },
  mono: { fontFamily: 'monospace', fontSize: 12 },
});
