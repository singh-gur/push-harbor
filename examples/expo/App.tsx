import * as Pushharbor from '@pushharbor/expo';
import { File, Paths } from 'expo-file-system';
import { useCallback, useEffect, useState } from 'react';
import { Button, Linking, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';

/**
 * Pushharbor example. In a real app the server's VAPID key comes from your server, and the
 * subscription goes back to it. Here both are entered by hand, or via a deep link for scripts:
 *   pushharborexample://register?relay=<url>&key=<VAPID public key>
 * The resulting subscription is also written to files/subscription.json (debug: `adb shell
 * run-as dev.pushharbor.testapp cat files/subscription.json`).
 */
export default function App() {
  const [relayUrl, setRelayUrl] = useState('http://127.0.0.1:8080');
  const [senderKey, setSenderKey] = useState('');
  const [subscriptions, setSubscriptions] = useState<Pushharbor.Subscription[]>([]);
  const [status, setStatus] = useState('');
  const [lastMessage, setLastMessage] = useState<Pushharbor.Message | null>(null);

  const refresh = useCallback(async () => {
    const subs = await Pushharbor.getSubscriptions();
    setSubscriptions(subs);
    new File(Paths.document, 'subscription.json').write(JSON.stringify(subs.at(-1) ?? null));
  }, []);

  const register = useCallback(
    async (relay: string, key: string) => {
      setStatus('Registering…');
      try {
        await Pushharbor.register({ relayUrl: relay, senderKey: key });
        setStatus('Registered');
      } catch (e: any) {
        setStatus(`Failed: ${e.code ?? ''} ${e.message}`);
      }
      await refresh();
    },
    [refresh],
  );

  useEffect(() => {
    Pushharbor.requestNotificationPermission();
    refresh();
    const messages = Pushharbor.addMessageListener(setLastMessage);
    const onLink = (url: string | null | undefined) => {
      if (!url?.startsWith('pushharborexample://register')) return;
      const params = new URL(url).searchParams;
      const relay = params.get('relay');
      const key = params.get('key');
      if (relay && key) register(relay, key);
    };
    Linking.getInitialURL().then(onLink);
    const links = Linking.addEventListener('url', ({ url }) => onLink(url));
    return () => {
      messages.remove();
      links.remove();
    };
  }, [refresh, register]);

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.title}>Pushharbor example</Text>
      <Text>Relay URL</Text>
      <TextInput style={styles.input} value={relayUrl} onChangeText={setRelayUrl} autoCapitalize="none" />
      <Text>Server VAPID public key</Text>
      <TextInput style={styles.input} value={senderKey} onChangeText={setSenderKey} autoCapitalize="none" />
      <Button title="Register" onPress={() => register(relayUrl, senderKey)} />
      <Text testID="status">{status}</Text>
      {subscriptions.map((s) => (
        <View key={s.id} style={styles.card}>
          <Text selectable>{JSON.stringify(s, null, 2)}</Text>
          <Button title="Unregister" onPress={() => Pushharbor.unregister(s.id).then(refresh)} />
        </View>
      ))}
      {lastMessage && <Text testID="last-message">Last message: {JSON.stringify(lastMessage)}</Text>}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flexGrow: 1, padding: 24, paddingTop: 64, gap: 8, backgroundColor: '#fff' },
  title: { fontSize: 20, fontWeight: '600' },
  input: { borderWidth: 1, borderColor: '#999', padding: 8 },
  card: { borderWidth: 1, borderColor: '#ccc', padding: 8, gap: 8 },
});
