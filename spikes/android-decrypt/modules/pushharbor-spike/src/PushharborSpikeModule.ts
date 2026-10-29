import { NativeModule, requireNativeModule } from 'expo';

export type Stats = {
  shown: number;
  dropped: number;
  ignored: number;
  noPermission: number;
  last: string | null;
  lastAt: number;
};

declare class PushharborSpikeModule extends NativeModule<{}> {
  getKeys(): { p256dh: string; auth: string };
  getToken(): Promise<string>;
  getStats(): Stats;
}

export default requireNativeModule<PushharborSpikeModule>('PushharborSpike');
