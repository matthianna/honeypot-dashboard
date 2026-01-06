import { useState, useEffect, useCallback } from 'react';

interface NotificationOptions {
  title: string;
  body: string;
  icon?: string;
  tag?: string;
  requireInteraction?: boolean;
}

export function useNotifications() {
  const [permission, setPermission] = useState<NotificationPermission>('default');
  const [enabled, setEnabled] = useState(() => {
    return localStorage.getItem('honeypot_notifications') === 'true';
  });

  // Check permission on mount
  useEffect(() => {
    if ('Notification' in window) {
      setPermission(Notification.permission);
    }
  }, []);

  // Persist enabled state
  useEffect(() => {
    localStorage.setItem('honeypot_notifications', String(enabled));
  }, [enabled]);

  const requestPermission = useCallback(async () => {
    if (!('Notification' in window)) {
      console.warn('Notifications not supported');
      return false;
    }

    try {
      const result = await Notification.requestPermission();
      setPermission(result);
      if (result === 'granted') {
        setEnabled(true);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Error requesting notification permission:', error);
      return false;
    }
  }, []);

  const sendNotification = useCallback(({ title, body, icon, tag, requireInteraction }: NotificationOptions) => {
    if (!enabled || permission !== 'granted') {
      return null;
    }

    try {
      const notification = new Notification(title, {
        body,
        icon: icon || '/favicon.ico',
        tag,
        requireInteraction,
        badge: '/favicon.ico',
      });

      // Auto close after 5 seconds if not requiring interaction
      if (!requireInteraction) {
        setTimeout(() => notification.close(), 5000);
      }

      return notification;
    } catch (error) {
      console.error('Error sending notification:', error);
      return null;
    }
  }, [enabled, permission]);

  const notifyAttackSpike = useCallback((count: number, threshold: number) => {
    return sendNotification({
      title: '⚠️ Attack Spike Detected',
      body: `${count} attacks in the last minute (${Math.round((count / threshold) * 100)}% above normal)`,
      tag: 'attack-spike',
      requireInteraction: true,
    });
  }, [sendNotification]);

  const notifyNewAttacker = useCallback((ip: string, country: string) => {
    return sendNotification({
      title: '🎯 New Attacker Detected',
      body: `IP: ${ip} from ${country}`,
      tag: `attacker-${ip}`,
    });
  }, [sendNotification]);

  const notifyMalware = useCallback((filename: string, hash: string) => {
    return sendNotification({
      title: '🦠 Malware Captured',
      body: `File: ${filename}\nHash: ${hash.slice(0, 16)}...`,
      tag: `malware-${hash}`,
      requireInteraction: true,
    });
  }, [sendNotification]);

  return {
    permission,
    enabled,
    setEnabled,
    requestPermission,
    sendNotification,
    notifyAttackSpike,
    notifyNewAttacker,
    notifyMalware,
    isSupported: 'Notification' in window,
  };
}

export default useNotifications;




