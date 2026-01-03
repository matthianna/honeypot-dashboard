import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  Terminal, Bug, Globe, Monitor, Shield, ShieldAlert,
  CheckCircle, AlertCircle, XCircle, Activity
} from 'lucide-react';
import api from '../services/api';

interface HoneypotStatus {
  name: string;
  id: string;
  icon: typeof Terminal;
  color: string;
  href: string;
  status: 'healthy' | 'warning' | 'error' | 'unknown';
  lastEvent: string | null;
  eventsLastHour: number;
  uniqueIPs: number;
}

const HONEYPOT_CONFIG = [
  { id: 'cowrie', name: 'Cowrie (SSH)', icon: Terminal, color: '#39ff14', href: '/cowrie' },
  { id: 'dionaea', name: 'Dionaea', icon: Bug, color: '#00d4ff', href: '/dionaea' },
  { id: 'galah', name: 'Galah (Web)', icon: Globe, color: '#ff6600', href: '/galah' },
  { id: 'rdpy', name: 'RDPY (RDP)', icon: Monitor, color: '#bf00ff', href: '/rdpy' },
  { id: 'heralding', name: 'Heralding', icon: Shield, color: '#ff3366', href: '/heralding' },
  { id: 'firewall', name: 'Firewall', icon: ShieldAlert, color: '#ffd700', href: '/firewall' },
];

export default function HoneypotHealth() {
  const [honeypots, setHoneypots] = useState<HoneypotStatus[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        // Fetch overview to get honeypot stats
        const overview = await api.getDashboardOverview('1h');
        
        const statuses: HoneypotStatus[] = HONEYPOT_CONFIG.map(hp => {
          const hpStats = overview.honeypots?.find(
            (h: { name: string }) => h.name.toLowerCase() === hp.id
          );
          
          const eventsLastHour = hpStats?.total_events || 0;
          const uniqueIPs = hpStats?.unique_ips || 0;
          
          // Determine status based on activity
          let status: HoneypotStatus['status'] = 'unknown';
          if (eventsLastHour > 0) {
            status = 'healthy';
          } else {
            // No events in last hour might indicate an issue
            status = 'warning';
          }
          
          return {
            ...hp,
            status,
            lastEvent: null, // Would need additional API call
            eventsLastHour,
            uniqueIPs,
          };
        });
        
        setHoneypots(statuses);
      } catch (err) {
        console.error('Failed to fetch honeypot health:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);

    return () => clearInterval(interval);
  }, []);

  const getStatusIcon = (status: HoneypotStatus['status']) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'warning':
        return <AlertCircle className="w-4 h-4 text-yellow-400" />;
      case 'error':
        return <XCircle className="w-4 h-4 text-red-400" />;
      default:
        return <Activity className="w-4 h-4 text-text-muted" />;
    }
  };

  if (loading) {
    return (
      <div className="bg-bg-secondary rounded-xl border border-bg-hover p-4">
        <div className="animate-pulse space-y-3">
          {[1, 2, 3, 4, 5, 6].map(i => (
            <div key={i} className="h-12 bg-bg-hover rounded-lg" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-bg-secondary rounded-xl border border-bg-hover overflow-hidden">
      <div className="px-4 py-3 border-b border-bg-hover flex items-center gap-2">
        <Activity className="w-5 h-5 text-neon-blue" />
        <h3 className="font-display font-bold text-text-primary">Honeypot Status</h3>
      </div>
      
      <div className="divide-y divide-bg-hover">
        {honeypots.map((hp) => {
          const Icon = hp.icon;
          return (
            <Link
              key={hp.id}
              to={hp.href}
              className="flex items-center justify-between px-4 py-3 hover:bg-bg-hover transition-colors group"
            >
              <div className="flex items-center gap-3">
                <div 
                  className="p-2 rounded-lg transition-transform group-hover:scale-110"
                  style={{ backgroundColor: `${hp.color}20` }}
                >
                  <Icon className="w-4 h-4" style={{ color: hp.color }} />
                </div>
                <div>
                  <div className="text-text-primary font-medium text-sm group-hover:text-white transition-colors">
                    {hp.name}
                  </div>
                  <div className="text-xs text-text-muted">
                    {hp.eventsLastHour.toLocaleString()} events • {hp.uniqueIPs} IPs
                  </div>
                </div>
              </div>
              
              <div className="flex items-center gap-2">
                {getStatusIcon(hp.status)}
                <div className="text-right">
                  <div 
                    className="text-lg font-display font-bold"
                    style={{ color: hp.color }}
                  >
                    {hp.eventsLastHour.toLocaleString()}
                  </div>
                  <div className="text-xs text-text-muted">/hour</div>
                </div>
              </div>
            </Link>
          );
        })}
      </div>
    </div>
  );
}

