import { useCallback, useEffect, useState } from 'react';
import { Users, Search } from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
} from 'recharts';
import { useAnalytics } from './AnalyticsLayout';
import { ExportToolbar, exportToCSV } from '../../components/analytics';
import DataTable from '../../components/DataTable';
import LoadingSpinner from '../../components/LoadingSpinner';
import IPLink from '../../components/IPLink';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

export default function FirewallTopAttackers() {
  const { timeRange, setLastUpdated } = useAnalytics();
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [attackerProfile, setAttackerProfile] = useState<any>(null);
  const [profileLoading, setProfileLoading] = useState(false);

  const { data: attackers, loading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsFirewallTopAttackers(timeRange, 50),
    [timeRange]),
    [timeRange],
    60000
  );

  useEffect(() => {
    if (attackers) setLastUpdated(new Date());
  }, [attackers, setLastUpdated]);

  const loadAttackerProfile = async (ip: string) => {
    setSelectedIp(ip);
    setProfileLoading(true);
    try {
      const profile = await api.getAnalyticsFirewallAttacker(ip, '30d');
      setAttackerProfile(profile);
    } catch (error) {
      console.error('Failed to load attacker profile:', error);
    } finally {
      setProfileLoading(false);
    }
  };

  const formatTime = (ts: string) => {
    try {
      return new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return ts;
    }
  };

  const attackerColumns = [
    { key: 'rank', header: '#', render: (_: any, i: number) => i + 1 },
    { key: 'ip', header: 'IP Address', render: (item: any) => (
      <button
        onClick={() => loadAttackerProfile(item.ip)}
        className={`font-mono text-sm hover:underline ${
          selectedIp === item.ip ? 'text-neon-green font-bold' : 'text-text-primary'
        }`}
      >
        {item.ip}
      </button>
    )},
    { key: 'total_attempts', header: 'Attempts', render: (item: any) => item.total_attempts.toLocaleString() },
    { key: 'blocked', header: 'Blocked', render: (item: any) => (
      <span className="text-neon-red">{item.blocked.toLocaleString()}</span>
    )},
    { key: 'block_rate', header: 'Block %', render: (item: any) => `${item.block_rate}%` },
    { key: 'unique_ports', header: 'Ports', render: (item: any) => item.unique_ports },
    { key: 'country', header: 'Country' },
    { key: 'burstiness', header: 'Burstiness', render: (item: any) => (
      <span className={`font-medium ${
        item.burstiness > 2 ? 'text-neon-red' : item.burstiness > 1 ? 'text-neon-orange' : 'text-text-muted'
      }`}>
        {item.burstiness}x
      </span>
    )},
    { key: 'last_seen', header: 'Last Seen', render: (item: any) => {
      try {
        return new Date(item.last_seen).toLocaleString();
      } catch {
        return item.last_seen;
      }
    }},
  ];

  if (loading && !attackers) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-display font-bold text-white flex items-center gap-2">
            <Users className="w-6 h-6 text-neon-purple" />
            Top Attackers Leaderboard
          </h2>
          <p className="text-sm text-text-muted mt-1">
            Click an IP to view detailed profile and timeline
          </p>
        </div>
        <ExportToolbar
          onExportCSV={() => exportToCSV(attackers?.attackers || [], 'firewall_attackers')}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Table */}
        <div className="lg:col-span-2">
          <div className="bg-bg-card rounded-xl border border-bg-hover">
            <div className="p-4 border-b border-bg-hover">
              <h3 className="font-medium text-white">All Attackers ({attackers?.attackers?.length || 0})</h3>
            </div>
            <DataTable
              columns={attackerColumns}
              data={attackers?.attackers || []}
              loading={loading}
              maxHeight="600px"
            />
          </div>
        </div>

        {/* Attacker Profile Sidebar */}
        <div className="space-y-4">
          {selectedIp && attackerProfile ? (
            <>
              <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
                <h3 className="font-medium text-white mb-4 flex items-center gap-2">
                  <Search className="w-4 h-4" />
                  Attacker Profile
                </h3>
                {profileLoading ? (
                  <LoadingSpinner />
                ) : (
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-text-muted">IP</span>
                      <IPLink ip={attackerProfile.ip} />
                    </div>
                    <div className="flex justify-between">
                      <span className="text-text-muted">Country</span>
                      <span>{attackerProfile.country}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-text-muted">ASN</span>
                      <span className="text-xs text-right max-w-[150px] truncate">{attackerProfile.asn}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-text-muted">Total Attempts</span>
                      <span className="font-mono">{attackerProfile.total_attempts?.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-text-muted">Blocked</span>
                      <span className="font-mono text-neon-red">{attackerProfile.blocked?.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-text-muted">First Seen</span>
                      <span className="text-xs">{new Date(attackerProfile.first_seen).toLocaleDateString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-text-muted">Last Seen</span>
                      <span className="text-xs">{new Date(attackerProfile.last_seen).toLocaleDateString()}</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Top Ports */}
              <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
                <h4 className="font-medium text-white mb-3">Top Targeted Ports</h4>
                <div className="h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={attackerProfile.top_ports?.slice(0, 6) || []} layout="vertical">
                      <XAxis type="number" stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                      <YAxis dataKey="port" type="category" width={40} stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid #2a2a4a' }} />
                      <Bar dataKey="count" fill="#bf00ff" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Timeline */}
              <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
                <h4 className="font-medium text-white mb-3">Activity Timeline</h4>
                <div className="h-32">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={attackerProfile.hourly_activity?.slice(-24) || []}>
                      <XAxis dataKey="timestamp" tickFormatter={formatTime} stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                      <YAxis stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid #2a2a4a' }} />
                      <Area type="monotone" dataKey="count" stroke="#bf00ff" fill="#bf00ff30" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </>
          ) : (
            <div className="bg-bg-card rounded-xl border border-bg-hover p-8 text-center">
              <Users className="w-12 h-12 text-text-muted mx-auto mb-3" />
              <p className="text-text-muted">Select an attacker to view profile</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

