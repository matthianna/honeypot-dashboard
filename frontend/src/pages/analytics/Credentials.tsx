import { useCallback, useEffect, useState } from 'react';
import { Key, Users, Lock, RefreshCw } from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { useAnalytics } from './AnalyticsLayout';
import { KPIGrid, KPICard, ExportToolbar, exportToCSV } from '../../components/analytics';
import DataTable from '../../components/DataTable';
import LoadingSpinner from '../../components/LoadingSpinner';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

export default function Credentials() {
  const { timeRange, setLastUpdated } = useAnalytics();
  const [showPasswords, setShowPasswords] = useState(false);

  const { data: topCreds, loading: topLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsCredentialsTop(timeRange, 20),
    [timeRange]),
    [timeRange],
    60000
  );

  const { data: pairs, loading: pairsLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsCredentialsPairs(timeRange, 30),
    [timeRange]),
    [timeRange],
    60000
  );

  const { data: reuse, loading: reuseLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsCredentialsReuse(timeRange),
    [timeRange]),
    [timeRange],
    60000
  );

  useEffect(() => {
    if (topCreds) setLastUpdated(new Date());
  }, [topCreds, setLastUpdated]);

  const maskPassword = (password: string) => {
    if (showPasswords) return password;
    if (password.length <= 2) return '**';
    return password[0] + '*'.repeat(password.length - 2) + password[password.length - 1];
  };

  const usernameColumns = [
    { key: 'rank', header: '#', render: (_: any, i: number) => i + 1 },
    { key: 'username', header: 'Username', render: (item: any) => (
      <span className="font-mono text-neon-green">{item.username}</span>
    )},
    { key: 'count', header: 'Attempts', render: (item: any) => item.count.toLocaleString() },
  ];

  const passwordColumns = [
    { key: 'rank', header: '#', render: (_: any, i: number) => i + 1 },
    { key: 'password', header: 'Password', render: (item: any) => (
      <span className="font-mono text-neon-orange">{maskPassword(item.password)}</span>
    )},
    { key: 'count', header: 'Attempts', render: (item: any) => item.count.toLocaleString() },
  ];

  const pairColumns = [
    { key: 'rank', header: '#', render: (_: any, i: number) => i + 1 },
    { key: 'username', header: 'Username', render: (item: any) => (
      <span className="font-mono text-neon-green">{item.username}</span>
    )},
    { key: 'password', header: 'Password', render: (item: any) => (
      <span className="font-mono text-neon-orange">{maskPassword(item.password)}</span>
    )},
    { key: 'count', header: 'Attempts', render: (item: any) => item.count.toLocaleString() },
  ];

  return (
    <div className="space-y-6">
      {/* KPIs */}
      <KPIGrid columns={4}>
        <KPICard
          title="Unique Usernames"
          value={topCreds?.usernames?.length || 0}
          icon={<Users className="w-5 h-5" />}
          color="green"
          loading={topLoading}
        />
        <KPICard
          title="Unique Passwords"
          value={topCreds?.passwords?.length || 0}
          icon={<Lock className="w-5 h-5" />}
          color="orange"
          loading={topLoading}
        />
        <KPICard
          title="Unique Combinations"
          value={pairs?.total_unique_pairs || 0}
          icon={<Key className="w-5 h-5" />}
          color="blue"
          loading={pairsLoading}
        />
        <KPICard
          title="Reused Passwords"
          value={reuse?.reused_passwords?.length || 0}
          icon={<RefreshCw className="w-5 h-5" />}
          color="red"
          loading={reuseLoading}
        />
      </KPIGrid>

      {/* Toggle Password Visibility */}
      <div className="flex justify-end">
        <button
          onClick={() => setShowPasswords(!showPasswords)}
          className="flex items-center gap-2 px-4 py-2 bg-bg-card border border-bg-hover rounded-lg text-sm text-text-secondary hover:text-text-primary hover:border-neon-green/50 transition-colors"
        >
          <Lock className="w-4 h-4" />
          {showPasswords ? 'Hide Passwords' : 'Show Passwords'}
        </button>
      </div>

      {/* Top Usernames & Passwords */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Usernames */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display font-bold text-white flex items-center gap-2">
              <Users className="w-5 h-5 text-neon-green" />
              Top Usernames
            </h3>
            <ExportToolbar
              onExportCSV={() => exportToCSV(topCreds?.usernames || [], 'top_usernames')}
            />
          </div>
          <DataTable
            columns={usernameColumns}
            data={topCreds?.usernames?.slice(0, 15) || []}
            loading={topLoading}
            maxHeight="350px"
          />
        </div>

        {/* Passwords */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display font-bold text-white flex items-center gap-2">
              <Lock className="w-5 h-5 text-neon-orange" />
              Top Passwords
            </h3>
            <ExportToolbar
              onExportCSV={() => exportToCSV(topCreds?.passwords || [], 'top_passwords')}
            />
          </div>
          <DataTable
            columns={passwordColumns}
            data={topCreds?.passwords?.slice(0, 15) || []}
            loading={topLoading}
            maxHeight="350px"
          />
        </div>
      </div>

      {/* Credential Pairs */}
      <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-display font-bold text-white flex items-center gap-2">
            <Key className="w-5 h-5 text-neon-blue" />
            Username / Password Pairs
          </h3>
          <ExportToolbar
            onExportCSV={() => exportToCSV(pairs?.pairs || [], 'credential_pairs')}
          />
        </div>
        <DataTable
          columns={pairColumns}
          data={pairs?.pairs || []}
          loading={pairsLoading}
          maxHeight="400px"
        />
      </div>

      {/* Credential Reuse */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Reused Passwords */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <h3 className="font-display font-bold text-white mb-4 flex items-center gap-2">
            <RefreshCw className="w-5 h-5 text-neon-red" />
            Passwords Used by Multiple IPs
          </h3>
          {reuseLoading ? (
            <div className="flex items-center justify-center py-8">
              <LoadingSpinner />
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={reuse?.reused_passwords?.slice(0, 10) || []}
                  layout="vertical"
                >
                  <XAxis type="number" stroke="#555" tick={{ fill: '#888', fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="password"
                    stroke="#555"
                    tick={{ fill: '#888', fontSize: 11 }}
                    width={100}
                    tickFormatter={(v) => maskPassword(v)}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(26, 26, 37, 0.95)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                    }}
                    formatter={(value: number) => [`${value} IPs`, 'Used by']}
                    labelFormatter={(label) => maskPassword(label)}
                  />
                  <Bar dataKey="ip_count" fill="#ff3366" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Reused Usernames */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <h3 className="font-display font-bold text-white mb-4 flex items-center gap-2">
            <Users className="w-5 h-5 text-neon-purple" />
            Usernames Used by Multiple IPs
          </h3>
          {reuseLoading ? (
            <div className="flex items-center justify-center py-8">
              <LoadingSpinner />
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={reuse?.reused_usernames?.slice(0, 10) || []}
                  layout="vertical"
                >
                  <XAxis type="number" stroke="#555" tick={{ fill: '#888', fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="username"
                    stroke="#555"
                    tick={{ fill: '#888', fontSize: 11 }}
                    width={100}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(26, 26, 37, 0.95)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                    }}
                    formatter={(value: number) => [`${value} IPs`, 'Used by']}
                  />
                  <Bar dataKey="ip_count" fill="#bf00ff" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

