import { useCallback, useEffect } from 'react';
import { Monitor, Users, Globe, Clock } from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  LineChart,
  Line,
} from 'recharts';
import { useAnalytics } from './AnalyticsLayout';
import { KPIGrid, KPICard, ExportToolbar, exportToCSV, exportToPNG } from '../../components/analytics';
import DataTable from '../../components/DataTable';
import LoadingSpinner from '../../components/LoadingSpinner';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

export default function RdpOverview() {
  const { timeRange, setLastUpdated } = useAnalytics();

  const { data: summary, loading: summaryLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsRdpSummary(timeRange),
    [timeRange]),
    [timeRange],
    60000
  );

  const { data: timeline, loading: timelineLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsRdpTimeline(timeRange),
    [timeRange]),
    [timeRange],
    60000
  );

  useEffect(() => {
    if (summary) setLastUpdated(new Date());
  }, [summary, setLastUpdated]);

  const formatTime = (ts: string) => {
    try {
      return new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return ts;
    }
  };

  const countryColumns = [
    { key: 'rank', header: '#', render: (_: any, i: number) => i + 1 },
    { key: 'country', header: 'Country' },
    { key: 'count', header: 'Connections', render: (item: any) => item.count.toLocaleString() },
    { key: 'percentage', header: '%', render: (item: any) => {
      const total = summary?.total_events || 1;
      return `${((item.count / total) * 100).toFixed(1)}%`;
    }},
  ];

  return (
    <div className="space-y-6">
      {/* KPIs */}
      <KPIGrid columns={4}>
        <KPICard
          title="Total Connections"
          value={summary?.total_events || 0}
          icon={<Monitor className="w-5 h-5" />}
          color="purple"
          loading={summaryLoading}
        />
        <KPICard
          title="Unique Attackers"
          value={summary?.unique_attackers || 0}
          icon={<Users className="w-5 h-5" />}
          color="blue"
          loading={summaryLoading}
        />
        <KPICard
          title="Countries"
          value={summary?.top_countries?.length || 0}
          icon={<Globe className="w-5 h-5" />}
          color="orange"
          loading={summaryLoading}
        />
        <KPICard
          title="Top Country"
          value={summary?.top_countries?.[0]?.country || '-'}
          subtitle={`${summary?.top_countries?.[0]?.count?.toLocaleString() || 0} connections`}
          icon={<Globe className="w-5 h-5" />}
          color="green"
          loading={summaryLoading}
        />
      </KPIGrid>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Connection Timeline */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display font-bold text-white flex items-center gap-2">
              <Clock className="w-5 h-5 text-neon-purple" />
              Connection Timeline
            </h3>
            <ExportToolbar
              onExportPNG={() => exportToPNG('rdp-timeline', 'rdp_timeline')}
            />
          </div>
          <div id="rdp-timeline" className="h-64">
            {timelineLoading ? (
              <div className="h-full flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeline?.timeline || []}>
                  <defs>
                    <linearGradient id="rdpGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#bf00ff" stopOpacity={0.4} />
                      <stop offset="100%" stopColor="#bf00ff" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis
                    dataKey="timestamp"
                    tickFormatter={formatTime}
                    stroke="#555"
                    tick={{ fill: '#888', fontSize: 11 }}
                    axisLine={false}
                  />
                  <YAxis stroke="#555" tick={{ fill: '#888', fontSize: 11 }} axisLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(26, 26, 37, 0.95)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                    }}
                    labelFormatter={formatTime}
                  />
                  <Area
                    type="monotone"
                    dataKey="connections"
                    stroke="#bf00ff"
                    fill="url(#rdpGradient)"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Unique IPs Over Time */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <h3 className="font-display font-bold text-white mb-4 flex items-center gap-2">
            <Users className="w-5 h-5 text-neon-blue" />
            Unique IPs Over Time
          </h3>
          <div className="h-64">
            {timelineLoading ? (
              <div className="h-full flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={timeline?.timeline || []}>
                  <XAxis
                    dataKey="timestamp"
                    tickFormatter={formatTime}
                    stroke="#555"
                    tick={{ fill: '#888', fontSize: 11 }}
                    axisLine={false}
                  />
                  <YAxis stroke="#555" tick={{ fill: '#888', fontSize: 11 }} axisLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(26, 26, 37, 0.95)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                    }}
                    labelFormatter={formatTime}
                  />
                  <Line
                    type="monotone"
                    dataKey="unique_ips"
                    stroke="#00d4ff"
                    strokeWidth={2}
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Top Countries */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Country Bar Chart */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <h3 className="font-display font-bold text-white mb-4 flex items-center gap-2">
            <Globe className="w-5 h-5 text-neon-orange" />
            Top Attack Origins
          </h3>
          {summaryLoading ? (
            <div className="h-64 flex items-center justify-center">
              <LoadingSpinner />
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={summary?.top_countries?.slice(0, 8) || []} layout="vertical">
                  <XAxis type="number" stroke="#555" tick={{ fill: '#888', fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="country"
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
                  />
                  <Bar dataKey="count" fill="#bf00ff" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Country Table */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display font-bold text-white">Country Details</h3>
            <ExportToolbar
              onExportCSV={() => exportToCSV(summary?.top_countries || [], 'rdp_countries')}
            />
          </div>
          <DataTable
            columns={countryColumns}
            data={summary?.top_countries || []}
            loading={summaryLoading}
            maxHeight="250px"
          />
        </div>
      </div>

      {/* Info Box */}
      <div className="bg-bg-card rounded-xl border border-neon-purple/30 p-4">
        <h3 className="font-display font-bold text-neon-purple mb-2 flex items-center gap-2">
          <Monitor className="w-5 h-5" />
          About RDP Honeypot (RDPY)
        </h3>
        <p className="text-sm text-text-secondary">
          RDPY simulates a Windows Remote Desktop server to attract and log RDP brute-force attacks.
          It captures connection attempts, authentication failures, and client information from
          attackers attempting to gain unauthorized access via RDP (port 3389).
        </p>
      </div>
    </div>
  );
}

