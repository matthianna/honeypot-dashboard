import { useCallback, useEffect, useState } from 'react';
import { Terminal, Command, TrendingUp } from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
} from 'recharts';
import { useAnalytics } from './AnalyticsLayout';
import { KPICard, ExportToolbar, exportToCSV } from '../../components/analytics';
import DataTable from '../../components/DataTable';
import LoadingSpinner from '../../components/LoadingSpinner';
import IPLink from '../../components/IPLink';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

const VARIANT_COLORS: Record<string, string> = {
  plain: '#39ff14',
  openai: '#00d4ff',
  ollama: '#ff6600',
};

export default function CowrieSessions() {
  const { timeRange, setLastUpdated } = useAnalytics();
  const [selectedVariant, setSelectedVariant] = useState<string | null>(null);

  const { data: sessions, loading: sessionsLoading } = useApiWithRefresh(
    useCallback(() => 
      api.getAnalyticsCowrieSessions(timeRange, 50, selectedVariant || undefined),
    [timeRange, selectedVariant]),
    [timeRange, selectedVariant],
    30000
  );

  const { data: distributions, loading: distLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsCowrieDistributions(timeRange),
    [timeRange]),
    [timeRange],
    60000
  );

  useEffect(() => {
    if (sessions) setLastUpdated(new Date());
  }, [sessions, setLastUpdated]);

  const sessionColumns = [
    { 
      key: 'session_id', 
      header: 'Session ID',
      render: (item: any) => (
        <span className="font-mono text-xs">{item.session_id.slice(0, 12)}...</span>
      )
    },
    {
      key: 'variant',
      header: 'Variant',
      render: (item: any) => (
        <span 
          className="px-2 py-1 rounded text-xs font-medium"
          style={{ 
            backgroundColor: `${VARIANT_COLORS[item.variant] || '#888'}20`,
            color: VARIANT_COLORS[item.variant] || '#888'
          }}
        >
          {item.variant || 'unknown'}
        </span>
      )
    },
    {
      key: 'src_ip',
      header: 'Source IP',
      render: (item: any) => item.src_ip ? <IPLink ip={item.src_ip} /> : '-'
    },
    {
      key: 'duration',
      header: 'Duration',
      render: (item: any) => {
        const d = item.duration || 0;
        if (d < 60) return `${d.toFixed(1)}s`;
        if (d < 3600) return `${Math.floor(d / 60)}m ${Math.floor(d % 60)}s`;
        return `${Math.floor(d / 3600)}h ${Math.floor((d % 3600) / 60)}m`;
      }
    },
    {
      key: 'commands',
      header: 'Commands',
      render: (item: any) => (
        <span className={item.commands > 0 ? 'text-neon-green font-medium' : 'text-text-muted'}>
          {item.commands}
        </span>
      )
    },
    {
      key: 'login_success',
      header: 'Login',
      render: (item: any) => (
        <span className={item.login_success ? 'text-neon-green' : 'text-neon-red'}>
          {item.login_success ? 'Success' : 'Failed'}
        </span>
      )
    },
  ];

  // Prepare comparison bar chart data
  const comparisonData = distributions?.variants?.map((v: any) => ({
    variant: v.variant.charAt(0).toUpperCase() + v.variant.slice(1),
    Sessions: v.sessions,
    Commands: v.commands,
    'Unique IPs': v.unique_ips,
  })) || [];

  return (
    <div className="space-y-6">
      {/* Variant KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {distributions?.variants?.map((v: any) => (
          <div
            key={v.variant}
            onClick={() => setSelectedVariant(selectedVariant === v.variant ? null : v.variant)}
            className={`cursor-pointer transition-all ${
              selectedVariant === v.variant ? 'ring-2' : ''
            }`}
            style={{ 
              borderColor: VARIANT_COLORS[v.variant],
              ...(selectedVariant === v.variant && { ringColor: VARIANT_COLORS[v.variant] })
            }}
          >
            <KPICard
              title={v.variant.charAt(0).toUpperCase() + v.variant.slice(1)}
              value={v.sessions}
              subtitle={`${v.commands} commands • ${v.unique_ips} IPs`}
              icon={<Terminal className="w-5 h-5" />}
              color={v.variant === 'plain' ? 'green' : v.variant === 'openai' ? 'blue' : 'orange'}
              loading={distLoading}
            />
          </div>
        ))}
      </div>

      {/* Filter indicator */}
      {selectedVariant && (
        <div className="flex items-center gap-2 text-sm">
          <span className="text-text-muted">Filtering by:</span>
          <span 
            className="px-2 py-1 rounded font-medium"
            style={{ 
              backgroundColor: `${VARIANT_COLORS[selectedVariant]}20`,
              color: VARIANT_COLORS[selectedVariant]
            }}
          >
            {selectedVariant}
          </span>
          <button
            onClick={() => setSelectedVariant(null)}
            className="text-neon-red hover:underline"
          >
            Clear
          </button>
        </div>
      )}

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Comparison Bar Chart */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <h3 className="font-display font-bold text-white mb-4 flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-neon-green" />
            Variant Comparison
          </h3>
          {distLoading ? (
            <div className="h-64 flex items-center justify-center">
              <LoadingSpinner />
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={comparisonData}>
                  <XAxis dataKey="variant" stroke="#555" tick={{ fill: '#888', fontSize: 12 }} />
                  <YAxis stroke="#555" tick={{ fill: '#888', fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(26, 26, 37, 0.95)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                    }}
                  />
                  <Legend />
                  <Bar dataKey="Sessions" fill="#39ff14" />
                  <Bar dataKey="Commands" fill="#00d4ff" />
                  <Bar dataKey="Unique IPs" fill="#ff6600" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Engagement Radar */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <h3 className="font-display font-bold text-white mb-4 flex items-center gap-2">
            <Command className="w-5 h-5 text-neon-blue" />
            Engagement Profile
          </h3>
          {distLoading ? (
            <div className="h-64 flex items-center justify-center">
              <LoadingSpinner />
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <RadarChart data={[
                  { metric: 'Sessions', plain: distributions?.variants?.find((v: any) => v.variant === 'plain')?.sessions || 0, openai: distributions?.variants?.find((v: any) => v.variant === 'openai')?.sessions || 0, ollama: distributions?.variants?.find((v: any) => v.variant === 'ollama')?.sessions || 0 },
                  { metric: 'Commands', plain: distributions?.variants?.find((v: any) => v.variant === 'plain')?.commands || 0, openai: distributions?.variants?.find((v: any) => v.variant === 'openai')?.commands || 0, ollama: distributions?.variants?.find((v: any) => v.variant === 'ollama')?.commands || 0 },
                  { metric: 'Unique IPs', plain: distributions?.variants?.find((v: any) => v.variant === 'plain')?.unique_ips || 0, openai: distributions?.variants?.find((v: any) => v.variant === 'openai')?.unique_ips || 0, ollama: distributions?.variants?.find((v: any) => v.variant === 'ollama')?.unique_ips || 0 },
                  { metric: 'Login Success', plain: distributions?.variants?.find((v: any) => v.variant === 'plain')?.login_success || 0, openai: distributions?.variants?.find((v: any) => v.variant === 'openai')?.login_success || 0, ollama: distributions?.variants?.find((v: any) => v.variant === 'ollama')?.login_success || 0 },
                ]}>
                  <PolarGrid stroke="#333" />
                  <PolarAngleAxis dataKey="metric" tick={{ fill: '#888', fontSize: 11 }} />
                  <PolarRadiusAxis tick={{ fill: '#888', fontSize: 10 }} />
                  <Radar name="Plain" dataKey="plain" stroke="#39ff14" fill="#39ff14" fillOpacity={0.3} />
                  <Radar name="OpenAI" dataKey="openai" stroke="#00d4ff" fill="#00d4ff" fillOpacity={0.3} />
                  <Radar name="Ollama" dataKey="ollama" stroke="#ff6600" fill="#ff6600" fillOpacity={0.3} />
                  <Legend />
                </RadarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Sessions Table */}
      <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-display font-bold text-white flex items-center gap-2">
            <Terminal className="w-5 h-5 text-neon-green" />
            Session List
            {selectedVariant && <span className="text-sm text-text-muted">({selectedVariant})</span>}
          </h3>
          <ExportToolbar
            onExportCSV={() => exportToCSV(sessions?.sessions || [], 'cowrie_sessions')}
          />
        </div>
        <DataTable
          columns={sessionColumns}
          data={sessions?.sessions || []}
          loading={sessionsLoading}
          maxHeight="400px"
        />
      </div>
    </div>
  );
}

