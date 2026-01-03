import { useCallback, useEffect } from 'react';
import { Cpu, Clock, AlertTriangle, Zap, TrendingUp } from 'lucide-react';
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
import { KPIGrid, KPICard } from '../../components/analytics';
import LoadingSpinner from '../../components/LoadingSpinner';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

const VARIANT_COLORS: Record<string, string> = {
  plain: '#39ff14',
  openai: '#00d4ff',
  ollama: '#ff6600',
};

export default function AiPerformance() {
  const { timeRange, setLastUpdated } = useAnalytics();

  const { data: latency, loading: latencyLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsAiLatency(timeRange),
    [timeRange]),
    [timeRange],
    60000
  );

  const { data: fallback, loading: fallbackLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsAiFallback(timeRange),
    [timeRange]),
    [timeRange],
    60000
  );

  const { data: errors } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsAiErrors(timeRange),
    [timeRange]),
    [timeRange],
    60000
  );

  useEffect(() => {
    if (latency) setLastUpdated(new Date());
  }, [latency, setLastUpdated]);

  // Prepare latency comparison data
  const latencyData = latency?.variants?.map((v: any) => ({
    variant: v.variant.charAt(0).toUpperCase() + v.variant.slice(1),
    'P50': v.latency_p50,
    'P90': v.latency_p90,
    'P99': v.latency_p99,
  })) || [];

  // Prepare performance radar data
  const radarData = latency?.variants?.map((v: any) => ({
    variant: v.variant,
    sessions: v.sessions,
    commands: v.commands,
    responsiveness: Math.max(0, 100 - (v.latency_p50 / 20)), // Lower latency = higher score
  })) || [];

  return (
    <div className="space-y-6">
      {/* KPIs */}
      <KPIGrid columns={4}>
        <KPICard
          title="OpenAI Fallback Rate"
          value={`${fallback?.fallback_rate?.openai || 0}%`}
          icon={<AlertTriangle className="w-5 h-5" />}
          color={fallback?.fallback_rate?.openai > 5 ? 'orange' : 'green'}
          loading={fallbackLoading}
        />
        <KPICard
          title="Ollama Fallback Rate"
          value={`${fallback?.fallback_rate?.ollama || 0}%`}
          icon={<AlertTriangle className="w-5 h-5" />}
          color={fallback?.fallback_rate?.ollama > 5 ? 'orange' : 'green'}
          loading={fallbackLoading}
        />
        <KPICard
          title="OpenAI P50 Latency"
          value={`${latency?.variants?.find((v: any) => v.variant === 'openai')?.latency_p50 || 0}ms`}
          icon={<Clock className="w-5 h-5" />}
          color="blue"
          loading={latencyLoading}
        />
        <KPICard
          title="Ollama P50 Latency"
          value={`${latency?.variants?.find((v: any) => v.variant === 'ollama')?.latency_p50 || 0}ms`}
          icon={<Clock className="w-5 h-5" />}
          color="orange"
          loading={latencyLoading}
        />
      </KPIGrid>

      {/* Latency Comparison */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <h3 className="font-display font-bold text-white mb-4 flex items-center gap-2">
            <Clock className="w-5 h-5 text-neon-green" />
            Response Latency by Variant (ms)
          </h3>
          {latencyLoading ? (
            <div className="h-64 flex items-center justify-center">
              <LoadingSpinner />
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={latencyData}>
                  <XAxis dataKey="variant" stroke="#555" tick={{ fill: '#888', fontSize: 12 }} />
                  <YAxis stroke="#555" tick={{ fill: '#888', fontSize: 11 }} label={{ value: 'ms', angle: -90, position: 'insideLeft', fill: '#888' }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(26, 26, 37, 0.95)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                    }}
                  />
                  <Legend />
                  <Bar dataKey="P50" fill="#39ff14" name="P50 (Median)" />
                  <Bar dataKey="P90" fill="#00d4ff" name="P90" />
                  <Bar dataKey="P99" fill="#ff6600" name="P99" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Performance Radar */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <h3 className="font-display font-bold text-white mb-4 flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-neon-blue" />
            Performance Profile
          </h3>
          {latencyLoading ? (
            <div className="h-64 flex items-center justify-center">
              <LoadingSpinner />
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <RadarChart data={[
                  { metric: 'Sessions', ...radarData.reduce((acc: any, v: any) => ({ ...acc, [v.variant]: v.sessions }), {}) },
                  { metric: 'Commands', ...radarData.reduce((acc: any, v: any) => ({ ...acc, [v.variant]: v.commands }), {}) },
                  { metric: 'Responsiveness', ...radarData.reduce((acc: any, v: any) => ({ ...acc, [v.variant]: v.responsiveness }), {}) },
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

      {/* Error Rates */}
      <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
        <h3 className="font-display font-bold text-white mb-4 flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-neon-orange" />
          Error Rates by Type
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* OpenAI Errors */}
          <div>
            <h4 className="text-sm font-medium text-neon-blue mb-3">OpenAI</h4>
            <div className="space-y-2">
              {Object.entries(errors?.error_rates?.openai || {}).map(([type, rate]: [string, any]) => (
                <div key={type} className="flex items-center justify-between">
                  <span className="text-text-secondary capitalize">{type}</span>
                  <div className="flex items-center gap-2">
                    <div className="w-24 h-2 bg-bg-secondary rounded-full overflow-hidden">
                      <div
                        className="h-full bg-neon-blue rounded-full"
                        style={{ width: `${Math.min(100, rate * 20)}%` }}
                      />
                    </div>
                    <span className="text-sm font-mono text-text-primary w-12 text-right">
                      {rate}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Ollama Errors */}
          <div>
            <h4 className="text-sm font-medium text-neon-orange mb-3">Ollama</h4>
            <div className="space-y-2">
              {Object.entries(errors?.error_rates?.ollama || {}).map(([type, rate]: [string, any]) => (
                <div key={type} className="flex items-center justify-between">
                  <span className="text-text-secondary capitalize">{type}</span>
                  <div className="flex items-center gap-2">
                    <div className="w-24 h-2 bg-bg-secondary rounded-full overflow-hidden">
                      <div
                        className="h-full bg-neon-orange rounded-full"
                        style={{ width: `${Math.min(100, rate * 20)}%` }}
                      />
                    </div>
                    <span className="text-sm font-mono text-text-primary w-12 text-right">
                      {rate}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Variant Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {latency?.variants?.map((v: any) => (
          <div
            key={v.variant}
            className="bg-bg-card rounded-xl border p-4"
            style={{ borderColor: `${VARIANT_COLORS[v.variant]}30` }}
          >
            <div className="flex items-center gap-2 mb-3">
              <Cpu className="w-5 h-5" style={{ color: VARIANT_COLORS[v.variant] }} />
              <h4 className="font-display font-bold" style={{ color: VARIANT_COLORS[v.variant] }}>
                {v.variant.charAt(0).toUpperCase() + v.variant.slice(1)}
              </h4>
            </div>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-text-muted">Sessions</span>
                <span className="font-mono">{v.sessions.toLocaleString()}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-text-muted">Commands</span>
                <span className="font-mono">{v.commands.toLocaleString()}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-text-muted">Latency (P50)</span>
                <span className="font-mono">{v.latency_p50}ms</span>
              </div>
              <div className="flex justify-between">
                <span className="text-text-muted">Latency (P99)</span>
                <span className="font-mono">{v.latency_p99}ms</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Note */}
      <div className="bg-bg-card rounded-xl border border-neon-blue/30 p-4">
        <h3 className="font-display font-bold text-neon-blue mb-2 flex items-center gap-2">
          <Zap className="w-5 h-5" />
          Performance Notes
        </h3>
        <p className="text-sm text-text-secondary">
          <strong>Plain</strong> variant uses pre-configured static responses, resulting in the fastest response times.
          <strong> OpenAI</strong> uses the GPT API for dynamic responses, with latency depending on API response times.
          <strong> Ollama</strong> runs a local LLM, with performance depending on hardware capabilities.
          The "2 second target" for LLM responses ensures attackers don't timeout waiting for responses.
        </p>
      </div>
    </div>
  );
}

