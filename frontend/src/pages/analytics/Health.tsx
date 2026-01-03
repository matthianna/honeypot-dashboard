import { useCallback, useEffect } from 'react';
import { HeartPulse, CheckCircle, AlertTriangle, XCircle, Database } from 'lucide-react';
import { useAnalytics } from './AnalyticsLayout';
import { KPIGrid, KPICard } from '../../components/analytics';
import LoadingSpinner from '../../components/LoadingSpinner';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

const HONEYPOT_COLORS: Record<string, string> = {
  cowrie: '#39ff14',
  dionaea: '#00d4ff',
  galah: '#ff6600',
  rdpy: '#bf00ff',
  heralding: '#ff3366',
  firewall: '#ffff00',
};

export default function Health() {
  const { timeRange, setLastUpdated } = useAnalytics();

  const { data: health, loading: healthLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsHealth(),
    []),
    [],
    30000
  );

  const { data: coverage, loading: coverageLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsHealthCoverage(timeRange),
    [timeRange]),
    [timeRange],
    60000
  );

  useEffect(() => {
    if (health) setLastUpdated(new Date());
  }, [health, setLastUpdated]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle className="w-5 h-5 text-neon-green" />;
      case 'warning':
        return <AlertTriangle className="w-5 h-5 text-neon-orange" />;
      case 'stale':
      case 'error':
        return <XCircle className="w-5 h-5 text-neon-red" />;
      default:
        return <Database className="w-5 h-5 text-text-muted" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'border-neon-green/30 bg-neon-green/5';
      case 'warning':
        return 'border-neon-orange/30 bg-neon-orange/5';
      case 'stale':
      case 'error':
        return 'border-neon-red/30 bg-neon-red/5';
      default:
        return 'border-bg-hover bg-bg-secondary';
    }
  };

  // Get all unique protocols from coverage matrix
  const allProtocols = coverage?.matrix 
    ? [...new Set(Object.values(coverage.matrix).flatMap((hp: any) => Object.keys(hp)))]
    : [];

  return (
    <div className="space-y-6">
      {/* Summary KPIs */}
      <KPIGrid columns={4}>
        <KPICard
          title="Healthy Honeypots"
          value={`${health?.summary?.healthy || 0} / ${health?.summary?.total || 0}`}
          icon={<HeartPulse className="w-5 h-5" />}
          color={health?.summary?.overall_status === 'healthy' ? 'green' : health?.summary?.overall_status === 'degraded' ? 'orange' : 'red'}
          loading={healthLoading}
        />
        <KPICard
          title="Overall Status"
          value={health?.summary?.overall_status?.toUpperCase() || 'UNKNOWN'}
          icon={getStatusIcon(health?.summary?.overall_status)}
          color={health?.summary?.overall_status === 'healthy' ? 'green' : 'orange'}
          loading={healthLoading}
        />
        <KPICard
          title="Protocols Covered"
          value={allProtocols.length}
          icon={<Database className="w-5 h-5" />}
          color="blue"
          loading={coverageLoading}
        />
        <KPICard
          title="Active Indices"
          value={health?.honeypots?.filter((h: any) => h.events_24h > 0).length || 0}
          icon={<CheckCircle className="w-5 h-5" />}
          color="purple"
          loading={healthLoading}
        />
      </KPIGrid>

      {/* Honeypot Status Cards */}
      <div>
        <h3 className="text-lg font-display font-bold text-white mb-4">Honeypot Status</h3>
        {healthLoading ? (
          <div className="flex items-center justify-center py-12">
            <LoadingSpinner />
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {health?.honeypots?.map((hp: any) => (
              <div
                key={hp.id}
                className={`p-4 rounded-xl border ${getStatusColor(hp.status)}`}
              >
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <h4 className="font-medium text-white">{hp.name}</h4>
                    <p className="text-xs text-text-muted">{hp.index}</p>
                  </div>
                  {getStatusIcon(hp.status)}
                </div>
                
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <div className="text-text-muted text-xs">Last 1h</div>
                    <div className="font-mono" style={{ color: HONEYPOT_COLORS[hp.id] }}>
                      {hp.events_1h?.toLocaleString() || 0}
                    </div>
                  </div>
                  <div>
                    <div className="text-text-muted text-xs">Last 24h</div>
                    <div className="font-mono" style={{ color: HONEYPOT_COLORS[hp.id] }}>
                      {hp.events_24h?.toLocaleString() || 0}
                    </div>
                  </div>
                </div>

                {hp.last_event && (
                  <div className="mt-3 pt-3 border-t border-bg-hover text-xs text-text-muted">
                    Last event: {hp.minutes_since_last != null ? (
                      hp.minutes_since_last < 1 ? '<1 min ago' : `${Math.round(hp.minutes_since_last)} min ago`
                    ) : 'Unknown'}
                  </div>
                )}

                {hp.error && (
                  <div className="mt-2 text-xs text-neon-red">{hp.error}</div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Coverage Matrix */}
      <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
        <h3 className="text-lg font-display font-bold text-white mb-4">Protocol Coverage Matrix</h3>
        {coverageLoading ? (
          <div className="flex items-center justify-center py-12">
            <LoadingSpinner />
          </div>
        ) : coverage?.matrix ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-bg-hover">
                  <th className="px-4 py-3 text-left text-xs font-semibold text-text-secondary uppercase">
                    Honeypot
                  </th>
                  {allProtocols.map((proto) => (
                    <th
                      key={proto}
                      className="px-4 py-3 text-center text-xs font-semibold text-text-secondary uppercase"
                    >
                      {proto}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {Object.entries(coverage.matrix).map(([hp, protocols]: [string, any]) => (
                  <tr key={hp} className="border-b border-bg-hover">
                    <td className="px-4 py-3 font-medium" style={{ color: HONEYPOT_COLORS[hp] }}>
                      {hp.charAt(0).toUpperCase() + hp.slice(1)}
                    </td>
                    {allProtocols.map((proto) => {
                      const count = protocols[proto] || 0;
                      return (
                        <td key={proto} className="px-4 py-3 text-center">
                          {count > 0 ? (
                            <span className="px-2 py-1 bg-neon-green/20 text-neon-green text-xs rounded-full font-mono">
                              {count.toLocaleString()}
                            </span>
                          ) : (
                            <span className="text-text-muted">-</span>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8 text-text-muted">No coverage data available</div>
        )}
      </div>
    </div>
  );
}

