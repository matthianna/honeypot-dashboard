import { useCallback } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  Users,
  Globe,
  AlertTriangle,
  ArrowRight,
  TrendingUp,
  Zap,
  Shield,
  Terminal,
  Eye,
  Crosshair,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  LineChart,
  Line,
} from 'recharts';
import Card, { CardHeader, CardContent } from '../components/Card';
import StatsCard from '../components/StatsCard';
import TimeRangeSelector from '../components/TimeRangeSelector';
import DataTable from '../components/DataTable';
import IPLink from '../components/IPLink';
import LoadingSpinner from '../components/LoadingSpinner';
import MitreHeatmap from '../components/MitreHeatmap';
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import { HONEYPOT_COLORS, HONEYPOT_NAMES, HoneypotType } from '../types';
import type { TopAttacker } from '../types';

export default function Dashboard() {
  const { timeRange, setTimeRange } = useTimeRange('24h');

  const { data: overview, loading: overviewLoading } = useApiWithRefresh(
    useCallback(() => api.getDashboardOverview(timeRange), [timeRange]),
    [timeRange],
    30000
  );

  const { data: topAttackers, loading: attackersLoading } = useApiWithRefresh(
    useCallback(() => api.getTopAttackers(timeRange, 10), [timeRange]),
    [timeRange],
    30000
  );

  const { data: timeline, loading: timelineLoading } = useApiWithRefresh(
    useCallback(() => api.getDashboardTimeline(timeRange), [timeRange]),
    [timeRange],
    30000
  );

  const { data: geoStats, loading: geoLoading } = useApiWithRefresh(
    useCallback(() => api.getGeoStats(timeRange), [timeRange]),
    [timeRange],
    30000
  );

  const { data: protocolDist, loading: protocolLoading } = useApiWithRefresh(
    useCallback(() => api.getProtocolDistribution(timeRange), [timeRange]),
    [timeRange],
    30000
  );

  const { data: velocity, loading: velocityLoading } = useApiWithRefresh(
    useCallback(() => api.getAttackVelocity(), []),
    [],
    10000
  );

  const { data: threatSummary, loading: threatLoading } = useApiWithRefresh(
    useCallback(() => api.getThreatSummary(timeRange), [timeRange]),
    [timeRange],
    30000
  );

  const { data: threatIntel, loading: threatIntelLoading } = useApiWithRefresh(
    useCallback(() => api.getThreatIntel(timeRange), [timeRange]),
    [timeRange],
    60000
  );

  const { data: topActors, loading: topActorsLoading } = useApiWithRefresh(
    useCallback(() => api.getTopThreatActors(timeRange), [timeRange]),
    [timeRange],
    60000
  );

  const formatTimestamp = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return timestamp;
    }
  };

  const attackerColumns = [
    {
      key: 'rank',
      header: '#',
      render: (_: TopAttacker, index: number) => (
        <span className="text-text-secondary">{index + 1}</span>
      ),
    },
    {
      key: 'ip',
      header: 'IP Address',
      render: (item: TopAttacker) => <IPLink ip={item.ip} />,
    },
    {
      key: 'count',
      header: 'Events',
      render: (item: TopAttacker) => (
        <span className="font-mono text-neon-green">{item.count.toLocaleString()}</span>
      ),
    },
    {
      key: 'country',
      header: 'Country',
      render: (item: TopAttacker) => (
        <span className="text-text-secondary">{item.country || 'Unknown'}</span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header with time range */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-display font-semibold text-text-primary">
            Security Overview
          </h2>
          <p className="text-sm text-text-secondary mt-1">
            Real-time honeypot monitoring and threat intelligence
          </p>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>

      {/* Main Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard
          title="Total Events"
          value={overview?.total_events || 0}
          icon={<Activity className="w-5 h-5" />}
          color="green"
          loading={overviewLoading}
        />
        <StatsCard
          title="Unique Attackers"
          value={overview?.total_unique_ips || 0}
          icon={<Users className="w-5 h-5" />}
          color="blue"
          loading={overviewLoading}
        />
        <StatsCard
          title="Countries"
          value={geoStats?.data?.length || 0}
          icon={<Globe className="w-5 h-5" />}
          color="purple"
          loading={geoLoading}
        />
        <StatsCard
          title="Active Honeypots"
          value={overview?.honeypots?.filter((h) => h.total_events > 0).length || 0}
          icon={<AlertTriangle className="w-5 h-5" />}
          color="orange"
          loading={overviewLoading}
        />
      </div>

      {/* Honeypot Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {overviewLoading
          ? Array.from({ length: 6 }).map((_, i) => (
              <div
                key={i}
                className="bg-bg-card rounded-xl p-4 animate-pulse border border-bg-hover"
              >
                <div className="h-4 bg-bg-hover rounded w-2/3 mb-3" />
                <div className="h-6 bg-bg-hover rounded w-1/2" />
              </div>
            ))
          : overview?.honeypots?.map((honeypot) => {
              const color = HONEYPOT_COLORS[honeypot.name as HoneypotType];
              const name = HONEYPOT_NAMES[honeypot.name as HoneypotType] || honeypot.name;
              const path = `/${honeypot.name}`;

              return (
                <Link
                  key={honeypot.name}
                  to={path}
                  className="bg-bg-card rounded-xl p-4 border border-bg-hover hover:border-opacity-50 transition-all card-hover"
                  style={{ borderColor: `${color}30` }}
                >
                  <div className="text-xs text-text-secondary mb-2">{name}</div>
                  <div className="font-display font-bold text-xl" style={{ color }}>
                    {honeypot.total_events.toLocaleString()}
                  </div>
                  <div className="text-xs text-text-muted mt-1">
                    {honeypot.unique_ips} IPs
                  </div>
                </Link>
              );
            })}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Chart */}
        <Card className="lg:col-span-2">
          <CardHeader
            title="Attack Timeline"
            subtitle="Events over time"
            icon={<TrendingUp className="w-5 h-5" />}
          />
          <CardContent>
            {timelineLoading ? (
              <div className="h-64 flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timeline?.data || []}>
                    <defs>
                      <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#39ff14" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#39ff14" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                    <XAxis
                      dataKey="timestamp"
                      tickFormatter={formatTimestamp}
                      stroke="#888888"
                      tick={{ fill: '#888888', fontSize: 12 }}
                    />
                    <YAxis stroke="#888888" tick={{ fill: '#888888', fontSize: 12 }} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1a1a25',
                        border: '1px solid #252532',
                        borderRadius: '8px',
                        color: '#e0e0e0',
                      }}
                      labelFormatter={formatTimestamp}
                    />
                    <Area
                      type="monotone"
                      dataKey="count"
                      stroke="#39ff14"
                      fill="url(#colorEvents)"
                      strokeWidth={2}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Geographic Distribution */}
        <Card>
          <CardHeader
            title="Top Countries"
            subtitle="Attack origins"
            icon={<Globe className="w-5 h-5" />}
          />
          <CardContent>
            {geoLoading ? (
              <div className="h-64 flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={geoStats?.data?.slice(0, 5) || []}
                      dataKey="count"
                      nameKey="country"
                      cx="50%"
                      cy="50%"
                      innerRadius={40}
                      outerRadius={80}
                      paddingAngle={2}
                    >
                      {geoStats?.data?.slice(0, 5).map((_, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={
                            ['#39ff14', '#00d4ff', '#ff6600', '#bf00ff', '#ff3366'][
                              index % 5
                            ]
                          }
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1a1a25',
                        border: '1px solid #252532',
                        borderRadius: '8px',
                        color: '#e0e0e0',
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="space-y-2 mt-4">
                  {geoStats?.data?.slice(0, 5).map((geo, index) => (
                    <div key={geo.country} className="flex items-center justify-between text-sm">
                      <div className="flex items-center">
                        <div
                          className="w-3 h-3 rounded-full mr-2"
                          style={{
                            backgroundColor: ['#39ff14', '#00d4ff', '#ff6600', '#bf00ff', '#ff3366'][index % 5],
                          }}
                        />
                        <span className="text-text-primary">{geo.country}</span>
                      </div>
                      <span className="text-text-secondary">{geo.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Top Attackers */}
      <Card>
        <CardHeader
          title="Top Attackers"
          subtitle="Most active threat actors"
          icon={<AlertTriangle className="w-5 h-5" />}
          action={
            <Link
              to="/attack-map"
              className="flex items-center text-sm text-neon-blue hover:text-neon-green transition-colors"
            >
              View Map
              <ArrowRight className="w-4 h-4 ml-1" />
            </Link>
          }
        />
        <CardContent className="p-0">
          <DataTable
            columns={attackerColumns}
            data={topAttackers?.data || []}
            loading={attackersLoading}
            emptyMessage="No attackers detected"
          />
        </CardContent>
      </Card>

      {/* Protocol Distribution and Attack Velocity Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Protocol Distribution */}
        <Card>
          <CardHeader
            title="Protocol Distribution"
            subtitle="Attack traffic by protocol"
            icon={<Shield className="w-5 h-5" />}
          />
          <CardContent>
            {protocolLoading ? (
              <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={protocolDist?.protocols?.slice(0, 8) || []} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                    <XAxis type="number" stroke="#888888" tick={{ fill: '#888888', fontSize: 12 }} />
                    <YAxis 
                      type="category" 
                      dataKey="protocol" 
                      stroke="#888888" 
                      tick={{ fill: '#888888', fontSize: 11 }} 
                      width={100}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1a1a25',
                        border: '1px solid #252532',
                        borderRadius: '8px',
                        color: '#e0e0e0',
                      }}
                      formatter={(value: number) => [value.toLocaleString(), 'Events']}
                    />
                    <Bar 
                      dataKey="count" 
                      fill="#00d4ff" 
                      radius={[0, 4, 4, 0]}
                    />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Attack Velocity */}
        <Card>
          <CardHeader
            title="Attack Velocity"
            subtitle="Events per minute (last hour)"
            icon={<Zap className="w-5 h-5" />}
          />
          <CardContent>
            {velocityLoading ? (
              <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <>
                <div className="grid grid-cols-3 gap-4 mb-4">
                  <div className="bg-bg-card rounded-lg p-3 border border-bg-hover">
                    <div className="text-xs text-text-secondary mb-1">Current</div>
                    <div className="text-xl font-display font-bold text-neon-green">
                      {velocity?.stats?.current_per_minute || 0}
                    </div>
                    <div className="text-xs text-text-muted">/min</div>
                  </div>
                  <div className="bg-bg-card rounded-lg p-3 border border-bg-hover">
                    <div className="text-xs text-text-secondary mb-1">Average</div>
                    <div className="text-xl font-display font-bold text-neon-blue">
                      {velocity?.stats?.avg_per_minute || 0}
                    </div>
                    <div className="text-xs text-text-muted">/min</div>
                  </div>
                  <div className="bg-bg-card rounded-lg p-3 border border-bg-hover">
                    <div className="text-xs text-text-secondary mb-1">Peak</div>
                    <div className="text-xl font-display font-bold text-neon-orange">
                      {velocity?.stats?.max_per_minute || 0}
                    </div>
                    <div className="text-xs text-text-muted">/min</div>
                  </div>
                </div>
                <div className="h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={velocity?.velocity || []}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis 
                        dataKey="timestamp" 
                        tickFormatter={(ts) => new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                        stroke="#888888"
                        tick={{ fill: '#888888', fontSize: 10 }}
                        interval="preserveStartEnd"
                      />
                      <YAxis stroke="#888888" tick={{ fill: '#888888', fontSize: 10 }} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1a1a25',
                          border: '1px solid #252532',
                          borderRadius: '8px',
                          color: '#e0e0e0',
                        }}
                        labelFormatter={(ts) => new Date(ts).toLocaleTimeString()}
                        formatter={(value: number) => [value, 'Events']}
                      />
                      <Line 
                        type="monotone" 
                        dataKey="count" 
                        stroke="#39ff14" 
                        strokeWidth={2}
                        dot={false}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Threat Summary */}
      <Card>
        <CardHeader
          title="Threat Categories"
          subtitle="Attack types detected"
          icon={<Crosshair className="w-5 h-5" />}
        />
        <CardContent>
          {threatLoading ? (
            <div className="h-24 flex items-center justify-center"><LoadingSpinner /></div>
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              {[
                { key: 'login_attempts', label: 'Login Attempts', icon: Terminal, color: 'text-neon-green' },
                { key: 'command_execution', label: 'Commands Executed', icon: Terminal, color: 'text-neon-blue' },
                { key: 'web_attacks', label: 'Web Attacks', icon: Globe, color: 'text-neon-orange' },
                { key: 'credential_harvesting', label: 'Credential Attempts', icon: Eye, color: 'text-neon-purple' },
                { key: 'port_scans', label: 'Unique Ports Targeted', icon: Crosshair, color: 'text-neon-red' },
              ].map(({ key, label, icon: Icon, color }) => (
                <div key={key} className="bg-bg-card rounded-lg p-4 border border-bg-hover">
                  <div className="flex items-center gap-2 mb-2">
                    <Icon className={`w-4 h-4 ${color}`} />
                    <span className="text-xs text-text-secondary">{label}</span>
                  </div>
                  <div className={`text-2xl font-display font-bold ${color}`}>
                    {(threatSummary?.summary?.[key] || 0).toLocaleString()}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* MITRE ATT&CK Coverage */}
      <MitreHeatmap timeRange={timeRange} />

      {/* Threat Intelligence */}
      <Card>
        <CardHeader
          title="Cross-Honeypot Threat Intelligence"
          subtitle={`${threatIntel?.summary?.multi_honeypot_attackers || 0} attackers targeting multiple honeypots (${threatIntel?.summary?.multi_percentage || 0}%)`}
          icon={<AlertTriangle className="w-5 h-5" />}
        />
        <CardContent>
          {threatIntelLoading || topActorsLoading ? (
            <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Top Threat Actors */}
              <div>
                <h4 className="text-sm font-medium text-text-secondary mb-3">Top Threat Actors (by diversity + volume)</h4>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {topActors?.threat_actors?.slice(0, 10).map((actor, index) => (
                    <div key={actor.ip} className="flex items-center justify-between p-3 bg-bg-secondary rounded-lg">
                      <div className="flex items-center gap-3">
                        <span className="w-6 h-6 flex items-center justify-center rounded-full bg-neon-red/20 text-neon-red text-xs font-bold">
                          {index + 1}
                        </span>
                        <div>
                          <IPLink ip={actor.ip} />
                          <div className="flex gap-1 mt-1">
                            {actor.honeypots.map((hp) => (
                              <span 
                                key={hp} 
                                className="px-1.5 py-0.5 text-xs rounded"
                                style={{ 
                                  backgroundColor: HONEYPOT_COLORS[hp as HoneypotType] + '20',
                                  color: HONEYPOT_COLORS[hp as HoneypotType]
                                }}
                              >
                                {hp}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="font-mono text-neon-green">{actor.total_events.toLocaleString()}</div>
                        <div className="text-xs text-text-muted">events</div>
                      </div>
                    </div>
                  ))}
                  {(!topActors?.threat_actors || topActors.threat_actors.length === 0) && (
                    <div className="text-center py-8 text-text-secondary">No threat actors detected</div>
                  )}
                </div>
              </div>

              {/* Honeypot Stats */}
              <div>
                <h4 className="text-sm font-medium text-text-secondary mb-3">Unique Attackers by Honeypot</h4>
                <div className="space-y-3">
                  {threatIntel?.honeypot_stats && Object.entries(threatIntel.honeypot_stats)
                    .sort(([, a], [, b]) => b - a)
                    .map(([hp, count]) => (
                      <div key={hp} className="flex items-center justify-between p-3 bg-bg-secondary rounded-lg">
                        <div className="flex items-center gap-2">
                          <div 
                            className="w-3 h-3 rounded-full"
                            style={{ backgroundColor: HONEYPOT_COLORS[hp as HoneypotType] || '#888' }}
                          />
                          <span className="font-medium text-text-primary capitalize">{HONEYPOT_NAMES[hp as HoneypotType] || hp}</span>
                        </div>
                        <span className="font-mono text-neon-green">{count.toLocaleString()}</span>
                      </div>
                    ))}
                </div>

                {/* Summary */}
                <div className="mt-4 p-4 bg-bg-card border border-bg-hover rounded-lg">
                  <div className="grid grid-cols-3 gap-4 text-center">
                    <div>
                      <div className="text-2xl font-display font-bold text-neon-green">
                        {threatIntel?.summary?.total_unique_attackers?.toLocaleString() || 0}
                      </div>
                      <div className="text-xs text-text-secondary">Total Attackers</div>
                    </div>
                    <div>
                      <div className="text-2xl font-display font-bold text-neon-orange">
                        {threatIntel?.summary?.multi_honeypot_attackers?.toLocaleString() || 0}
                      </div>
                      <div className="text-xs text-text-secondary">Multi-Honeypot</div>
                    </div>
                    <div>
                      <div className="text-2xl font-display font-bold text-neon-purple">
                        {threatIntel?.summary?.multi_percentage || 0}%
                      </div>
                      <div className="text-xs text-text-secondary">Overlap</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

