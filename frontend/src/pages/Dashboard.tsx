import { useCallback, useState, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  Users,
  Globe,
  ArrowRight,
  TrendingUp,
  TrendingDown,
  Zap,
  Shield,
  Terminal,
  Bug,
  Monitor,
  ShieldAlert,
  MapPin,
  Clock,
  Target,
  Skull,
  Eye,
  Radio,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
} from 'recharts';
import TimeRangeSelector from '../components/TimeRangeSelector';
import IPLink from '../components/IPLink';
import LoadingSpinner from '../components/LoadingSpinner';
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import { HONEYPOT_COLORS, HONEYPOT_NAMES, HoneypotType } from '../types';

const HONEYPOT_ICONS: Record<string, typeof Terminal> = {
  cowrie: Terminal,
  dionaea: Bug,
  galah: Globe,
  rdpy: Monitor,
  heralding: Shield,
  firewall: ShieldAlert,
};

export default function Dashboard() {
  const { timeRange, setTimeRange } = useTimeRange('24h');
  const [currentTime, setCurrentTime] = useState(new Date());
  const [animatedTotal, setAnimatedTotal] = useState(0);

  // Update clock
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const { data: overview, loading: overviewLoading } = useApiWithRefresh(
    useCallback(() => api.getDashboardOverview(timeRange), [timeRange]),
    [timeRange],
    15000
  );

  const { data: topAttackers, loading: attackersLoading } = useApiWithRefresh(
    useCallback(() => api.getTopAttackers(timeRange, 5), [timeRange]),
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

  const { data: velocity } = useApiWithRefresh(
    useCallback(() => api.getAttackVelocity(), []),
    [],
    5000
  );

  const { data: threatIntel } = useApiWithRefresh(
    useCallback(() => api.getThreatIntel(timeRange), [timeRange]),
    [timeRange],
    60000
  );

  const { data: honeypotHealth, loading: healthLoading } = useApiWithRefresh(
    useCallback(() => api.getHoneypotHealth(), []),
    [],
    30000
  );

  // Animate total events counter
  useEffect(() => {
    if (overview?.total_events) {
      const target = overview.total_events;
      const duration = 1500;
      const steps = 60;
      const increment = target / steps;
      let current = 0;
      let step = 0;

      const timer = setInterval(() => {
        step++;
        current += increment;
        setAnimatedTotal(Math.round(current));
        if (step >= steps) {
          clearInterval(timer);
          setAnimatedTotal(target);
        }
      }, duration / steps);

      return () => clearInterval(timer);
    }
  }, [overview?.total_events]);

  // Calculate trend
  const trend = useMemo(() => {
    if (!velocity?.velocity || velocity.velocity.length < 2) return { direction: 'stable', percentage: 0 };
    const recent = velocity.velocity.slice(-5).reduce((s, v) => s + v.count, 0) / 5;
    const older = velocity.velocity.slice(0, 5).reduce((s, v) => s + v.count, 0) / 5;
    const pct = older > 0 ? ((recent - older) / older) * 100 : 0;
    return {
      direction: pct > 10 ? 'up' : pct < -10 ? 'down' : 'stable',
      percentage: Math.abs(pct).toFixed(1),
    };
  }, [velocity]);

  const formatTime = (ts: string) => {
    try {
      return new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return ts;
    }
  };

  return (
    <div className="space-y-8">
      {/* Hero Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-bg-secondary via-bg-card to-bg-secondary border border-bg-hover">
        {/* Animated background grid */}
        <div className="absolute inset-0 opacity-10">
          <div className="absolute inset-0" style={{
            backgroundImage: `linear-gradient(rgba(57,255,20,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(57,255,20,0.1) 1px, transparent 1px)`,
            backgroundSize: '50px 50px',
          }} />
        </div>
        
        {/* Glowing orbs */}
        <div className="absolute -top-20 -right-20 w-64 h-64 bg-neon-green/10 rounded-full blur-3xl" />
        <div className="absolute -bottom-20 -left-20 w-64 h-64 bg-neon-blue/10 rounded-full blur-3xl" />
        
        <div className="relative z-10 p-8">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
            {/* Left: Title & Status */}
            <div>
              <div className="flex items-center gap-3 mb-2">
                <div className="relative">
                  <div className="w-3 h-3 bg-neon-green rounded-full animate-pulse" />
                  <div className="absolute inset-0 w-3 h-3 bg-neon-green rounded-full animate-ping" />
                </div>
                <span className="text-sm text-neon-green font-medium uppercase tracking-wider">
                  Live Monitoring
                </span>
              </div>
              <h1 className="text-3xl lg:text-4xl font-display font-bold text-white mb-2">
                Honeypot Security Center
              </h1>
              <div className="flex items-center gap-4 text-text-secondary text-sm">
                <div className="flex items-center gap-1">
                  <Clock className="w-4 h-4" />
                  <span>{currentTime.toLocaleTimeString()}</span>
                </div>
                <div className="flex items-center gap-1">
                  <Radio className="w-4 h-4 text-neon-green" />
                  <span>{overview?.honeypots?.filter(h => h.total_events > 0).length || 0} Active Sensors</span>
                </div>
              </div>
            </div>

            {/* Center: Main Counter */}
            <div className="text-center lg:text-right">
              <div className="text-xs text-text-muted uppercase tracking-wider mb-1">Total Events Captured</div>
              <div className="flex items-baseline justify-center lg:justify-end gap-3">
                <span className="text-5xl lg:text-6xl font-display font-black text-transparent bg-clip-text bg-gradient-to-r from-neon-green via-neon-blue to-neon-green">
                  {animatedTotal.toLocaleString()}
                </span>
                {trend.direction !== 'stable' && (
                  <div className={`flex items-center gap-1 ${trend.direction === 'up' ? 'text-red-400' : 'text-green-400'}`}>
                    {trend.direction === 'up' ? <TrendingUp className="w-5 h-5" /> : <TrendingDown className="w-5 h-5" />}
                    <span className="text-sm font-medium">{trend.percentage}%</span>
                  </div>
                )}
              </div>
              <div className="text-text-muted text-sm mt-1">
                {overview?.total_unique_ips?.toLocaleString() || 0} unique attackers from {geoStats?.data?.length || 0} countries
              </div>
            </div>

            {/* Right: Time Selector */}
            <div>
              <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
            </div>
          </div>

          {/* Quick Stats Bar */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8">
            <QuickStat
              icon={<Zap className="w-5 h-5" />}
              label="Current Rate"
              value={`${velocity?.stats?.current_per_minute || 0}/min`}
              color="green"
            />
            <QuickStat
              icon={<Target className="w-5 h-5" />}
              label="Peak Rate"
              value={`${velocity?.stats?.max_per_minute || 0}/min`}
              color="orange"
            />
            <QuickStat
              icon={<Skull className="w-5 h-5" />}
              label="Multi-Target Attackers"
              value={threatIntel?.summary?.multi_honeypot_attackers || 0}
              color="red"
            />
            <QuickStat
              icon={<Eye className="w-5 h-5" />}
              label="Avg Rate"
              value={`${velocity?.stats?.avg_per_minute || 0}/min`}
              color="blue"
            />
          </div>
        </div>
      </div>

      {/* Honeypot Health Status */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-display font-bold text-white">System Health</h2>
            {honeypotHealth && (
              <span className={`px-2 py-0.5 text-xs rounded-full ${
                honeypotHealth.summary.overall_status === 'healthy' ? 'bg-neon-green/20 text-neon-green' :
                honeypotHealth.summary.overall_status === 'warning' ? 'bg-neon-orange/20 text-neon-orange' :
                'bg-neon-red/20 text-neon-red'
              }`}>
                {honeypotHealth.summary.healthy}/{honeypotHealth.summary.total} Online
              </span>
            )}
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {healthLoading ? (
            Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="bg-bg-card rounded-lg p-3 animate-pulse border border-bg-hover">
                <div className="h-4 bg-bg-hover rounded w-1/2 mb-2" />
                <div className="h-6 bg-bg-hover rounded w-2/3" />
              </div>
            ))
          ) : (
            honeypotHealth?.honeypots?.map((hp) => {
              const statusColors: Record<string, string> = {
                healthy: 'bg-neon-green',
                warning: 'bg-neon-orange',
                stale: 'bg-neon-red',
                offline: 'bg-text-muted',
                error: 'bg-neon-red',
                unknown: 'bg-text-muted',
              };
              const statusText: Record<string, string> = {
                healthy: 'Live',
                warning: 'Delayed',
                stale: 'Stale',
                offline: 'Offline',
                error: 'Error',
                unknown: 'Unknown',
              };
              
              return (
                <Link
                  key={hp.id}
                  to={`/${hp.id}`}
                  className="group bg-bg-card rounded-lg p-3 border border-bg-hover hover:border-opacity-50 transition-all duration-200"
                  style={{ borderColor: `${hp.color}30` }}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-text-primary">{hp.name}</span>
                    <div className="flex items-center gap-1.5">
                      <div className={`w-2 h-2 rounded-full ${statusColors[hp.status]} ${hp.status === 'healthy' ? 'animate-pulse' : ''}`} />
                      <span className="text-xs text-text-muted">{statusText[hp.status]}</span>
                    </div>
                  </div>
                  <div className="flex items-baseline justify-between">
                    <span className="text-lg font-display font-bold" style={{ color: hp.color }}>
                      {hp.events_1h}
                    </span>
                    <span className="text-xs text-text-muted">last 1h</span>
                  </div>
                  {hp.minutes_since_last !== null && hp.minutes_since_last < 60 && (
                    <div className="text-xs text-text-muted mt-1">
                      Last: {hp.minutes_since_last < 1 ? '<1' : Math.round(hp.minutes_since_last)}m ago
                    </div>
                  )}
                </Link>
              );
            })
          )}
        </div>
      </div>

      {/* Honeypot Grid */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-display font-bold text-white">Honeypot Sensors</h2>
          <Link to="/attackers" className="text-sm text-neon-blue hover:text-neon-green transition-colors flex items-center gap-1">
            View All Attackers <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {overviewLoading ? (
            Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="bg-bg-card rounded-xl p-5 animate-pulse border border-bg-hover">
                <div className="w-10 h-10 bg-bg-hover rounded-lg mb-3" />
                <div className="h-4 bg-bg-hover rounded w-2/3 mb-2" />
                <div className="h-8 bg-bg-hover rounded w-1/2" />
              </div>
            ))
          ) : (
            overview?.honeypots?.map((hp) => {
              const Icon = HONEYPOT_ICONS[hp.name] || Shield;
              const color = HONEYPOT_COLORS[hp.name as HoneypotType];
              const name = HONEYPOT_NAMES[hp.name as HoneypotType] || hp.name;
              const isActive = hp.total_events > 0;
              
              return (
                <Link
                  key={hp.name}
                  to={`/${hp.name}`}
                  className="group relative bg-bg-card rounded-xl p-5 border border-bg-hover hover:border-opacity-50 transition-all duration-300 overflow-hidden"
                  style={{ borderColor: isActive ? `${color}30` : undefined }}
                >
                  {/* Hover glow */}
                  <div 
                    className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
                    style={{ background: `radial-gradient(circle at center, ${color}10 0%, transparent 70%)` }}
                  />
                  
                  <div className="relative z-10">
                    <div 
                      className="w-10 h-10 rounded-lg flex items-center justify-center mb-3 transition-transform group-hover:scale-110"
                      style={{ backgroundColor: `${color}20` }}
                    >
                      <Icon className="w-5 h-5" style={{ color }} />
                    </div>
                    <div className="text-sm text-text-secondary mb-1">{name}</div>
                    <div className="text-2xl font-display font-bold" style={{ color }}>
                      {hp.total_events.toLocaleString()}
                    </div>
                    <div className="flex items-center gap-2 mt-2 text-xs text-text-muted">
                      <Users className="w-3 h-3" />
                      <span>{hp.unique_ips} IPs</span>
                    </div>
                    
                    {/* Activity indicator */}
                    {isActive && (
                      <div className="absolute top-3 right-3">
                        <div className="w-2 h-2 rounded-full animate-pulse" style={{ backgroundColor: color }} />
                      </div>
                    )}
                  </div>
                </Link>
              );
            })
          )}
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Chart */}
        <div className="lg:col-span-2 bg-bg-card rounded-xl border border-bg-hover overflow-hidden">
          <div className="flex items-center justify-between p-4 border-b border-bg-hover">
            <div className="flex items-center gap-2">
              <Activity className="w-5 h-5 text-neon-green" />
              <span className="font-display font-bold text-white">Attack Timeline</span>
            </div>
            <Link to="/attack-map" className="text-sm text-neon-blue hover:text-neon-green transition-colors flex items-center gap-1">
              Live Map <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
          <div className="p-4">
            {timelineLoading ? (
              <div className="h-64 flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timeline?.data || []}>
                    <defs>
                      <linearGradient id="timelineGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#39ff14" stopOpacity={0.4} />
                        <stop offset="100%" stopColor="#39ff14" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis
                      dataKey="timestamp"
                      tickFormatter={formatTime}
                      stroke="#555"
                      tick={{ fill: '#888', fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <YAxis 
                      stroke="#555" 
                      tick={{ fill: '#888', fontSize: 11 }} 
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'rgba(26, 26, 37, 0.95)',
                        border: '1px solid rgba(255,255,255,0.1)',
                        borderRadius: '12px',
                        boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
                      }}
                      labelFormatter={formatTime}
                      formatter={(value: number) => [value.toLocaleString(), 'Events']}
                    />
                    <Area
                      type="monotone"
                      dataKey="count"
                      stroke="#39ff14"
                      fill="url(#timelineGradient)"
                      strokeWidth={2}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
        </div>

        {/* Top Countries */}
        <div className="bg-bg-card rounded-xl border border-bg-hover overflow-hidden">
          <div className="flex items-center justify-between p-4 border-b border-bg-hover">
            <div className="flex items-center gap-2">
              <Globe className="w-5 h-5 text-neon-blue" />
              <span className="font-display font-bold text-white">Top Attack Origins</span>
            </div>
            <Link to="/analytics" className="text-sm text-neon-blue hover:text-neon-green transition-colors flex items-center gap-1">
              Analytics <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
          <div className="p-4">
            {geoLoading ? (
              <div className="h-64 flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              <div className="space-y-3">
                {geoStats?.data?.slice(0, 8).map((geo, i) => {
                  const maxCount = geoStats.data[0]?.count || 1;
                  const percentage = (geo.count / maxCount) * 100;
                  const colors = ['#39ff14', '#00d4ff', '#ff6600', '#bf00ff', '#ff3366', '#ffd700', '#00ff88', '#ff00ff'];
                  
                  return (
                    <div key={geo.country} className="group">
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2">
                          <MapPin className="w-3 h-3 text-text-muted" />
                          <span className="text-sm text-text-primary group-hover:text-white transition-colors">
                            {geo.country}
                          </span>
                        </div>
                        <span className="text-sm font-mono text-text-secondary">
                          {geo.count.toLocaleString()}
                        </span>
                      </div>
                      <div className="h-1.5 bg-bg-hover rounded-full overflow-hidden">
                        <div 
                          className="h-full rounded-full transition-all duration-500"
                          style={{ 
                            width: `${percentage}%`,
                            backgroundColor: colors[i % colors.length],
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Attackers */}
        <div className="bg-bg-card rounded-xl border border-bg-hover overflow-hidden">
          <div className="flex items-center justify-between p-4 border-b border-bg-hover">
            <div className="flex items-center gap-2">
              <Skull className="w-5 h-5 text-neon-red" />
              <span className="font-display font-bold text-white">Top Threat Actors</span>
            </div>
          </div>
          <div className="divide-y divide-bg-hover">
            {attackersLoading ? (
              <div className="p-8 flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              topAttackers?.data?.slice(0, 5).map((attacker, i) => {
                // Behavior classification styling
                const behaviorStyles: Record<string, { color: string; bg: string; icon: string }> = {
                  Script: { color: 'text-neon-red', bg: 'bg-neon-red/20', icon: '⚡' },
                  Human: { color: 'text-neon-green', bg: 'bg-neon-green/20', icon: '👤' },
                  Bot: { color: 'text-neon-orange', bg: 'bg-neon-orange/20', icon: '🤖' },
                };
                const behavior = attacker.behavior_classification;
                const style = behavior ? behaviorStyles[behavior] : null;
                
                // Format duration
                const formatDuration = (seconds?: number) => {
                  if (!seconds) return null;
                  if (seconds < 60) return `${Math.round(seconds)}s`;
                  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
                  return `${(seconds / 3600).toFixed(1)}h`;
                };
                
                return (
                  <div key={attacker.ip} className="flex items-center justify-between p-4 hover:bg-bg-hover/50 transition-colors">
                    <div className="flex items-center gap-4">
                      <div className="w-8 h-8 rounded-lg bg-neon-red/20 flex items-center justify-center text-neon-red font-bold text-sm">
                        {i + 1}
                      </div>
                      <div>
                        <IPLink ip={attacker.ip} />
                        <div className="text-xs text-text-muted flex items-center gap-2 mt-0.5">
                          <span className="flex items-center gap-1">
                            <MapPin className="w-3 h-3" />
                            {attacker.country || 'Unknown'}
                          </span>
                          {attacker.total_duration_seconds && (
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {formatDuration(attacker.total_duration_seconds)}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      {style && behavior && (
                        <div className={`px-2 py-1 rounded-lg text-xs font-medium ${style.bg} ${style.color} flex items-center gap-1`}>
                          <span>{style.icon}</span>
                          <span>{behavior}</span>
                        </div>
                      )}
                      <div className="text-right">
                        <div className="font-mono text-neon-green font-bold">
                          {attacker.count.toLocaleString()}
                        </div>
                        <div className="text-xs text-text-muted">events</div>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Attack Velocity Chart */}
        <div className="bg-bg-card rounded-xl border border-bg-hover overflow-hidden">
          <div className="flex items-center justify-between p-4 border-b border-bg-hover">
            <div className="flex items-center gap-2">
              <Zap className="w-5 h-5 text-neon-orange" />
              <span className="font-display font-bold text-white">Attack Velocity</span>
            </div>
            <span className="text-xs text-text-muted">Last hour</span>
          </div>
          <div className="p-4">
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={velocity?.velocity?.slice(-20) || []}>
                  <XAxis 
                    dataKey="timestamp"
                    tickFormatter={(ts) => new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                    stroke="#555"
                    tick={{ fill: '#888', fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                    interval="preserveStartEnd"
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(26, 26, 37, 0.95)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '12px',
                    }}
                    labelFormatter={(ts) => new Date(ts).toLocaleTimeString()}
                    formatter={(value: number) => [value, 'Events']}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {velocity?.velocity?.slice(-20).map((_, i) => (
                      <Cell 
                        key={i}
                        fill={i === (velocity?.velocity?.length || 0) - 21 + 20 ? '#39ff14' : '#00d4ff'}
                        fillOpacity={0.3 + (i / 20) * 0.7}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// Quick Stat Component
function QuickStat({ 
  icon, 
  label, 
  value, 
  color 
}: { 
  icon: React.ReactNode; 
  label: string; 
  value: string | number; 
  color: 'green' | 'blue' | 'orange' | 'red';
}) {
  const colorClasses = {
    green: 'text-neon-green bg-neon-green/10 border-neon-green/20',
    blue: 'text-neon-blue bg-neon-blue/10 border-neon-blue/20',
    orange: 'text-neon-orange bg-neon-orange/10 border-neon-orange/20',
    red: 'text-neon-red bg-neon-red/10 border-neon-red/20',
  };

  return (
    <div className={`flex items-center gap-3 p-3 rounded-xl border ${colorClasses[color]}`}>
      <div className={colorClasses[color].split(' ')[0]}>{icon}</div>
      <div>
        <div className="text-xs text-text-muted">{label}</div>
        <div className={`text-lg font-display font-bold ${colorClasses[color].split(' ')[0]}`}>
          {typeof value === 'number' ? value.toLocaleString() : value}
        </div>
      </div>
    </div>
  );
}
