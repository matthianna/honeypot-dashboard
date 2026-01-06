import { useCallback, useState, useEffect, useMemo, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  Users,
  Globe,
  ArrowRight,
  TrendingUp,
  TrendingDown,
  Shield,
  Terminal,
  Bug,
  Monitor,
  Clock,
  Radio,
  Zap,
  Target,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from 'recharts';
import TimeRangeSelector from '../components/TimeRangeSelector';
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
};

export default function Dashboard() {
  const { timeRange, setTimeRange } = useTimeRange('24h');
  const [currentTime, setCurrentTime] = useState(new Date());
  const [animatedTotal, setAnimatedTotal] = useState<number | null>(null);
  const previousTotalRef = useRef<number>(0);

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

  // Animate total events counter - only animate the difference
  useEffect(() => {
    if (overview?.total_events !== undefined) {
      const target = overview.total_events;
      const start = previousTotalRef.current;
      
      // If this is the first load (no previous value), just set it directly
      if (animatedTotal === null) {
        setAnimatedTotal(target);
        previousTotalRef.current = target;
        return;
      }
      
      // If the value hasn't changed, do nothing
      if (start === target) return;
      
      // Animate from current value to new value
      const difference = target - start;
      const duration = Math.min(1000, Math.abs(difference) * 5); // Faster animation for small changes
      const steps = 30;
      const increment = difference / steps;
      let current = start;
      let step = 0;

      const timer = setInterval(() => {
        step++;
        current += increment;
        setAnimatedTotal(Math.round(current));
        if (step >= steps) {
          clearInterval(timer);
          setAnimatedTotal(target);
          previousTotalRef.current = target;
        }
      }, duration / steps);

      return () => clearInterval(timer);
    }
  }, [overview?.total_events]);

  // Calculate trend from timeline data
  const trend = useMemo(() => {
    if (!timeline?.data || timeline.data.length < 4) return { direction: 'stable', percentage: 0 };
    const data = timeline.data;
    const midpoint = Math.floor(data.length / 2);
    const recent = data.slice(midpoint).reduce((s: number, v: { count: number }) => s + v.count, 0) / (data.length - midpoint);
    const older = data.slice(0, midpoint).reduce((s: number, v: { count: number }) => s + v.count, 0) / midpoint;
    const pct = older > 0 ? ((recent - older) / older) * 100 : 0;
    return {
      direction: pct > 10 ? 'up' : pct < -10 ? 'down' : 'stable',
      percentage: Math.abs(pct).toFixed(1),
    };
  }, [timeline]);

  // Format timeline axis based on time range
  const formatTimelineAxis = useCallback((ts: string) => {
    try {
      const date = new Date(ts);
      // Show date for 7d and 30d ranges
      if (timeRange === '7d' || timeRange === '30d') {
        return date.toLocaleDateString('en-US', { 
          month: 'short', 
          day: 'numeric',
          hour: '2-digit',
        }).replace(',', '');
      }
      return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return ts;
    }
  }, [timeRange]);

  // Format tooltip label with full date/time
  const formatTooltipLabel = (ts: string) => {
    try {
      const date = new Date(ts);
      if (timeRange === '7d' || timeRange === '30d') {
        return date.toLocaleString('en-US', { 
          weekday: 'short',
          month: 'short', 
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
        });
      }
      return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return ts;
    }
  };

  // Prepare honeypot distribution data with improved formatting
  const honeypotDistributionData = useMemo(() => {
    if (!overview?.honeypots) return [];
    
    const filtered = overview.honeypots
      .filter(h => h.total_events > 0 && h.name !== 'firewall')
      .sort((a, b) => b.total_events - a.total_events);
    
    const total = filtered.reduce((sum, h) => sum + h.total_events, 0);
    
    return filtered.map(h => ({
      name: HONEYPOT_NAMES[h.name as HoneypotType] || h.name,
      shortName: h.name.charAt(0).toUpperCase() + h.name.slice(1, 4),
      value: h.total_events,
      uniqueIPs: h.unique_ips,
      color: HONEYPOT_COLORS[h.name as HoneypotType] || '#888',
      percentage: ((h.total_events / total) * 100).toFixed(1),
      fill: HONEYPOT_COLORS[h.name as HoneypotType] || '#888',
    }));
  }, [overview]);

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
                  {(animatedTotal ?? overview?.total_events ?? 0).toLocaleString()}
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
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
          {overviewLoading ? (
            Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="bg-bg-card rounded-xl p-5 animate-pulse border border-bg-hover">
                <div className="w-10 h-10 bg-bg-hover rounded-lg mb-3" />
                <div className="h-4 bg-bg-hover rounded w-2/3 mb-2" />
                <div className="h-8 bg-bg-hover rounded w-1/2" />
              </div>
            ))
          ) : (
            overview?.honeypots?.filter(hp => hp.name !== 'firewall').map((hp) => {
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
              <span className="text-xs text-text-muted px-2 py-0.5 bg-bg-hover rounded">
                {timeRange === '1h' ? 'Last Hour' : timeRange === '24h' ? 'Last 24h' : timeRange === '7d' ? 'Last 7 Days' : 'Last 30 Days'}
              </span>
            </div>
            <Link to="/attack-map" className="text-sm text-neon-blue hover:text-neon-green transition-colors flex items-center gap-1">
              Live Map <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
          <div className="p-4">
            {timelineLoading ? (
              <div className="h-72 flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timeline?.data || []} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="timelineGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#39ff14" stopOpacity={0.5} />
                        <stop offset="50%" stopColor="#39ff14" stopOpacity={0.2} />
                        <stop offset="100%" stopColor="#39ff14" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis
                      dataKey="timestamp"
                      tickFormatter={formatTimelineAxis}
                      stroke="#444"
                      tick={{ fill: '#888', fontSize: 10 }}
                      axisLine={{ stroke: '#333' }}
                      tickLine={{ stroke: '#333' }}
                      interval="preserveStartEnd"
                      minTickGap={50}
                    />
                    <YAxis 
                      stroke="#444" 
                      tick={{ fill: '#888', fontSize: 10 }} 
                      axisLine={{ stroke: '#333' }}
                      tickLine={{ stroke: '#333' }}
                      tickFormatter={(v) => v >= 1000 ? `${(v/1000).toFixed(1)}k` : v}
                      width={45}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'rgba(20, 20, 30, 0.95)',
                        border: '1px solid rgba(57, 255, 20, 0.3)',
                        borderRadius: '12px',
                        boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
                        padding: '12px 16px',
                      }}
                      labelStyle={{ color: '#fff', fontWeight: 'bold', marginBottom: '4px' }}
                      itemStyle={{ color: '#39ff14' }}
                      labelFormatter={formatTooltipLabel}
                      formatter={(value: number) => [
                        <span key="value" className="font-mono font-bold">{value.toLocaleString()} events</span>,
                        null
                      ]}
                    />
                    <Area
                      type="monotone"
                      dataKey="count"
                      stroke="#39ff14"
                      fill="url(#timelineGradient)"
                      strokeWidth={2}
                      dot={false}
                      activeDot={{ r: 6, fill: '#39ff14', stroke: '#000', strokeWidth: 2 }}
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
            <Link to="/attack-analysis" className="text-sm text-neon-blue hover:text-neon-green transition-colors flex items-center gap-1">
              View All <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
          <div className="p-4">
            {geoLoading ? (
              <div className="h-72 flex items-center justify-center">
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
                          <span className="w-5 h-5 rounded flex items-center justify-center text-xs font-bold" 
                            style={{ backgroundColor: `${colors[i % colors.length]}20`, color: colors[i % colors.length] }}>
                            {i + 1}
                          </span>
                          <span className="text-sm text-text-primary group-hover:text-white transition-colors">
                            {geo.country}
                          </span>
                        </div>
                        <span className="text-sm font-mono text-text-secondary">
                          {geo.count.toLocaleString()}
                        </span>
                      </div>
                      <div className="h-2 bg-bg-hover rounded-full overflow-hidden">
                        <div 
                          className="h-full rounded-full transition-all duration-500"
                          style={{ 
                            width: `${percentage}%`,
                            background: `linear-gradient(90deg, ${colors[i % colors.length]} 0%, ${colors[i % colors.length]}80 100%)`,
                            boxShadow: `0 0 8px ${colors[i % colors.length]}40`,
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

      {/* Attack Distribution - Improved */}
      <div className="bg-bg-card rounded-xl border border-bg-hover overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-bg-hover">
          <div className="flex items-center gap-2">
            <Target className="w-5 h-5 text-neon-purple" />
            <span className="font-display font-bold text-white">Attack Distribution by Honeypot</span>
          </div>
          <div className="flex items-center gap-2 text-xs text-text-muted">
            <Zap className="w-4 h-4" />
            <span>{honeypotDistributionData.length} Active Honeypots</span>
          </div>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Left: Donut Chart with center stats */}
            <div className="relative">
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={honeypotDistributionData}
                      cx="50%"
                      cy="50%"
                      innerRadius={70}
                      outerRadius={120}
                      paddingAngle={3}
                      dataKey="value"
                      animationBegin={0}
                      animationDuration={800}
                      stroke="rgba(0,0,0,0.5)"
                      strokeWidth={2}
                    >
                      {honeypotDistributionData.map((entry, index) => (
                        <Cell 
                          key={`cell-${index}`} 
                          fill={entry.color}
                          style={{
                            filter: `drop-shadow(0 0 8px ${entry.color}40)`,
                          }}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'rgba(20, 20, 30, 0.95)',
                        border: '1px solid rgba(255,255,255,0.2)',
                        borderRadius: '12px',
                        boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
                        padding: '12px 16px',
                      }}
                      formatter={(value: number, _name: string, props: any) => {
                        return [
                          <div key="content" className="text-white">
                            <div className="font-bold text-lg">{value.toLocaleString()}</div>
                            <div className="text-text-muted text-xs">{props.payload.percentage}% of total</div>
                            <div className="text-text-muted text-xs mt-1">{props.payload.uniqueIPs} unique IPs</div>
                          </div>,
                          null
                        ];
                      }}
                      labelFormatter={(name) => <span className="font-bold">{name}</span>}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              {/* Center stats */}
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <div className="text-center">
                  <div className="text-3xl font-display font-bold text-white">
                    {overview?.total_events?.toLocaleString() || 0}
                  </div>
                  <div className="text-xs text-text-muted uppercase tracking-wider">Total Events</div>
                </div>
              </div>
            </div>

            {/* Right: Bar Chart + Stats */}
            <div className="flex flex-col gap-6">
              {/* Bar chart */}
              <div className="h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={honeypotDistributionData} layout="vertical" margin={{ left: 0, right: 20 }}>
                    <XAxis type="number" hide />
                    <YAxis 
                      type="category" 
                      dataKey="shortName" 
                      tick={{ fill: '#888', fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                      width={50}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'rgba(20, 20, 30, 0.95)',
                        border: '1px solid rgba(255,255,255,0.2)',
                        borderRadius: '8px',
                        padding: '8px 12px',
                      }}
                      formatter={(value: number) => [value.toLocaleString(), 'Events']}
                      labelFormatter={(label) => honeypotDistributionData.find(d => d.shortName === label)?.name || label}
                    />
                    <Bar 
                      dataKey="value" 
                      radius={[0, 4, 4, 0]}
                    >
                      {honeypotDistributionData.map((entry, index) => (
                        <Cell 
                          key={`bar-${index}`} 
                          fill={entry.color}
                          style={{ filter: `drop-shadow(0 0 4px ${entry.color}60)` }}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {/* Legend with stats */}
              <div className="grid grid-cols-2 gap-3">
                {honeypotDistributionData.map(item => (
                  <Link 
                    key={item.name} 
                    to={`/${item.name.toLowerCase().replace(/[^a-z]/g, '')}`}
                    className="flex items-center gap-3 p-3 rounded-lg bg-bg-hover/50 hover:bg-bg-hover transition-all group border border-transparent hover:border-opacity-30"
                    style={{ '--hover-border': item.color } as any}
                  >
                    <div 
                      className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 transition-transform group-hover:scale-110"
                      style={{ backgroundColor: `${item.color}20` }}
                    >
                      <span className="text-lg font-bold" style={{ color: item.color }}>
                        {item.percentage}%
                      </span>
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-medium text-text-primary truncate group-hover:text-white transition-colors">
                        {item.name}
                      </div>
                      <div className="flex items-center gap-2 text-xs text-text-muted">
                        <span>{item.value.toLocaleString()} events</span>
                        <span>•</span>
                        <span>{item.uniqueIPs} IPs</span>
                      </div>
                    </div>
                    <ArrowRight className="w-4 h-4 text-text-muted opacity-0 group-hover:opacity-100 transition-opacity" />
                  </Link>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
