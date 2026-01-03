import { useState, useEffect, useMemo } from 'react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  Legend
} from 'recharts';
import { Activity, TrendingUp, Clock, Zap } from 'lucide-react';
import api from '../services/api';
import LoadingSpinner from './LoadingSpinner';
import TimeRangeSelector from './TimeRangeSelector';
import ExportButton from './ExportButton';
import type { TimeRange } from '../types';

// Honeypot colors matching the rest of the app
const HONEYPOT_COLORS: Record<string, string> = {
  cowrie: '#39ff14',
  dionaea: '#00d4ff',
  galah: '#ff6600',
  rdpy: '#bf00ff',
  heralding: '#ff3366',
};

const HONEYPOT_LABELS: Record<string, string> = {
  cowrie: 'Cowrie (SSH)',
  dionaea: 'Dionaea',
  galah: 'Galah (HTTP)',
  rdpy: 'RDPY (RDP)',
  heralding: 'Heralding',
};

interface TimelineDataPoint {
  timestamp: string;
  formattedTime: string;
  cowrie: number;
  dionaea: number;
  galah: number;
  rdpy: number;
  heralding: number;
  total: number;
}

interface HoneypotStats {
  name: string;
  total: number;
  peak: number;
  average: number;
  color: string;
}

export default function AttackTimeline() {
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<TimelineDataPoint[]>([]);
  const [visibleHoneypots, setVisibleHoneypots] = useState<Record<string, boolean>>({
    cowrie: true,
    dionaea: true,
    galah: true,
    rdpy: true,
    heralding: true,
  });

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const response = await api.getTimelineByHoneypot(timeRange);
        
        // Merge all timestamps into a unified timeline
        const allTimestamps = new Set<string>();
        Object.values(response.honeypots).forEach(hp => {
          hp.forEach(point => allTimestamps.add(point.timestamp));
        });
        
        // Sort timestamps
        const sortedTimestamps = Array.from(allTimestamps).sort();
        
        // Build unified data points
        const unifiedData: TimelineDataPoint[] = sortedTimestamps.map(ts => {
          const date = new Date(ts);
          const formattedTime = formatTimestamp(date, timeRange);
          
          const cowrie = response.honeypots.cowrie?.find(p => p.timestamp === ts)?.count || 0;
          const dionaea = response.honeypots.dionaea?.find(p => p.timestamp === ts)?.count || 0;
          const galah = response.honeypots.galah?.find(p => p.timestamp === ts)?.count || 0;
          const rdpy = response.honeypots.rdpy?.find(p => p.timestamp === ts)?.count || 0;
          const heralding = response.honeypots.heralding?.find(p => p.timestamp === ts)?.count || 0;
          
          return {
            timestamp: ts,
            formattedTime,
            cowrie,
            dionaea,
            galah,
            rdpy,
            heralding,
            total: cowrie + dionaea + galah + rdpy + heralding,
          };
        });
        
        setData(unifiedData);
      } catch (err) {
        console.error('Failed to fetch timeline data:', err);
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
  }, [timeRange]);

  const formatTimestamp = (date: Date, range: TimeRange): string => {
    switch (range) {
      case '1h':
        return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
      case '24h':
        return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
      case '7d':
        return date.toLocaleDateString('en-US', { weekday: 'short', hour: '2-digit' });
      case '30d':
        return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      default:
        return date.toLocaleString();
    }
  };

  // Calculate stats for each honeypot
  const stats = useMemo<HoneypotStats[]>(() => {
    const honeypots = ['cowrie', 'dionaea', 'galah', 'rdpy', 'heralding'] as const;
    return honeypots.map(hp => {
      const values = data.map(d => d[hp]);
      const total = values.reduce((a, b) => a + b, 0);
      const peak = Math.max(...values, 0);
      const average = values.length > 0 ? total / values.length : 0;
      return {
        name: hp,
        total,
        peak,
        average,
        color: HONEYPOT_COLORS[hp],
      };
    }).sort((a, b) => b.total - a.total);
  }, [data]);

  const totalAttacks = useMemo(() => {
    return data.reduce((sum, d) => sum + d.total, 0);
  }, [data]);

  const peakAttacks = useMemo(() => {
    return Math.max(...data.map(d => d.total), 0);
  }, [data]);

  const toggleHoneypot = (hp: string) => {
    setVisibleHoneypots(prev => ({ ...prev, [hp]: !prev[hp] }));
  };

  if (loading) {
    return (
      <div className="h-96 flex items-center justify-center bg-bg-secondary rounded-xl">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        {stats.map(stat => (
          <div
            key={stat.name}
            className={`bg-bg-secondary rounded-xl border p-4 cursor-pointer transition-all ${
              visibleHoneypots[stat.name] 
                ? 'border-opacity-50 shadow-lg' 
                : 'border-bg-hover opacity-50'
            }`}
            style={{ 
              borderColor: visibleHoneypots[stat.name] ? stat.color : undefined,
              boxShadow: visibleHoneypots[stat.name] ? `0 0 20px ${stat.color}20` : undefined
            }}
            onClick={() => toggleHoneypot(stat.name)}
          >
            <div className="flex items-center gap-2 mb-2">
              <div 
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: stat.color }}
              />
              <span className="text-text-secondary text-sm font-medium capitalize">
                {stat.name}
              </span>
            </div>
            <div 
              className="text-2xl font-display font-bold"
              style={{ color: stat.color }}
            >
              {stat.total.toLocaleString()}
            </div>
            <div className="text-xs text-text-muted mt-1">
              Peak: {stat.peak.toLocaleString()} / Avg: {Math.round(stat.average).toLocaleString()}
            </div>
          </div>
        ))}
      </div>

      {/* Main Chart */}
      <div className="bg-bg-secondary rounded-xl border border-bg-hover overflow-hidden">
        <div className="px-4 py-3 border-b border-bg-hover flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-neon-purple/20 rounded-lg">
              <Activity className="w-5 h-5 text-neon-purple" />
            </div>
            <div>
              <h3 className="font-display font-bold text-text-primary">Attack Timeline</h3>
              <p className="text-sm text-text-muted">All honeypots activity over time</p>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-4 text-sm">
              <div className="flex items-center gap-2 text-text-secondary">
                <Zap className="w-4 h-4 text-neon-orange" />
                <span>Total: <span className="font-mono text-neon-green">{totalAttacks.toLocaleString()}</span></span>
              </div>
              <div className="flex items-center gap-2 text-text-secondary">
                <TrendingUp className="w-4 h-4 text-neon-pink" />
                <span>Peak: <span className="font-mono text-neon-pink">{peakAttacks.toLocaleString()}</span></span>
              </div>
            </div>
            <ExportButton 
              data={data}
              filename="attack_timeline"
              timeRange={timeRange}
              disabled={loading || data.length === 0}
            />
            <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
          </div>
        </div>
        
        <div className="p-4" style={{ height: 400 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={data}
              margin={{ top: 10, right: 30, left: 0, bottom: 0 }}
            >
              <defs>
                {Object.entries(HONEYPOT_COLORS).map(([hp, color]) => (
                  <linearGradient key={hp} id={`gradient-${hp}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={color} stopOpacity={0.4}/>
                    <stop offset="95%" stopColor={color} stopOpacity={0}/>
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2a4a" />
              <XAxis 
                dataKey="formattedTime" 
                stroke="#6b7280"
                tick={{ fill: '#9ca3af', fontSize: 11 }}
                axisLine={{ stroke: '#374151' }}
              />
              <YAxis 
                stroke="#6b7280"
                tick={{ fill: '#9ca3af', fontSize: 11 }}
                axisLine={{ stroke: '#374151' }}
                tickFormatter={(value) => value >= 1000 ? `${(value / 1000).toFixed(1)}k` : value}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1a1a2e',
                  border: '1px solid #2a2a4a',
                  borderRadius: '8px',
                  boxShadow: '0 10px 25px rgba(0,0,0,0.5)',
                }}
                labelStyle={{ color: '#f3f4f6', fontWeight: 'bold', marginBottom: 8 }}
                formatter={(value: number, name: string) => [
                  <span style={{ color: HONEYPOT_COLORS[name] }}>{value.toLocaleString()}</span>,
                  HONEYPOT_LABELS[name] || name
                ]}
              />
              <Legend 
                verticalAlign="top"
                height={36}
                formatter={(value) => (
                  <span 
                    style={{ 
                      color: visibleHoneypots[value] ? HONEYPOT_COLORS[value] : '#6b7280',
                      cursor: 'pointer',
                    }}
                  >
                    {HONEYPOT_LABELS[value] || value}
                  </span>
                )}
                onClick={(e) => toggleHoneypot(e.dataKey as string)}
              />
              
              {/* Render areas in order of total (largest first for stacking) */}
              {stats.map(stat => (
                visibleHoneypots[stat.name] && (
                  <Area
                    key={stat.name}
                    type="monotone"
                    dataKey={stat.name}
                    stackId="1"
                    stroke={stat.color}
                    fill={`url(#gradient-${stat.name})`}
                    strokeWidth={2}
                    animationDuration={1000}
                  />
                )
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Activity Summary */}
      <div className="bg-bg-secondary rounded-xl border border-bg-hover p-4">
        <div className="flex items-center gap-2 mb-4">
          <Clock className="w-5 h-5 text-neon-blue" />
          <h4 className="font-display font-bold text-text-primary">Activity Summary</h4>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          {stats.map(stat => (
            <div key={stat.name} className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-text-secondary capitalize text-sm">{stat.name}</span>
                <span className="font-mono text-sm" style={{ color: stat.color }}>
                  {((stat.total / totalAttacks) * 100).toFixed(1)}%
                </span>
              </div>
              <div className="h-2 bg-bg-hover rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${(stat.total / totalAttacks) * 100}%`,
                    backgroundColor: stat.color,
                    boxShadow: `0 0 10px ${stat.color}`,
                  }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}





