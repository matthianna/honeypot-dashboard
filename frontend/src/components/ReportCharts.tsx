import { useMemo } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  ComposedChart,
  Scatter,
} from 'recharts';
import Card, { CardHeader, CardContent } from './Card';

const CHART_COLORS = {
  primary: '#39ff14',
  secondary: '#00d4ff',
  tertiary: '#ff6600',
  quaternary: '#bf00ff',
  quinary: '#ff3366',
  senary: '#ffcc00',
};

const VARIANT_COLORS: Record<string, string> = {
  plain: '#39ff14',
  openai: '#00d4ff',
  ollama: '#ff6600',
};

const tooltipStyle = {
  backgroundColor: '#1a1a25',
  border: '1px solid #252532',
  borderRadius: '8px',
};

// ==================== Honeypot Distribution Chart ====================

interface HoneypotDistributionProps {
  data: Record<string, { events: number; unique_ips: number }>;
  title?: string;
}

export function HoneypotDistributionChart({ data, title = 'Attack Distribution by Honeypot' }: HoneypotDistributionProps) {
  const chartData = useMemo(() => 
    Object.entries(data).map(([name, stats]) => ({
      name: name.charAt(0).toUpperCase() + name.slice(1),
      events: stats.events,
      ips: stats.unique_ips,
    })),
    [data]
  );

  const colors = ['#39ff14', '#00d4ff', '#ff6600', '#bf00ff', '#ff3366'];

  return (
    <Card>
      <CardHeader title={title} />
      <CardContent>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={100}
                paddingAngle={2}
                dataKey="events"
                label={({ name, percent }) => `${name} (${(percent * 100).toFixed(1)}%)`}
              >
                {chartData.map((_, index) => (
                  <Cell key={index} fill={colors[index % colors.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

// ==================== LLM Comparison Bar Chart ====================

interface LLMComparisonProps {
  variants: Array<{
    variant: string;
    display_name: string;
    metrics: {
      sessions: number;
      commands_executed: number;
      file_downloads: number;
    };
    duration: {
      avg: number;
    };
  }>;
  metric: 'sessions' | 'commands' | 'duration' | 'downloads';
  title?: string;
}

export function LLMComparisonBarChart({ variants, metric, title }: LLMComparisonProps) {
  const chartData = useMemo(() => {
    switch (metric) {
      case 'sessions':
        return variants.map(v => ({
          name: v.display_name,
          value: v.metrics.sessions,
        }));
      case 'commands':
        return variants.map(v => ({
          name: v.display_name,
          value: v.metrics.commands_executed,
        }));
      case 'duration':
        return variants.map(v => ({
          name: v.display_name,
          value: v.duration.avg,
        }));
      case 'downloads':
        return variants.map(v => ({
          name: v.display_name,
          value: v.metrics.file_downloads,
        }));
      default:
        return [];
    }
  }, [variants, metric]);

  const metricLabels: Record<string, string> = {
    sessions: 'Sessions',
    commands: 'Commands Executed',
    duration: 'Avg Duration (s)',
    downloads: 'File Downloads',
  };

  return (
    <Card>
      <CardHeader title={title || `LLM Comparison: ${metricLabels[metric]}`} />
      <CardContent>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
              <XAxis dataKey="name" stroke="#888888" />
              <YAxis stroke="#888888" />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="value" name={metricLabels[metric]}>
                {chartData.map((_, index) => (
                  <Cell 
                    key={index} 
                    fill={VARIANT_COLORS[variants[index]?.variant] || CHART_COLORS.primary} 
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

// ==================== Engagement Funnel Chart ====================

interface EngagementFunnelProps {
  data: Array<{
    variant: string;
    display_name: string;
    engagement: {
      login_rate: number;
      success_rate: number;
      command_rate: number;
    };
  }>;
  title?: string;
}

export function EngagementRadarChart({ data, title = 'Engagement Metrics Comparison' }: EngagementFunnelProps) {
  const radarData = useMemo(() => [
    { metric: 'Login Rate', ...Object.fromEntries(data.map(v => [v.variant, v.engagement.login_rate])) },
    { metric: 'Success Rate', ...Object.fromEntries(data.map(v => [v.variant, v.engagement.success_rate])) },
    { metric: 'Command Rate', ...Object.fromEntries(data.map(v => [v.variant, v.engagement.command_rate])) },
  ], [data]);

  return (
    <Card>
      <CardHeader title={title} />
      <CardContent>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart data={radarData}>
              <PolarGrid stroke="#252532" />
              <PolarAngleAxis dataKey="metric" stroke="#888888" />
              <PolarRadiusAxis stroke="#888888" />
              {data.map(v => (
                <Radar
                  key={v.variant}
                  name={v.display_name}
                  dataKey={v.variant}
                  stroke={VARIANT_COLORS[v.variant]}
                  fill={VARIANT_COLORS[v.variant]}
                  fillOpacity={0.3}
                />
              ))}
              <Legend />
              <Tooltip contentStyle={tooltipStyle} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

// ==================== Weekly Trend Chart ====================

interface WeeklyTrendProps {
  data: Array<{
    week: string;
    total_events: number;
    unique_ips: number;
  }>;
  title?: string;
}

export function WeeklyTrendChart({ data, title = 'Weekly Attack Trends' }: WeeklyTrendProps) {
  return (
    <Card>
      <CardHeader title={title} />
      <CardContent>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data}>
              <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
              <XAxis dataKey="week" stroke="#888888" />
              <YAxis stroke="#888888" />
              <Tooltip contentStyle={tooltipStyle} />
              <Legend />
              <Area 
                type="monotone" 
                dataKey="total_events" 
                name="Total Events" 
                stroke={CHART_COLORS.primary} 
                fill={CHART_COLORS.primary} 
                fillOpacity={0.3} 
              />
              <Area 
                type="monotone" 
                dataKey="unique_ips" 
                name="Unique IPs" 
                stroke={CHART_COLORS.secondary} 
                fill={CHART_COLORS.secondary} 
                fillOpacity={0.3} 
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

// ==================== Hourly Pattern Chart ====================

interface HourlyPatternProps {
  data: Array<{ hour: number; count: number }>;
  peakHour?: number;
  title?: string;
}

export function HourlyPatternChart({ data, peakHour, title = 'Hourly Attack Pattern' }: HourlyPatternProps) {
  return (
    <Card>
      <CardHeader title={title} subtitle="Attack distribution by hour of day (UTC)" />
      <CardContent>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data}>
              <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
              <XAxis dataKey="hour" stroke="#888888" />
              <YAxis stroke="#888888" />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="count" fill={CHART_COLORS.tertiary}>
                {data.map((entry, index) => (
                  <Cell 
                    key={index} 
                    fill={entry.hour === peakHour ? CHART_COLORS.primary : CHART_COLORS.tertiary} 
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        {peakHour !== undefined && (
          <div className="mt-4 text-center">
            <span className="text-text-muted">Peak Hour: </span>
            <span className="font-mono text-neon-orange">{peakHour}:00 UTC</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ==================== Geographic Bar Chart ====================

interface GeographicChartProps {
  data: Array<{ country: string; total: number }>;
  title?: string;
  maxItems?: number;
}

export function GeographicBarChart({ data, title = 'Top Attacking Countries', maxItems = 10 }: GeographicChartProps) {
  const chartData = useMemo(() => data.slice(0, maxItems), [data, maxItems]);

  return (
    <Card>
      <CardHeader title={title} />
      <CardContent>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
              <XAxis type="number" stroke="#888888" />
              <YAxis dataKey="country" type="category" stroke="#888888" width={120} />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="total" name="Attacks" fill={CHART_COLORS.primary} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

// ==================== MITRE Technique Chart ====================

interface MITREChartProps {
  data: Array<{ technique_id: string; name: string; count: number }>;
  title?: string;
}

export function MITRETechniqueChart({ data, title = 'MITRE ATT&CK Techniques' }: MITREChartProps) {
  const chartData = useMemo(() => 
    data.map(t => ({
      id: t.technique_id,
      name: t.name.length > 20 ? t.name.slice(0, 20) + '...' : t.name,
      count: t.count,
    })),
    [data]
  );

  return (
    <Card>
      <CardHeader title={title} subtitle="Attack techniques observed in honeypot data" />
      <CardContent>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
              <XAxis dataKey="id" stroke="#888888" />
              <YAxis stroke="#888888" />
              <Tooltip 
                contentStyle={tooltipStyle}
                formatter={(value: number) => value.toLocaleString()}
              />
              <Bar dataKey="count" fill={CHART_COLORS.secondary} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

// ==================== Effectiveness Comparison Chart ====================

interface EffectivenessProps {
  variants: Array<{
    variant: string;
    display_name: string;
    duration: { avg: number };
    metrics: { commands_executed: number; sessions: number };
  }>;
  title?: string;
}

export function EffectivenessScatterChart({ variants, title = 'Engagement vs Duration' }: EffectivenessProps) {
  const chartData = useMemo(() => 
    variants.map(v => ({
      name: v.display_name,
      duration: v.duration.avg,
      commands: v.metrics.commands_executed,
      sessions: v.metrics.sessions,
      commandsPerSession: v.metrics.sessions > 0 
        ? Math.round(v.metrics.commands_executed / v.metrics.sessions * 100) / 100 
        : 0,
    })),
    [variants]
  );

  return (
    <Card>
      <CardHeader title={title} subtitle="Commands per session vs average duration" />
      <CardContent>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
              <XAxis 
                dataKey="duration" 
                stroke="#888888" 
                label={{ value: 'Avg Duration (s)', position: 'bottom', fill: '#888888' }}
              />
              <YAxis 
                stroke="#888888" 
                label={{ value: 'Commands/Session', angle: -90, position: 'insideLeft', fill: '#888888' }}
              />
              <Tooltip 
                contentStyle={tooltipStyle}
                formatter={(value: number, name: string) => [
                  value.toLocaleString(),
                  name === 'commandsPerSession' ? 'Commands/Session' : name
                ]}
              />
              <Scatter dataKey="commandsPerSession" fill={CHART_COLORS.primary}>
                {chartData.map((_, index) => (
                  <Cell 
                    key={index} 
                    fill={VARIANT_COLORS[variants[index]?.variant] || CHART_COLORS.primary}
                  />
                ))}
              </Scatter>
            </ComposedChart>
          </ResponsiveContainer>
        </div>
        <div className="flex justify-center gap-6 mt-4">
          {variants.map(v => (
            <div key={v.variant} className="flex items-center gap-2">
              <div 
                className="w-3 h-3 rounded-full" 
                style={{ backgroundColor: VARIANT_COLORS[v.variant] }}
              />
              <span className="text-sm text-text-secondary">{v.display_name}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

