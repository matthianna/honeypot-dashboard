import { useCallback, useEffect, useState } from 'react';
import { Command, GitBranch, Play, Clock } from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { useAnalytics } from './AnalyticsLayout';
import { KPIGrid, KPICard, ExportToolbar, exportToCSV } from '../../components/analytics';
import DataTable from '../../components/DataTable';
import LoadingSpinner from '../../components/LoadingSpinner';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

const VARIANT_COLORS: Record<string, string> = {
  plain: '#39ff14',
  openai: '#00d4ff',
  ollama: '#ff6600',
};

export default function Commands() {
  const { timeRange, setLastUpdated } = useAnalytics();
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [sessionTimeline, setSessionTimeline] = useState<any>(null);
  const [timelineLoading, setTimelineLoading] = useState(false);

  const { data: topCommands, loading: commandsLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsCowrieCommandsTop(timeRange, 30),
    [timeRange]),
    [timeRange],
    60000
  );

  const { data: sequences, loading: seqLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsCowrieSequences(timeRange),
    [timeRange]),
    [timeRange],
    60000
  );

  const { data: sessionsList, loading: sessionsLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsCaseStudyList(timeRange, 3, 20),
    [timeRange]),
    [timeRange],
    60000
  );

  useEffect(() => {
    if (topCommands) setLastUpdated(new Date());
  }, [topCommands, setLastUpdated]);

  const loadSessionTimeline = async (sessionId: string) => {
    setSelectedSession(sessionId);
    setTimelineLoading(true);
    try {
      const data = await api.getAnalyticsCowrieSessionTimeline(sessionId);
      setSessionTimeline(data);
    } catch (error) {
      console.error('Failed to load session timeline:', error);
    } finally {
      setTimelineLoading(false);
    }
  };

  const commandColumns = [
    { key: 'rank', header: '#', render: (_: any, i: number) => i + 1 },
    { key: 'command', header: 'Command', render: (item: any) => (
      <span className="font-mono text-sm text-neon-green">{item.command}</span>
    )},
    { key: 'count', header: 'Count', render: (item: any) => item.count.toLocaleString() },
    { key: 'unique_ips', header: 'Unique IPs' },
    { key: 'by_variant', header: 'By Variant', render: (item: any) => (
      <div className="flex gap-2">
        {Object.entries(item.by_variant || {}).map(([variant, count]: [string, any]) => (
          <span 
            key={variant}
            className="px-1.5 py-0.5 rounded text-xs"
            style={{ 
              backgroundColor: `${VARIANT_COLORS[variant]}20`,
              color: VARIANT_COLORS[variant]
            }}
          >
            {variant}: {count}
          </span>
        ))}
      </div>
    )},
  ];

  const sequenceColumns = [
    { key: 'rank', header: '#', render: (_: any, i: number) => i + 1 },
    { key: 'sequence', header: 'Sequence', render: (item: any) => (
      <span className="font-mono text-sm text-neon-blue">{item.sequence}</span>
    )},
    { key: 'count', header: 'Count', render: (item: any) => item.count.toLocaleString() },
  ];

  const sessionColumns = [
    { key: 'session_id', header: 'Session', render: (item: any) => (
      <button
        onClick={() => loadSessionTimeline(item.session_id)}
        className="font-mono text-xs text-neon-green hover:underline"
      >
        {item.session_id.slice(0, 12)}...
      </button>
    )},
    { key: 'variant', header: 'Variant', render: (item: any) => (
      <span 
        className="px-2 py-0.5 rounded text-xs"
        style={{ 
          backgroundColor: `${VARIANT_COLORS[item.variant] || '#888'}20`,
          color: VARIANT_COLORS[item.variant] || '#888'
        }}
      >
        {item.variant}
      </span>
    )},
    { key: 'commands', header: 'Commands', render: (item: any) => (
      <span className="text-neon-orange font-medium">{item.commands}</span>
    )},
    { key: 'duration', header: 'Duration', render: (item: any) => `${item.duration.toFixed(1)}s` },
  ];

  return (
    <div className="space-y-6">
      {/* KPIs */}
      <KPIGrid columns={4}>
        <KPICard
          title="Total Commands"
          value={topCommands?.commands?.reduce((a: number, c: any) => a + c.count, 0) || 0}
          icon={<Command className="w-5 h-5" />}
          color="green"
          loading={commandsLoading}
        />
        <KPICard
          title="Unique Commands"
          value={topCommands?.commands?.length || 0}
          icon={<Command className="w-5 h-5" />}
          color="blue"
          loading={commandsLoading}
        />
        <KPICard
          title="Command Sequences"
          value={sequences?.bigrams?.length || 0}
          icon={<GitBranch className="w-5 h-5" />}
          color="orange"
          loading={seqLoading}
        />
        <KPICard
          title="Interactive Sessions"
          value={sessionsList?.total || 0}
          icon={<Play className="w-5 h-5" />}
          color="purple"
          loading={sessionsLoading}
        />
      </KPIGrid>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Commands */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display font-bold text-white flex items-center gap-2">
              <Command className="w-5 h-5 text-neon-green" />
              Top Commands
            </h3>
            <ExportToolbar
              onExportCSV={() => exportToCSV(topCommands?.commands || [], 'top_commands')}
            />
          </div>
          {commandsLoading ? (
            <div className="h-64 flex items-center justify-center">
              <LoadingSpinner />
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topCommands?.commands?.slice(0, 10) || []} layout="vertical">
                  <XAxis type="number" stroke="#555" tick={{ fill: '#888', fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="command"
                    stroke="#555"
                    tick={{ fill: '#888', fontSize: 10 }}
                    width={150}
                    tickFormatter={(v) => v.length > 20 ? v.slice(0, 20) + '...' : v}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(26, 26, 37, 0.95)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                    }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {(topCommands?.commands?.slice(0, 10) || []).map((_: any, i: number) => (
                      <Cell key={i} fill={i === 0 ? '#39ff14' : '#00d4ff'} fillOpacity={1 - i * 0.08} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Command Sequences */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display font-bold text-white flex items-center gap-2">
              <GitBranch className="w-5 h-5 text-neon-orange" />
              Command Sequences (Bigrams)
            </h3>
          </div>
          <DataTable
            columns={sequenceColumns}
            data={sequences?.bigrams?.slice(0, 10) || []}
            loading={seqLoading}
            maxHeight="250px"
          />
        </div>
      </div>

      {/* Full Command Table */}
      <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-display font-bold text-white">All Commands</h3>
          <ExportToolbar
            onExportCSV={() => exportToCSV(topCommands?.commands || [], 'all_commands')}
          />
        </div>
        <DataTable
          columns={commandColumns}
          data={topCommands?.commands || []}
          loading={commandsLoading}
          maxHeight="400px"
        />
      </div>

      {/* Session Playback */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Session List */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <h3 className="font-display font-bold text-white mb-4 flex items-center gap-2">
            <Play className="w-5 h-5 text-neon-purple" />
            Interactive Sessions (3+ commands)
          </h3>
          <DataTable
            columns={sessionColumns}
            data={sessionsList?.sessions || []}
            loading={sessionsLoading}
            maxHeight="350px"
          />
        </div>

        {/* Session Timeline */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <h3 className="font-display font-bold text-white mb-4 flex items-center gap-2">
            <Clock className="w-5 h-5 text-neon-blue" />
            Session Playback
          </h3>
          {!selectedSession ? (
            <div className="h-64 flex items-center justify-center text-text-muted">
              Select a session to view its timeline
            </div>
          ) : timelineLoading ? (
            <div className="h-64 flex items-center justify-center">
              <LoadingSpinner />
            </div>
          ) : sessionTimeline ? (
            <div className="space-y-4 max-h-80 overflow-y-auto">
              <div className="text-sm text-text-muted">
                Session: <span className="text-neon-green font-mono">{selectedSession}</span>
                {sessionTimeline.info?.src_ip && (
                  <span> from <span className="text-neon-blue">{sessionTimeline.info.src_ip}</span></span>
                )}
              </div>
              <div className="space-y-2">
                {sessionTimeline.events?.filter((e: any) => e.event_type?.includes('command'))
                  .map((event: any, i: number) => (
                    <div key={i} className="flex items-start gap-3 p-2 bg-bg-secondary rounded">
                      <span className="text-xs text-text-muted font-mono whitespace-nowrap">
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </span>
                      <span className="font-mono text-sm text-neon-green flex-1">
                        $ {event.details?.input || 'unknown'}
                      </span>
                    </div>
                  ))}
              </div>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-text-muted">
              No timeline data available
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

