// CowrieDemo.tsx - Cowrie SSH Honeypot Analysis Page
import { useState } from 'react';
import {
  BarChart2,
  Clock,
  Map,
  Terminal,
  Key,
  GitCompare,
  TrendingUp,
  Eye,
  Users,
  Bot,
  Zap,
  Shield,
  Globe,
  X,
  Play,
  Pause,
  RotateCcw,
  CheckCircle,
  XCircle,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  Legend,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
} from 'recharts';
import Card, { CardHeader, CardContent } from '../components/Card';
import StatsCard from '../components/StatsCard';
import Tabs from '../components/Tabs';
import DataTable from '../components/DataTable';
import IPLink from '../components/IPLink';
import HoneypotMap from '../components/HoneypotMap';

// Import mock data
import {
  MOCK_STATS,
  MOCK_SESSION_BEHAVIOR,
  MOCK_COMMANDS,
  MOCK_COMMAND_INTENT,
  MOCK_COMMANDS_BY_VARIANT,
  MOCK_TOP_COMMANDS,
  MOCK_VARIANTS,
  MOCK_RADAR_DATA,
  MOCK_DURATION_DISTRIBUTION,
  MOCK_VARIANT_TIMELINE,
  MOCK_SESSIONS,
  MOCK_GEO_DATA,
  MOCK_CREDENTIALS,
  MOCK_TOP_USERNAMES,
  MOCK_TOP_PASSWORDS,
  MOCK_CREDENTIAL_STATS,
  MOCK_DEPLOYMENT,
  MOCK_INTERESTING_SESSIONS,
  MOCK_SESSION_DETAILS,
} from './demo/cowrieMockData';

const COLORS = ['#39ff14', '#00d4ff', '#ff6600', '#bf00ff', '#ff3366'];
const VARIANT_COLORS: Record<string, string> = {
  'plain': '#39ff14',
  'openai': '#00d4ff',
  'ollama': '#bf00ff',
};
const VARIANT_LABELS: Record<string, string> = {
  'plain': 'Plain (Standard)',
  'openai': 'OpenAI (GPT-4o)',
  'ollama': 'Ollama (Llama 3)',
};

// Mock Session Modal Component
function MockSessionModal({ sessionId, onClose }: { sessionId: string; onClose: () => void }) {
  const [activeTab, setActiveTab] = useState<'replay' | 'commands' | 'credentials' | 'events'>('replay');
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentCommandIndex, setCurrentCommandIndex] = useState(0);
  
  const details = MOCK_SESSION_DETAILS[sessionId];
  
  if (!details) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
        <div className="bg-bg-secondary rounded-xl p-8 text-center">
          <p className="text-text-secondary">Session details not available</p>
          <button onClick={onClose} className="mt-4 px-4 py-2 bg-neon-purple text-white rounded-lg">
            Close
          </button>
        </div>
      </div>
    );
  }

  const formatTime = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return timestamp;
    }
  };

  const formatDuration = (seconds: number): string => {
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  };

  const handlePlay = () => {
    if (currentCommandIndex >= details.commands.length) {
      setCurrentCommandIndex(0);
    }
    setIsPlaying(!isPlaying);
  };

  const handleReset = () => {
    setIsPlaying(false);
    setCurrentCommandIndex(0);
  };

  // Auto-advance commands when playing
  if (isPlaying && currentCommandIndex < details.commands.length) {
    setTimeout(() => {
      setCurrentCommandIndex(prev => prev + 1);
      if (currentCommandIndex + 1 >= details.commands.length) {
        setIsPlaying(false);
      }
    }, 800);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="bg-bg-secondary rounded-xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl border border-bg-hover">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-bg-hover">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-neon-green/10">
              <Terminal className="w-5 h-5 text-neon-green" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white">Session Replay</h3>
              <p className="text-xs text-text-muted font-mono">{sessionId.slice(0, 24)}...</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-bg-hover rounded-lg transition-colors">
            <X className="w-5 h-5 text-text-secondary" />
          </button>
        </div>

        {/* Session Info */}
        <div className="p-4 bg-bg-card border-b border-bg-hover">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-text-muted">Source IP:</span>
              <p className="font-mono text-neon-blue">{details.info.src_ip}</p>
            </div>
            <div>
              <span className="text-text-muted">Location:</span>
              <p className="text-white">{details.info.city}, {details.info.country}</p>
            </div>
            <div>
              <span className="text-text-muted">Duration:</span>
              <p className="font-mono text-neon-orange">{formatDuration(details.info.duration)}</p>
            </div>
            <div>
              <span className="text-text-muted">Sensor:</span>
              <p className="text-neon-purple">{details.info.sensor}</p>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-bg-hover">
          {[
            { id: 'replay', label: 'Replay', icon: <Play className="w-4 h-4" /> },
            { id: 'commands', label: `Commands (${details.commands.length})`, icon: <Terminal className="w-4 h-4" /> },
            { id: 'credentials', label: `Credentials (${details.credentials.length})`, icon: <Key className="w-4 h-4" /> },
            { id: 'events', label: `Events (${details.events.length})`, icon: <Eye className="w-4 h-4" /> },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'text-neon-green border-b-2 border-neon-green bg-neon-green/5'
                  : 'text-text-secondary hover:text-white hover:bg-bg-hover'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-4">
          {/* Replay Tab */}
          {activeTab === 'replay' && (
            <div className="space-y-4">
              {/* Controls */}
              <div className="flex items-center gap-3 bg-bg-card rounded-lg p-3">
                <button
                  onClick={handlePlay}
                  className="p-2 rounded-lg bg-neon-green/20 text-neon-green hover:bg-neon-green/30 transition-colors"
                >
                  {isPlaying ? <Pause className="w-5 h-5" /> : <Play className="w-5 h-5" />}
                </button>
                <button
                  onClick={handleReset}
                  className="p-2 rounded-lg bg-bg-hover text-text-secondary hover:text-white transition-colors"
                >
                  <RotateCcw className="w-5 h-5" />
                </button>
                <div className="flex-1 h-2 bg-bg-hover rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-neon-green transition-all duration-300"
                    style={{ width: `${(currentCommandIndex / Math.max(details.commands.length, 1)) * 100}%` }}
                  />
                </div>
                <span className="text-sm text-text-muted font-mono">
                  {currentCommandIndex}/{details.commands.length}
                </span>
              </div>

              {/* Terminal */}
              <div className="bg-[#0c0c0c] rounded-lg border border-bg-hover font-mono text-sm">
                <div className="flex items-center gap-2 px-4 py-2 bg-bg-card border-b border-bg-hover rounded-t-lg">
                  <div className="w-3 h-3 rounded-full bg-red-500" />
                  <div className="w-3 h-3 rounded-full bg-yellow-500" />
                  <div className="w-3 h-3 rounded-full bg-green-500" />
                  <span className="ml-2 text-xs text-text-muted">root@{details.info.sensor}</span>
                </div>
                <div className="p-4 h-80 overflow-y-auto">
                  {details.commands.slice(0, currentCommandIndex).map((cmd, i) => (
                    <div key={i} className="mb-2">
                      <div className="flex items-start gap-2">
                        <span className="text-text-muted text-xs">{formatTime(cmd.timestamp)}</span>
                        <span className="text-neon-green">$</span>
                        <span className="text-white break-all">{cmd.command}</span>
                      </div>
                    </div>
                  ))}
                  {currentCommandIndex < details.commands.length && (
                    <div className="flex items-center gap-2 text-neon-green">
                      <span>$</span>
                      <span className="w-2 h-4 bg-neon-green animate-pulse" />
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Commands Tab */}
          {activeTab === 'commands' && (
            <div className="space-y-2">
              {details.commands.map((cmd, i) => (
                <div
                  key={i}
                  className="flex items-start gap-3 p-3 bg-bg-card rounded-lg border border-bg-hover hover:border-neon-green/30 transition-colors"
                >
                  <div className="text-xs text-text-muted font-mono w-8 pt-0.5">{i + 1}.</div>
                  <div className="flex-1 min-w-0">
                    <pre className="font-mono text-sm text-neon-green whitespace-pre-wrap break-all">
                      {cmd.command}
                    </pre>
                    <div className="text-xs text-text-muted mt-1">{formatTime(cmd.timestamp)}</div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Credentials Tab */}
          {activeTab === 'credentials' && (
            <div className="space-y-3">
              {details.credentials.map((cred, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between p-4 bg-bg-card rounded-lg border border-bg-hover"
                >
                  <div className="flex items-center gap-4">
                    <div className="text-xs text-text-muted">{formatTime(cred.timestamp)}</div>
                    <div className="flex items-center gap-2">
                      <code className="font-mono text-neon-green bg-neon-green/10 px-2 py-1 rounded">{cred.username}</code>
                      <span className="text-text-muted">:</span>
                      <code className="font-mono text-neon-orange bg-neon-orange/10 px-2 py-1 rounded">{cred.password}</code>
                    </div>
                  </div>
                  {cred.success ? (
                    <span className="flex items-center gap-1 text-neon-green text-sm">
                      <CheckCircle className="w-4 h-4" /> Success
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-neon-red text-sm">
                      <XCircle className="w-4 h-4" /> Failed
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Events Tab */}
          {activeTab === 'events' && (
            <div className="space-y-2">
              {details.events.map((event, i) => (
                <div
                  key={i}
                  className="flex items-center gap-4 p-3 bg-bg-card rounded-lg border border-bg-hover"
                >
                  <div className="text-xs text-text-muted font-mono w-20">{formatTime(event.timestamp)}</div>
                  <div className="px-2 py-1 rounded text-xs font-medium bg-neon-blue/10 text-neon-blue">
                    {event.type}
                  </div>
                  <div className="flex-1 text-sm text-text-secondary">
                    {JSON.stringify(event.details)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function CowrieDemo() {
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);

  const formatTimestamp = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return timestamp;
    }
  };

  const formatDuration = (seconds: number | null | undefined): string => {
    if (seconds === null || seconds === undefined) return '0s';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  };

  const sessionColumns = [
    {
      key: 'session_id',
      header: 'Session',
      render: (item: Record<string, unknown>) => {
        const sessionId = item.session_id as string;
        const hasDetails = MOCK_SESSION_DETAILS[sessionId];
        return (
          <button
            onClick={() => hasDetails && setSelectedSessionId(sessionId)}
            className={`font-mono text-xs ${hasDetails ? 'text-neon-green hover:underline cursor-pointer' : 'text-text-muted'}`}
            disabled={!hasDetails}
          >
            {sessionId?.slice(0, 12)}...
            {hasDetails && <Play className="inline w-3 h-3 ml-1" />}
          </button>
        );
      },
    },
    {
      key: 'src_ip',
      header: 'Source IP',
      render: (item: Record<string, unknown>) => <IPLink ip={item.src_ip as string} />,
    },
    {
      key: 'variant',
      header: 'Variant',
      render: (item: Record<string, unknown>) => (
        <span className="capitalize px-2 py-0.5 rounded text-xs" style={{ color: VARIANT_COLORS[(item.variant as string) || 'plain'], backgroundColor: `${VARIANT_COLORS[(item.variant as string) || 'plain']}20` }}>
          {(item.variant as string) || 'plain'}
        </span>
      ),
    },
    {
      key: 'duration',
      header: 'Duration',
      render: (item: Record<string, unknown>) => (
        <span className="font-mono text-neon-blue">{formatDuration(item.duration as number)}</span>
      ),
    },
    {
      key: 'commands_count',
      header: 'Commands',
      render: (item: Record<string, unknown>) => (
        <span className={`font-mono ${(item.commands_count as number) > 0 ? 'text-neon-orange' : 'text-text-muted'}`}>
          {(item.commands_count as number) || 0}
        </span>
      ),
    },
  ];

  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      icon: <BarChart2 className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Stats Cards */}
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            <div className="lg:col-span-3 grid grid-cols-1 sm:grid-cols-4 gap-4">
              <StatsCard title="Total Events" value={MOCK_STATS.total_events} color="green" />
              <StatsCard title="Unique Attackers" value={MOCK_STATS.unique_ips} color="blue" />
              <StatsCard title="Sessions" value={MOCK_STATS.total_sessions} color="purple" />
              <StatsCard title="Variants" value={MOCK_STATS.variants_count} color="orange" />
            </div>
            {/* Deployment Info */}
            <Card className="bg-gradient-to-br from-neon-green/5 to-transparent">
              <CardContent className="p-4">
                <div className="text-xs text-text-secondary mb-2 font-medium">Deployment</div>
                <div className="space-y-2">
                  {MOCK_DEPLOYMENT.map((d) => (
                    <div key={d.ip} className="flex items-center justify-between text-xs">
                      <span className="capitalize" style={{ color: VARIANT_COLORS[d.variant] }}>{d.variant}</span>
                      <span className="font-mono text-text-muted">{d.ip}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Command Statistics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <Card className="bg-gradient-to-br from-neon-green/10 to-transparent">
              <CardContent className="p-4">
                <div className="text-2xl font-display font-bold text-neon-green">
                  {MOCK_VARIANTS.reduce((sum, v) => sum + v.commands_count, 0).toLocaleString()}
                </div>
                <div className="text-xs text-text-secondary">Total Commands</div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-blue/10 to-transparent">
              <CardContent className="p-4">
                <div className="text-2xl font-display font-bold text-neon-blue">
                  {MOCK_VARIANTS.reduce((sum, v) => sum + v.unique_commands, 0)}
                </div>
                <div className="text-xs text-text-secondary">Unique Commands</div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-purple/10 to-transparent">
              <CardContent className="p-4">
                <div className="text-2xl font-display font-bold text-neon-purple">
                  {(MOCK_VARIANTS.reduce((sum, v) => sum + v.commands_count, 0) / MOCK_STATS.total_sessions).toFixed(2)}
                </div>
                <div className="text-xs text-text-secondary">Avg Cmds/Session</div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-orange/10 to-transparent">
              <CardContent className="p-4">
                <div className="text-2xl font-display font-bold text-neon-orange">
                  {MOCK_VARIANTS.reduce((sum, v) => sum + v.sessions_with_commands, 0).toLocaleString()}
                </div>
                <div className="text-xs text-text-secondary">Sessions w/ Commands</div>
              </CardContent>
            </Card>
          </div>

          {/* Event Timeline */}
          <Card>
            <CardHeader title="Event Timeline by Variant" subtitle="Plain vs OpenAI vs Ollama activity over time" icon={<Clock className="w-5 h-5" />} />
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={MOCK_VARIANT_TIMELINE}>
                    <defs>
                      <linearGradient id="colorPlainDemo" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#39ff14" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#39ff14" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="colorOpenaiDemo" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="colorOllamaDemo" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#bf00ff" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#bf00ff" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                    <XAxis dataKey="timestamp" tickFormatter={formatTimestamp} stroke="#888888" />
                    <YAxis stroke="#888888" />
                    <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                    <Legend />
                    <Area type="monotone" dataKey="plain" name="Plain" stroke="#39ff14" fill="url(#colorPlainDemo)" strokeWidth={2} stackId="1" />
                    <Area type="monotone" dataKey="openai" name="OpenAI" stroke="#00d4ff" fill="url(#colorOpenaiDemo)" strokeWidth={2} stackId="1" />
                    <Area type="monotone" dataKey="ollama" name="Ollama" stroke="#bf00ff" fill="url(#colorOllamaDemo)" strokeWidth={2} stackId="1" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          {/* Sessions Table */}
          <Card>
            <CardHeader title="Recent Sessions" icon={<Terminal className="w-5 h-5" />} />
            <CardContent>
              <DataTable columns={sessionColumns} data={MOCK_SESSIONS.slice(0, 20)} emptyMessage="No sessions found" />
            </CardContent>
          </Card>

          {/* Top Countries */}
          <Card>
            <CardHeader 
              title="Top Attack Countries" 
              subtitle={`${MOCK_GEO_DATA.length} countries total`}
              icon={<Globe className="w-5 h-5" />}
            />
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                {MOCK_GEO_DATA.slice(0, 5).map((item, index) => (
                  <div key={item.country} className="bg-bg-secondary rounded-lg p-3 text-center hover:bg-bg-hover transition-colors">
                    <div className="flex items-center justify-center gap-2 mb-1">
                      <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                      <span className="font-medium text-text-primary text-sm truncate">{item.country}</span>
                    </div>
                    <div className="text-lg font-mono font-bold text-neon-green">{item.count.toLocaleString()}</div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'sessions',
      label: 'Session Explorer',
      icon: <Terminal className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Session Statistics */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
              <div className="text-2xl font-display font-bold text-neon-green">{MOCK_STATS.total_sessions.toLocaleString()}</div>
              <div className="text-xs text-text-secondary">Total Sessions</div>
            </div>
            <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
              <div className="text-2xl font-display font-bold text-neon-blue">{MOCK_COMMANDS.total.toLocaleString()}</div>
              <div className="text-xs text-text-secondary">Total Commands</div>
            </div>
            <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
              <div className="text-2xl font-display font-bold text-neon-purple">{MOCK_SESSION_BEHAVIOR.human.count}</div>
              <div className="text-xs text-text-secondary">Human-like (≥60s)</div>
            </div>
            <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
              <div className="text-2xl font-display font-bold text-neon-orange">{MOCK_SESSION_BEHAVIOR.bot.count.toLocaleString()}</div>
              <div className="text-xs text-text-secondary">Bot-like (5-60s)</div>
            </div>
            <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
              <div className="text-2xl font-display font-bold text-text-muted">{MOCK_SESSION_BEHAVIOR.script.count}</div>
              <div className="text-xs text-text-secondary">Script (&lt;5s)</div>
            </div>
          </div>

          {/* Behavior Analysis & Duration Distribution */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Session Behavior Analysis" subtitle="Classification based on duration and activity" icon={<Users className="w-5 h-5" />} />
              <CardContent>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="flex items-center gap-2 text-sm"><Users className="w-4 h-4 text-neon-purple" />Human (≥60s)</span>
                      <span className="font-mono text-neon-purple">{MOCK_SESSION_BEHAVIOR.human.count} ({MOCK_SESSION_BEHAVIOR.human.percentage}%)</span>
                    </div>
                    <div className="h-2 bg-bg-secondary rounded-full overflow-hidden">
                      <div className="h-full bg-neon-purple rounded-full" style={{ width: `${MOCK_SESSION_BEHAVIOR.human.percentage}%` }} />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="flex items-center gap-2 text-sm"><Bot className="w-4 h-4 text-neon-orange" />Bot (5-60s)</span>
                      <span className="font-mono text-neon-orange">{MOCK_SESSION_BEHAVIOR.bot.count.toLocaleString()} ({MOCK_SESSION_BEHAVIOR.bot.percentage}%)</span>
                    </div>
                    <div className="h-2 bg-bg-secondary rounded-full overflow-hidden">
                      <div className="h-full bg-neon-orange rounded-full" style={{ width: `${MOCK_SESSION_BEHAVIOR.bot.percentage}%` }} />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="flex items-center gap-2 text-sm"><Zap className="w-4 h-4 text-text-muted" />Script (&lt;5s)</span>
                      <span className="font-mono text-text-muted">{MOCK_SESSION_BEHAVIOR.script.count} ({MOCK_SESSION_BEHAVIOR.script.percentage}%)</span>
                    </div>
                    <div className="h-2 bg-bg-secondary rounded-full overflow-hidden">
                      <div className="h-full bg-text-muted rounded-full" style={{ width: `${MOCK_SESSION_BEHAVIOR.script.percentage}%` }} />
                    </div>
                  </div>
                  
                  <div className="pt-4 border-t border-bg-hover">
                    <div className="grid grid-cols-3 gap-2 text-center text-xs">
                      <div>
                        <div className="text-neon-purple font-bold">{MOCK_SESSION_BEHAVIOR.human.commands}</div>
                        <div className="text-text-muted">Human Cmds</div>
                      </div>
                      <div>
                        <div className="text-neon-orange font-bold">{MOCK_SESSION_BEHAVIOR.bot.commands.toLocaleString()}</div>
                        <div className="text-text-muted">Bot Cmds</div>
                      </div>
                      <div>
                        <div className="text-text-secondary font-bold">{MOCK_SESSION_BEHAVIOR.script.commands}</div>
                        <div className="text-text-muted">Script Cmds</div>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="Session Duration Distribution" icon={<Clock className="w-5 h-5" />} />
              <CardContent>
                <div className="h-48">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={[
                      { range: '0-5s', count: MOCK_SESSION_BEHAVIOR.script.count },
                      { range: '5-30s', count: 4200 },
                      { range: '30s-1m', count: 2800 },
                      { range: '1-5m', count: 1250 },
                      { range: '5m+', count: 127 },
                    ]}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis dataKey="range" stroke="#888888" />
                      <YAxis stroke="#888888" />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      <Bar dataKey="count" fill="#39ff14" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Interesting Sessions */}
          <Card>
            <CardHeader 
              title="Interesting Sessions for Analysis" 
              subtitle="Sessions with significant activity - click to replay"
              icon={<Eye className="w-5 h-5" />}
            />
            <CardContent>
              <DataTable
                data={MOCK_INTERESTING_SESSIONS.sessions}
                columns={[
                  { key: 'session_id', header: 'Session', render: (item: Record<string, unknown>) => {
                    const sessionId = item.session_id as string;
                    const hasDetails = MOCK_SESSION_DETAILS[sessionId];
                    return (
                      <button
                        onClick={() => hasDetails && setSelectedSessionId(sessionId)}
                        className={`font-mono text-xs ${hasDetails ? 'text-neon-green hover:underline cursor-pointer' : 'text-text-muted'}`}
                        disabled={!hasDetails}
                      >
                        {sessionId?.slice(0, 16)}...
                        {hasDetails && <Play className="inline w-3 h-3 ml-1" />}
                      </button>
                    );
                  }},
                  { key: 'src_ip', header: 'Source IP', render: (item: Record<string, unknown>) => <IPLink ip={item.src_ip as string} /> },
                  { key: 'country', header: 'Country', render: (item: Record<string, unknown>) => (item.country as string) || 'Unknown' },
                  { key: 'variant', header: 'Variant', render: (item: Record<string, unknown>) => (
                    <span className="capitalize" style={{ color: VARIANT_COLORS[(item.variant as string) || 'plain'] || '#39ff14' }}>{(item.variant as string) || 'plain'}</span>
                  )},
                  { key: 'commands_count', header: 'Commands', render: (item: Record<string, unknown>) => (
                    <span className="font-mono text-neon-green font-bold">{(item.commands_count as number) || 0}</span>
                  )},
                  { key: 'duration', header: 'Duration', render: (item: Record<string, unknown>) => formatDuration(item.duration as number) },
                ]}
                emptyMessage="No interesting sessions found"
              />
            </CardContent>
          </Card>

          {/* Variant Session Breakdown */}
          <Card>
            <CardHeader title="Sessions by Variant" subtitle="Breakdown of session activity per honeypot variant" icon={<GitCompare className="w-5 h-5" />} />
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {MOCK_VARIANTS.map((v) => (
                  <div key={v.variant} className="bg-bg-secondary rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-3 pb-2 border-b border-bg-hover">
                      <div className="w-3 h-3 rounded-full" style={{ backgroundColor: VARIANT_COLORS[v.variant] }} />
                      <span className="font-medium text-text-primary capitalize">{v.variant}</span>
                    </div>
                    <div className="grid grid-cols-2 gap-3 text-sm">
                      <div>
                        <div className="text-text-muted">Sessions</div>
                        <div className="font-mono text-lg" style={{ color: VARIANT_COLORS[v.variant] }}>{v.sessions_count.toLocaleString()}</div>
                      </div>
                      <div>
                        <div className="text-text-muted">Commands</div>
                        <div className="font-mono text-lg text-neon-orange">{v.commands_count.toLocaleString()}</div>
                      </div>
                      <div>
                        <div className="text-text-muted">Avg Duration</div>
                        <div className="font-mono text-neon-blue">{formatDuration(v.avg_session_duration)}</div>
                      </div>
                      <div>
                        <div className="text-text-muted">Login Rate</div>
                        <div className="font-mono text-neon-green">{v.success_rate}%</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'commands',
      label: 'Commands',
      icon: <Terminal className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Stats Row */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <Card className="bg-gradient-to-br from-neon-green/10 to-transparent">
              <CardContent className="p-4">
                <div className="text-2xl font-display font-bold text-neon-green">{MOCK_COMMANDS.total.toLocaleString()}</div>
                <div className="text-xs text-text-secondary">Total Executions</div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-blue/10 to-transparent">
              <CardContent className="p-4">
                <div className="text-2xl font-display font-bold text-neon-blue">{MOCK_COMMANDS.unique}</div>
                <div className="text-xs text-text-secondary">Unique Commands</div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-red/10 to-transparent">
              <CardContent className="p-4">
                <div className="text-2xl font-display font-bold text-neon-red">{MOCK_COMMANDS.critical_risk}</div>
                <div className="text-xs text-text-secondary">Critical Risk</div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-orange/10 to-transparent">
              <CardContent className="p-4">
                <div className="text-2xl font-display font-bold text-neon-orange">{MOCK_COMMANDS.high_risk}</div>
                <div className="text-xs text-text-secondary">High Risk</div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-purple/10 to-transparent">
              <CardContent className="p-4">
                <div className="text-2xl font-display font-bold text-neon-purple">{MOCK_COMMANDS.mitre_techniques}</div>
                <div className="text-xs text-text-secondary">MITRE Techniques</div>
              </CardContent>
            </Card>
          </div>

          {/* Intent Distribution */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Command Intent Distribution" subtitle="What attackers are trying to do" />
              <CardContent>
                <div className="space-y-3">
                  {MOCK_COMMAND_INTENT.map((intent) => {
                    const total = MOCK_COMMANDS.total;
                    const percentage = Math.round((intent.count / total) * 100);
                    return (
                      <div key={intent.intent} className="flex items-center gap-3">
                        <div className="w-36 text-sm text-text-secondary">{intent.intent}</div>
                        <div className="flex-1 bg-bg-secondary rounded-full h-5 overflow-hidden">
                          <div 
                            className="h-full rounded-full transition-all duration-500"
                            style={{ width: `${percentage}%`, backgroundColor: intent.color }}
                          />
                        </div>
                        <div className="w-24 text-right font-mono text-sm">{intent.count.toLocaleString()}</div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="MITRE ATT&CK Techniques" subtitle="Detected adversary techniques" />
              <CardContent>
                <div className="space-y-2 max-h-80 overflow-y-auto">
                  {[
                    { technique: 'T1082 - System Information Discovery', count: 487 },
                    { technique: 'T1003 - OS Credential Dumping', count: 387 },
                    { technique: 'T1033 - System Owner/User Discovery', count: 356 },
                    { technique: 'T1070 - Indicator Removal', count: 289 },
                    { technique: 'T1059 - Command and Scripting Interpreter', count: 245 },
                    { technique: 'T1105 - Ingress Tool Transfer', count: 189 },
                    { technique: 'T1053 - Scheduled Task/Job', count: 167 },
                    { technique: 'T1057 - Process Discovery', count: 134 },
                    { technique: 'T1049 - System Network Connections', count: 121 },
                  ].map((tech) => (
                    <div key={tech.technique} className="flex items-center justify-between p-3 bg-bg-secondary rounded-lg hover:bg-bg-hover transition-colors">
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-xs text-neon-blue bg-neon-blue/20 px-2 py-1 rounded">{tech.technique.split(' - ')[0]}</span>
                        <span className="text-sm text-text-primary">{tech.technique.split(' - ')[1]}</span>
                      </div>
                      <span className="font-mono text-neon-green font-bold">{tech.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Commands by Variant - CRITICAL FOR THESIS */}
          <Card>
            <CardHeader title="Commands by Variant" subtitle="Comparison of command execution across honeypot variants (AI variants capture more)" />
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={MOCK_COMMANDS_BY_VARIANT} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis type="number" stroke="#888888" />
                      <YAxis dataKey="variant" type="category" stroke="#888888" width={80} />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      <Bar dataKey="commands" radius={[0, 4, 4, 0]}>
                        {MOCK_COMMANDS_BY_VARIANT.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <div className="grid grid-cols-3 gap-4">
                  {MOCK_COMMANDS_BY_VARIANT.map((item) => (
                    <div key={item.variant} className="p-4 bg-bg-secondary rounded-lg text-center">
                      <div className="text-3xl font-display font-bold" style={{ color: item.color }}>
                        {item.commands.toLocaleString()}
                      </div>
                      <div className="text-sm text-text-secondary">{item.variant}</div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Top Commands */}
          <Card>
            <CardHeader title="Top Executed Commands" subtitle="Most frequently used commands by attackers" />
            <CardContent className="p-0">
              <div className="max-h-[400px] overflow-y-auto">
                <table className="w-full">
                  <thead className="sticky top-0 bg-bg-card">
                    <tr className="border-b border-bg-hover">
                      <th className="text-left py-4 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Command</th>
                      <th className="text-left py-4 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Category</th>
                      <th className="text-center py-4 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Risk</th>
                      <th className="text-right py-4 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Count</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-bg-hover">
                    {MOCK_TOP_COMMANDS.map((cmd, index) => {
                      const riskColors: Record<string, string> = {
                        critical: 'bg-neon-red text-white',
                        high: 'bg-neon-orange text-bg-primary',
                        medium: 'bg-neon-yellow text-bg-primary',
                        low: 'bg-bg-hover text-text-secondary'
                      };
                      return (
                        <tr key={index} className="hover:bg-bg-secondary transition-colors">
                          <td className="py-4 px-4">
                            <code className="font-mono text-sm text-neon-green">{cmd.command}</code>
                          </td>
                          <td className="py-4 px-4 text-sm text-text-secondary">{cmd.category}</td>
                          <td className="py-4 px-4 text-center">
                            <span className={`px-2 py-1 rounded text-xs font-medium ${riskColors[cmd.risk]}`}>{cmd.risk}</span>
                          </td>
                          <td className="py-4 px-4 text-right font-mono text-neon-blue font-bold">{cmd.count.toLocaleString()}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'variants',
      label: 'Variant Comparison',
      icon: <GitCompare className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* LLM Comparison Header */}
          <div className="text-center py-4 bg-gradient-to-r from-neon-green/10 via-transparent to-neon-purple/10 rounded-lg border border-bg-hover">
            <h2 className="text-xl font-display font-bold text-white mb-1">LLM Variant Comparison</h2>
            <p className="text-sm text-text-secondary">Side-by-side analysis of Plain, OpenAI, and Ollama honeypot variants</p>
          </div>

          {/* Attacker Time Wasted Analysis */}
          <Card className="border-2 border-neon-purple/30 bg-gradient-to-br from-bg-card to-neon-purple/5">
            <CardHeader 
              title="⏱️ Attacker Time Wasted Analysis" 
              subtitle="Key thesis metric: How long do AI honeypots keep attackers engaged compared to traditional honeypots?" 
              icon={<Clock className="w-5 h-5 text-neon-purple" />}
            />
            <CardContent>
              <div className="space-y-6">
                {/* Time Wasted Summary Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {MOCK_VARIANTS.map((v) => {
                    const totalTimeSeconds = v.avg_session_duration * v.sessions_count;
                    const hours = Math.floor(totalTimeSeconds / 3600);
                    const minutes = Math.floor((totalTimeSeconds % 3600) / 60);
                    const plainData = MOCK_VARIANTS.find(c => c.variant === 'plain');
                    const plainAvg = plainData?.avg_session_duration || 1;
                    const improvement = v.variant !== 'plain' ? ((v.avg_session_duration / plainAvg - 1) * 100) : 0;
                    
                    return (
                      <div 
                        key={v.variant} 
                        className="bg-bg-secondary rounded-xl p-5 border-2 relative overflow-hidden"
                        style={{ borderColor: `${VARIANT_COLORS[v.variant]}50` }}
                      >
                        <div className="absolute inset-0 opacity-5" style={{ background: `linear-gradient(135deg, ${VARIANT_COLORS[v.variant]}, transparent)` }} />
                        <div className="relative z-10">
                          <div className="flex items-center justify-between mb-3">
                            <span className="font-semibold text-lg" style={{ color: VARIANT_COLORS[v.variant] }}>
                              {VARIANT_LABELS[v.variant] || v.variant}
                            </span>
                            {v.variant !== 'plain' && improvement > 0 && (
                              <span className="text-xs px-2 py-1 bg-neon-green/20 text-neon-green rounded-full font-bold">
                                +{improvement.toFixed(0)}% longer
                              </span>
                            )}
                            {v.variant === 'plain' && (
                              <span className="text-xs px-2 py-1 bg-text-muted/20 text-text-muted rounded-full">
                                Baseline
                              </span>
                            )}
                          </div>
                          
                          <div className="space-y-3">
                            <div>
                              <div className="text-xs text-text-muted mb-1">Avg Session Duration</div>
                              <div className="text-3xl font-bold font-mono" style={{ color: VARIANT_COLORS[v.variant] }}>
                                {v.avg_session_duration.toFixed(1)}<span className="text-lg text-text-muted">s</span>
                              </div>
                            </div>
                            
                            <div>
                              <div className="text-xs text-text-muted mb-1">Total Attacker Time Wasted</div>
                              <div className="text-xl font-bold text-white">
                                {hours > 0 && <span>{hours}<span className="text-sm text-text-muted">h </span></span>}
                                {minutes}<span className="text-sm text-text-muted">m</span>
                              </div>
                              <div className="text-xs text-text-secondary mt-1">
                                ({v.sessions_count.toLocaleString()} sessions × {v.avg_session_duration.toFixed(1)}s avg)
                              </div>
                            </div>
                            
                            <div className="grid grid-cols-2 gap-2 pt-2 border-t border-bg-hover">
                              <div>
                                <div className="text-xs text-text-muted">Max Duration</div>
                                <div className="font-mono text-sm text-white">{v.max_session_duration.toFixed(0)}s</div>
                              </div>
                              <div>
                                <div className="text-xs text-text-muted">P90 Duration</div>
                                <div className="font-mono text-sm text-white">{v.p90_duration.toFixed(1)}s</div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Duration Comparison Bar Chart */}
                <div className="bg-bg-secondary rounded-lg p-4">
                  <h4 className="text-sm font-medium text-text-secondary mb-3">Session Duration Comparison (Higher = Better Deception)</h4>
                  <div className="h-16">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart 
                        data={MOCK_VARIANTS.map(c => ({ 
                          name: VARIANT_LABELS[c.variant] || c.variant, 
                          duration: c.avg_session_duration,
                          variant: c.variant
                        }))} 
                        layout="vertical"
                      >
                        <XAxis type="number" stroke="#888" tick={{ fill: '#888', fontSize: 11 }} unit="s" />
                        <YAxis type="category" dataKey="name" stroke="#888" tick={{ fill: '#888', fontSize: 12 }} width={120} />
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #333', borderRadius: '8px' }}
                          formatter={(value: number) => [`${value.toFixed(1)}s`, 'Avg Duration']}
                        />
                        <Bar dataKey="duration" radius={[0, 4, 4, 0]}>
                          {MOCK_VARIANTS.map((c) => (
                            <Cell key={c.variant} fill={VARIANT_COLORS[c.variant] || '#888'} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Thesis Insight */}
                <div className="bg-neon-purple/10 border border-neon-purple/30 rounded-lg p-4">
                  <div className="flex items-start gap-3">
                    <Zap className="w-5 h-5 text-neon-purple flex-shrink-0 mt-0.5" />
                    <div>
                      <h4 className="font-medium text-neon-purple mb-1">Thesis Insight</h4>
                      <p className="text-sm text-text-secondary">
                        The <strong className="text-neon-blue">OpenAI (GPT-4o)</strong> variant keeps attackers engaged <strong className="text-neon-green">67% longer</strong> than 
                        the traditional Cowrie honeypot (24.7s vs 14.8s average).
                        This demonstrates that AI-powered interactive responses effectively waste more attacker time and resources.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Variant Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {MOCK_VARIANTS.map((v) => (
              <Card key={v.variant} className="overflow-hidden">
                <div className="h-1" style={{ backgroundColor: VARIANT_COLORS[v.variant] }} />
                <CardContent className="p-5">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold text-white">{VARIANT_LABELS[v.variant] || v.variant}</h3>
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: VARIANT_COLORS[v.variant] }} />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <div className="flex items-center gap-2 text-text-muted text-xs mb-1"><Users className="w-3 h-3" />Sessions</div>
                      <div className="text-xl font-bold text-white">{v.sessions_count.toLocaleString()}</div>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 text-text-muted text-xs mb-1"><Clock className="w-3 h-3" />Avg Duration</div>
                      <div className="text-xl font-bold text-white">{v.avg_session_duration.toFixed(1)}s</div>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 text-text-muted text-xs mb-1"><Terminal className="w-3 h-3" />Commands</div>
                      <div className="text-xl font-bold text-white">{v.commands_count.toLocaleString()}</div>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 text-text-muted text-xs mb-1"><Shield className="w-3 h-3" />Login Rate</div>
                      <div className="text-xl font-bold text-white">{v.success_rate}%</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Activity Comparison */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Activity Comparison" subtitle="Events over time by variant" icon={<TrendingUp className="w-5 h-5" />} />
              <CardContent>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={MOCK_VARIANT_TIMELINE}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis dataKey="timestamp" tickFormatter={formatTimestamp} stroke="#888888" />
                      <YAxis stroke="#888888" />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      <Legend />
                      <Line type="monotone" dataKey="plain" name="Plain" stroke="#39ff14" strokeWidth={2} dot={false} />
                      <Line type="monotone" dataKey="openai" name="OpenAI" stroke="#00d4ff" strokeWidth={2} dot={false} />
                      <Line type="monotone" dataKey="ollama" name="Ollama" stroke="#bf00ff" strokeWidth={2} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="Session Duration Analysis" subtitle="Duration percentiles by variant" icon={<Clock className="w-5 h-5" />} />
              <CardContent>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={MOCK_VARIANTS.map(c => ({ name: VARIANT_LABELS[c.variant], avg: c.avg_session_duration, p50: c.p50_duration, p90: c.p90_duration }))}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis dataKey="name" stroke="#888888" tick={{ fontSize: 10 }} />
                      <YAxis stroke="#888888" label={{ value: 'Seconds', angle: -90, position: 'insideLeft', fill: '#888888' }} />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      <Legend />
                      <Bar dataKey="avg" name="Average" fill="#39ff14" />
                      <Bar dataKey="p50" name="Median (P50)" fill="#00d4ff" />
                      <Bar dataKey="p90" name="P90" fill="#ff6600" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Session Duration Distribution by Variant */}
          <Card>
            <CardHeader title="Session Duration Distribution" subtitle="Comparison of how long attackers engage with each variant" />
            <CardContent>
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={MOCK_DURATION_DISTRIBUTION} barGap={2}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                    <XAxis dataKey="range" stroke="#888" tick={{ fill: '#888', fontSize: 12 }} />
                    <YAxis stroke="#888" tick={{ fill: '#888', fontSize: 12 }} />
                    <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #333', borderRadius: '8px' }} />
                    <Legend />
                    <Bar dataKey="plain" name="Plain" fill="#39ff14" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="openai" name="OpenAI" fill="#00d4ff" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="ollama" name="Ollama" fill="#bf00ff" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          {/* Radar + Command Diversity */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Engagement Metrics" subtitle="Multi-dimensional comparison (normalized to 100)" />
              <CardContent>
                <div className="h-72">
                  <ResponsiveContainer width="100%" height="100%">
                    <RadarChart data={MOCK_RADAR_DATA}>
                      <PolarGrid stroke="#333" />
                      <PolarAngleAxis dataKey="metric" tick={{ fill: '#888', fontSize: 11 }} />
                      <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: '#666', fontSize: 10 }} />
                      <Radar name="Plain" dataKey="plain" stroke="#39ff14" fill="#39ff14" fillOpacity={0.3} strokeWidth={2} />
                      <Radar name="OpenAI" dataKey="openai" stroke="#00d4ff" fill="#00d4ff" fillOpacity={0.3} strokeWidth={2} />
                      <Radar name="Ollama" dataKey="ollama" stroke="#bf00ff" fill="#bf00ff" fillOpacity={0.3} strokeWidth={2} />
                      <Legend />
                    </RadarChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="Command Diversity" subtitle="Unique commands per variant" />
              <CardContent>
                <div className="h-72">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={MOCK_VARIANTS.map(c => ({ variant: VARIANT_LABELS[c.variant], uniqueCommands: c.unique_commands }))} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                      <XAxis type="number" stroke="#888" tick={{ fill: '#888', fontSize: 12 }} />
                      <YAxis type="category" dataKey="variant" stroke="#888" tick={{ fill: '#888', fontSize: 11 }} width={120} />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #333', borderRadius: '8px' }} />
                      <Bar dataKey="uniqueCommands" name="Unique Commands" radius={[0, 4, 4, 0]}>
                        {MOCK_VARIANTS.map((c) => (<Cell key={c.variant} fill={VARIANT_COLORS[c.variant] || '#888'} />))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Attack Funnel */}
          <Card>
            <CardHeader title="Attack Funnel Comparison" subtitle="Progression: Session → Login Attempt → Success → Commands" />
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                {MOCK_VARIANTS.map((v) => {
                  const totalLogins = v.login_success + v.login_failed;
                  const stages = [
                    { label: 'Sessions', value: v.sessions_count, pct: 100 },
                    { label: 'Login Attempts', value: totalLogins, pct: v.sessions_count > 0 ? (totalLogins / v.sessions_count) * 100 : 0 },
                    { label: 'Login Success', value: v.login_success, pct: v.sessions_count > 0 ? (v.login_success / v.sessions_count) * 100 : 0 },
                    { label: 'Commands', value: v.commands_count, pct: v.sessions_count > 0 ? Math.min((v.commands_count / v.sessions_count) * 100, 100) : 0 },
                  ];
                  return (
                    <div key={v.variant} className="space-y-3">
                      <h4 className="font-semibold text-center pb-2 border-b" style={{ color: VARIANT_COLORS[v.variant], borderColor: `${VARIANT_COLORS[v.variant]}40` }}>
                        {VARIANT_LABELS[v.variant] || v.variant}
                      </h4>
                      {stages.map((stage, idx) => (
                        <div key={stage.label} className="relative">
                          <div className="flex justify-between text-sm mb-1">
                            <span className="text-text-secondary">{stage.label}</span>
                            <span className="text-white font-mono">{stage.value.toLocaleString()}</span>
                          </div>
                          <div className="h-6 bg-bg-secondary rounded overflow-hidden">
                            <div className="h-full rounded transition-all" style={{ width: `${Math.min(stage.pct, 100)}%`, backgroundColor: VARIANT_COLORS[v.variant], opacity: 1 - (idx * 0.15) }} />
                          </div>
                        </div>
                      ))}
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Statistical Summary Table */}
          <Card>
            <CardHeader title="Statistical Summary" subtitle="Key metrics comparison" />
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-bg-hover">
                      <th className="text-left py-3 px-4 text-text-secondary font-medium">Metric</th>
                      {MOCK_VARIANTS.map(c => (
                        <th key={c.variant} className="text-right py-3 px-4 font-medium" style={{ color: VARIANT_COLORS[c.variant] }}>
                          {VARIANT_LABELS[c.variant] || c.variant}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Total Events</td>
                      {MOCK_VARIANTS.map(v => (<td key={v.variant} className="text-right py-3 px-4 font-mono text-white">{v.total_events.toLocaleString()}</td>))}
                    </tr>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Unique IPs</td>
                      {MOCK_VARIANTS.map(v => (<td key={v.variant} className="text-right py-3 px-4 font-mono text-white">{v.unique_ips.toLocaleString()}</td>))}
                    </tr>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Sessions</td>
                      {MOCK_VARIANTS.map(v => (<td key={v.variant} className="text-right py-3 px-4 font-mono text-white">{v.sessions_count.toLocaleString()}</td>))}
                    </tr>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Login Success Rate</td>
                      {MOCK_VARIANTS.map(v => (<td key={v.variant} className="text-right py-3 px-4 font-mono text-white">{v.success_rate}%</td>))}
                    </tr>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Commands Executed</td>
                      {MOCK_VARIANTS.map(v => (<td key={v.variant} className="text-right py-3 px-4 font-mono text-white">{v.commands_count.toLocaleString()}</td>))}
                    </tr>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Unique Commands</td>
                      {MOCK_VARIANTS.map(v => (<td key={v.variant} className="text-right py-3 px-4 font-mono text-white">{v.unique_commands}</td>))}
                    </tr>
                    <tr className="border-b border-bg-hover/50 bg-neon-green/5">
                      <td className="py-3 px-4 text-text-secondary font-medium">Avg Commands/Session</td>
                      {MOCK_VARIANTS.map(v => (<td key={v.variant} className="text-right py-3 px-4 font-mono font-bold" style={{ color: VARIANT_COLORS[v.variant] }}>{v.avg_commands_per_session.toFixed(2)}</td>))}
                    </tr>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Sessions with Commands</td>
                      {MOCK_VARIANTS.map(v => (<td key={v.variant} className="text-right py-3 px-4 font-mono text-white">{v.sessions_with_commands.toLocaleString()}</td>))}
                    </tr>
                    <tr className="border-b border-bg-hover/50 bg-neon-blue/5">
                      <td className="py-3 px-4 text-text-secondary font-medium">Avg Cmds/Active Session</td>
                      {MOCK_VARIANTS.map(v => (<td key={v.variant} className="text-right py-3 px-4 font-mono font-bold" style={{ color: VARIANT_COLORS[v.variant] }}>{v.avg_commands_per_active_session.toFixed(2)}</td>))}
                    </tr>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">File Downloads</td>
                      {MOCK_VARIANTS.map(v => (<td key={v.variant} className="text-right py-3 px-4 font-mono text-white">{v.file_downloads}</td>))}
                    </tr>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Avg Session Duration</td>
                      {MOCK_VARIANTS.map(v => (<td key={v.variant} className="text-right py-3 px-4 font-mono text-white">{v.avg_session_duration.toFixed(2)}s</td>))}
                    </tr>
                    <tr>
                      <td className="py-3 px-4 text-text-secondary">Max Session Duration</td>
                      {MOCK_VARIANTS.map(v => (<td key={v.variant} className="text-right py-3 px-4 font-mono text-white">{v.max_session_duration.toFixed(1)}s</td>))}
                    </tr>
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'credentials',
      label: 'Credentials',
      icon: <Key className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
            <Card className="bg-gradient-to-br from-neon-orange/10 to-transparent">
              <CardContent className="p-4">
                <div className="text-2xl font-display font-bold text-neon-orange">
                  {MOCK_CREDENTIAL_STATS.total_attempts.toLocaleString()}
                </div>
                <div className="text-xs text-text-secondary">Total Attempts</div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-green/10 to-transparent">
              <CardContent className="p-4">
                <div className="text-2xl font-display font-bold text-neon-green">
                  {MOCK_CREDENTIAL_STATS.successful_attempts.toLocaleString()}
                </div>
                <div className="text-xs text-text-secondary">Successful</div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-red/10 to-transparent">
              <CardContent className="p-4">
                <div className="text-2xl font-display font-bold text-neon-red">
                  {MOCK_CREDENTIAL_STATS.failed_attempts.toLocaleString()}
                </div>
                <div className="text-xs text-text-secondary">Failed</div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-blue/10 to-transparent">
              <CardContent className="p-4">
                <div className="text-2xl font-display font-bold text-neon-blue">
                  {MOCK_CREDENTIAL_STATS.unique_usernames}
                </div>
                <div className="text-xs text-text-secondary">Unique Users</div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-purple/10 to-transparent">
              <CardContent className="p-4">
                <div className="text-2xl font-display font-bold text-neon-purple">
                  {MOCK_CREDENTIAL_STATS.unique_passwords}
                </div>
                <div className="text-xs text-text-secondary">Unique Passwords</div>
              </CardContent>
            </Card>
          </div>

          {/* Top Usernames & Passwords */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Top 10 Usernames" subtitle="Most frequently targeted usernames" />
              <CardContent>
                <div className="space-y-3">
                  {MOCK_TOP_USERNAMES.map((item, index) => (
                    <div key={item.username} className="flex items-center gap-3">
                      <span className="w-6 h-6 flex items-center justify-center bg-neon-green/20 rounded-full text-neon-green text-xs font-bold">
                        {index + 1}
                      </span>
                      <code className="font-mono text-sm text-neon-green w-24 truncate">{item.username}</code>
                      <div className="flex-1 h-5 bg-bg-secondary rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-neon-green/50 rounded-full transition-all" 
                          style={{ width: `${(item.count / MOCK_TOP_USERNAMES[0].count) * 100}%` }} 
                        />
                      </div>
                      <span className="font-mono text-sm text-text-muted w-20 text-right">{item.count.toLocaleString()}</span>
                      <span className="text-xs text-text-secondary w-12 text-right">{item.percentage}%</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="Top 10 Passwords" subtitle="Most commonly used passwords" />
              <CardContent>
                <div className="space-y-3">
                  {MOCK_TOP_PASSWORDS.map((item, index) => (
                    <div key={item.password} className="flex items-center gap-3">
                      <span className="w-6 h-6 flex items-center justify-center bg-neon-orange/20 rounded-full text-neon-orange text-xs font-bold">
                        {index + 1}
                      </span>
                      <code className="font-mono text-sm text-neon-orange w-24 truncate">{item.password}</code>
                      <div className="flex-1 h-5 bg-bg-secondary rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-neon-orange/50 rounded-full transition-all" 
                          style={{ width: `${(item.count / MOCK_TOP_PASSWORDS[0].count) * 100}%` }} 
                        />
                      </div>
                      <span className="font-mono text-sm text-text-muted w-20 text-right">{item.count.toLocaleString()}</span>
                      <span className="text-xs text-text-secondary w-12 text-right">{item.percentage}%</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* All Credential Combinations Table */}
          <Card>
            <CardHeader 
              title="All Credential Combinations" 
              subtitle={`${MOCK_CREDENTIAL_STATS.unique_combinations} unique username/password pairs attempted`}
              icon={<Key className="w-5 h-5" />} 
            />
            <CardContent className="p-0">
              <div className="max-h-[500px] overflow-y-auto">
                <table className="w-full">
                  <thead className="sticky top-0 bg-bg-card border-b border-bg-hover z-10">
                    <tr>
                      <th className="text-left py-3 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">#</th>
                      <th className="text-left py-3 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Username</th>
                      <th className="text-left py-3 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Password</th>
                      <th className="text-center py-3 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Status</th>
                      <th className="text-right py-3 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Attempts</th>
                      <th className="text-right py-3 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Share</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-bg-hover">
                    {MOCK_CREDENTIALS.map((cred, index) => {
                      const sharePercent = ((cred.count / MOCK_CREDENTIAL_STATS.total_attempts) * 100).toFixed(1);
                      return (
                        <tr key={`${cred.username}-${cred.password}-${index}`} className="hover:bg-bg-hover/50 transition-colors">
                          <td className="py-3 px-4 text-text-muted text-sm font-mono">{index + 1}</td>
                          <td className="py-3 px-4">
                            <code className="font-mono text-sm text-neon-green bg-neon-green/10 px-2 py-1 rounded border border-neon-green/20">
                              {cred.username}
                            </code>
                          </td>
                          <td className="py-3 px-4">
                            <code className="font-mono text-sm text-neon-orange bg-neon-orange/10 px-2 py-1 rounded border border-neon-orange/20">
                              {cred.password}
                            </code>
                          </td>
                          <td className="py-3 px-4 text-center">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                              cred.success 
                                ? 'bg-neon-green/10 text-neon-green border border-neon-green/30' 
                                : 'bg-neon-red/10 text-neon-red border border-neon-red/30'
                            }`}>
                              {cred.success ? 'Success' : 'Failed'}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-right">
                            <span className="font-mono text-base font-bold text-neon-blue">{cred.count.toLocaleString()}</span>
                          </td>
                          <td className="py-3 px-4 text-right">
                            <span className="text-sm text-text-secondary">{sharePercent}%</span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>

          {/* Success Rate Analysis */}
          <Card>
            <CardHeader title="Authentication Success Analysis" subtitle="Breakdown of successful vs failed login attempts" />
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-text-secondary">Success Rate</span>
                    <span className="font-mono text-2xl font-bold text-neon-green">{MOCK_CREDENTIAL_STATS.success_rate}%</span>
                  </div>
                  <div className="h-4 bg-bg-secondary rounded-full overflow-hidden flex">
                    <div 
                      className="h-full bg-neon-green" 
                      style={{ width: `${MOCK_CREDENTIAL_STATS.success_rate}%` }}
                    />
                    <div 
                      className="h-full bg-neon-red" 
                      style={{ width: `${100 - MOCK_CREDENTIAL_STATS.success_rate}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-neon-green">{MOCK_CREDENTIAL_STATS.successful_attempts.toLocaleString()} successful</span>
                    <span className="text-neon-red">{MOCK_CREDENTIAL_STATS.failed_attempts.toLocaleString()} failed</span>
                  </div>
                </div>
                <div className="space-y-3">
                  <div className="p-3 bg-bg-secondary rounded-lg">
                    <div className="text-sm text-text-secondary mb-1">Avg attempts per session</div>
                    <div className="font-mono text-xl font-bold text-white">
                      {(MOCK_CREDENTIAL_STATS.total_attempts / MOCK_STATS.total_sessions).toFixed(1)}
                    </div>
                  </div>
                  <div className="p-3 bg-bg-secondary rounded-lg">
                    <div className="text-sm text-text-secondary mb-1">Most targeted username</div>
                    <div className="font-mono text-xl font-bold text-neon-green">root</div>
                    <div className="text-xs text-text-muted">62.2% of all attempts</div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'map',
      label: 'Attack Map',
      icon: <Map className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <HoneypotMap
            data={MOCK_GEO_DATA.map(g => ({ country: g.country, count: g.count }))}
            title="Cowrie SSH Attack Origins"
            height="450px"
            accentColor="#39ff14"
          />
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Top Countries Distribution" subtitle="Attack share by country" />
              <CardContent>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie 
                        data={MOCK_GEO_DATA.slice(0, 6)} 
                        dataKey="count" 
                        nameKey="country" 
                        cx="50%" 
                        cy="50%" 
                        outerRadius={80} 
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      >
                        {MOCK_GEO_DATA.slice(0, 6).map((_, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="Attack Countries" subtitle={`${MOCK_GEO_DATA.length} countries detected`} />
              <CardContent>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {MOCK_GEO_DATA.map((item, index) => (
                    <div key={item.country} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg hover:bg-bg-hover transition-colors">
                      <div className="flex items-center gap-3">
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                        <span className="text-text-primary font-medium">{item.country}</span>
                      </div>
                      <span className="font-mono text-neon-green">{item.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h2 className="text-xl font-display font-semibold text-neon-green">Cowrie SSH Honeypot</h2>
            <p className="text-sm text-text-secondary mt-1">SSH/Telnet honeypot with AI-enhanced interaction capabilities</p>
          </div>
        </div>
        <Tabs tabs={tabs} defaultTab="overview" />
      </div>

      {/* Session Replay Modal */}
      {selectedSessionId && (
        <MockSessionModal 
          sessionId={selectedSessionId} 
          onClose={() => setSelectedSessionId(null)} 
        />
      )}
    </>
  );
}

