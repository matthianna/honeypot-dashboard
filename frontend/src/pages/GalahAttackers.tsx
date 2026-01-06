import { useCallback, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Users,
  Globe,
  Clock,
  ChevronRight,
  Play,
  Eye,
  Search,
  ArrowLeft,
  Terminal,
  Bot,
  X,
} from 'lucide-react';
import TimeRangeSelector from '../components/TimeRangeSelector';
import LoadingSpinner from '../components/LoadingSpinner';
import IPLink from '../components/IPLink';
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';

interface Attacker {
  ip: string;
  total_requests: number;
  sessions: number;
  unique_paths: number;
  first_seen: string;
  last_seen: string;
  methods: string[];
  country: string | null;
  city: string | null;
}

interface Session {
  session_id: string;
  request_count: number;
  first_request: string;
  last_request: string;
  duration_seconds: number | null;
  paths: string[];
  methods: string[];
  user_agent: string | null;
}

interface SessionEvent {
  sequence: number;
  timestamp: string;
  method: string | null;
  path: string | null;
  query: string | null;
  request_body: string | null;
  response_status: number | null;
  response_body: string | null;
  response_mime: string | null;
  ai_generated: boolean;
  ai_model: string | null;
}

const METHOD_COLORS: Record<string, string> = {
  GET: 'bg-neon-green/20 text-neon-green',
  POST: 'bg-neon-blue/20 text-neon-blue',
  PUT: 'bg-neon-orange/20 text-neon-orange',
  DELETE: 'bg-neon-red/20 text-neon-red',
  HEAD: 'bg-purple-500/20 text-purple-400',
  OPTIONS: 'bg-gray-500/20 text-gray-400',
};

export default function GalahAttackers() {
  const navigate = useNavigate();
  const { timeRange, setTimeRange } = useTimeRange('24h');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedAttacker, setSelectedAttacker] = useState<string | null>(null);
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [sessionReplay, setSessionReplay] = useState<{
    session_id: string;
    info: { source_ip: string | null; country: string | null; city: string | null; user_agent: string | null };
    events: SessionEvent[];
    total_events: number;
    duration_seconds: number | null;
  } | null>(null);
  const [replayLoading, setReplayLoading] = useState(false);

  const { data: attackersData, loading: attackersLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahAttackers(timeRange, 200), [timeRange]),
    [timeRange]
  );

  // Filter attackers by search term
  const filteredAttackers = (attackersData?.attackers || []).filter((a: Attacker) =>
    a.ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (a.country?.toLowerCase() || '').includes(searchTerm.toLowerCase()) ||
    (a.city?.toLowerCase() || '').includes(searchTerm.toLowerCase())
  );

  const handleSelectAttacker = async (ip: string) => {
    setSelectedAttacker(ip);
    setSelectedSession(null);
    setSessionReplay(null);
    setSessionsLoading(true);
    
    try {
      const data = await api.getGalahAttackerSessions(ip, timeRange);
      setSessions(data.sessions);
    } catch (e) {
      console.error('Error fetching sessions:', e);
      setSessions([]);
    } finally {
      setSessionsLoading(false);
    }
  };

  const handleSelectSession = async (sessionId: string) => {
    setSelectedSession(sessionId);
    setReplayLoading(true);
    
    try {
      const data = await api.getGalahSessionReplay(sessionId);
      setSessionReplay(data);
    } catch (e) {
      console.error('Error fetching session replay:', e);
      setSessionReplay(null);
    } finally {
      setReplayLoading(false);
    }
  };

  const formatDuration = (seconds: number | null) => {
    if (!seconds) return '-';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  };

  const formatTime = (ts: string) => {
    try {
      return new Date(ts).toLocaleString();
    } catch {
      return ts;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate('/galah')}
            className="p-2 rounded-lg bg-bg-card border border-bg-hover hover:border-neon-orange transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h1 className="text-2xl font-display font-bold text-text-primary flex items-center gap-2">
              <Users className="w-6 h-6 text-neon-orange" />
              Galah Attackers
            </h1>
            <p className="text-text-secondary text-sm mt-1">
              Browse all IPs that attacked the Galah honeypot and replay their sessions
            </p>
          </div>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>

      <div className="grid grid-cols-12 gap-6 h-[calc(100vh-200px)]">
        {/* Attackers List */}
        <div className="col-span-3 bg-bg-card rounded-xl border border-bg-hover flex flex-col overflow-hidden">
          <div className="p-4 border-b border-bg-hover">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search IP, country..."
                className="w-full pl-10 pr-4 py-2 bg-bg-secondary border border-bg-hover rounded-lg text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-neon-orange"
              />
            </div>
            <div className="text-xs text-text-muted mt-2">
              {attackersData?.total || 0} unique attackers
            </div>
          </div>

          <div className="flex-1 overflow-y-auto">
            {attackersLoading ? (
              <div className="flex items-center justify-center py-8">
                <LoadingSpinner />
              </div>
            ) : filteredAttackers.length === 0 ? (
              <div className="text-center py-8 text-text-muted text-sm">
                No attackers found
              </div>
            ) : (
              filteredAttackers.map((attacker: Attacker) => (
                <button
                  key={attacker.ip}
                  onClick={() => handleSelectAttacker(attacker.ip)}
                  className={`w-full p-3 border-b border-bg-hover text-left transition-colors hover:bg-bg-hover ${
                    selectedAttacker === attacker.ip ? 'bg-neon-orange/10 border-l-2 border-l-neon-orange' : ''
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-sm text-text-primary">{attacker.ip}</span>
                    <ChevronRight className="w-4 h-4 text-text-muted" />
                  </div>
                  <div className="flex items-center gap-2 mt-1 text-xs text-text-muted">
                    <span>{attacker.total_requests} req</span>
                    <span>•</span>
                    <span>{attacker.sessions} sessions</span>
                  </div>
                  {attacker.country && (
                    <div className="flex items-center gap-1 mt-1 text-xs text-text-secondary">
                      <Globe className="w-3 h-3" />
                      <span>{attacker.city ? `${attacker.city}, ` : ''}{attacker.country}</span>
                    </div>
                  )}
                </button>
              ))
            )}
          </div>
        </div>

        {/* Sessions List */}
        <div className="col-span-3 bg-bg-card rounded-xl border border-bg-hover flex flex-col overflow-hidden">
          <div className="p-4 border-b border-bg-hover">
            <h3 className="font-medium text-text-primary">
              {selectedAttacker ? (
                <>Sessions for <span className="font-mono text-neon-orange">{selectedAttacker}</span></>
              ) : (
                'Select an attacker'
              )}
            </h3>
            <div className="text-xs text-text-muted mt-1">
              {sessions.length} sessions found
            </div>
          </div>

          <div className="flex-1 overflow-y-auto">
            {!selectedAttacker ? (
              <div className="flex flex-col items-center justify-center py-12 text-text-muted">
                <Users className="w-8 h-8 mb-2 opacity-50" />
                <span className="text-sm">Select an attacker to view sessions</span>
              </div>
            ) : sessionsLoading ? (
              <div className="flex items-center justify-center py-8">
                <LoadingSpinner />
              </div>
            ) : sessions.length === 0 ? (
              <div className="text-center py-8 text-text-muted text-sm">
                No sessions found
              </div>
            ) : (
              sessions.map((session) => (
                <button
                  key={session.session_id}
                  onClick={() => handleSelectSession(session.session_id)}
                  className={`w-full p-3 border-b border-bg-hover text-left transition-colors hover:bg-bg-hover ${
                    selectedSession === session.session_id ? 'bg-neon-blue/10 border-l-2 border-l-neon-blue' : ''
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-text-primary">
                        {session.request_count} requests
                      </span>
                      {session.methods.map((m) => (
                        <span
                          key={m}
                          className={`px-1.5 py-0.5 rounded text-xs font-mono ${METHOD_COLORS[m] || 'bg-gray-500/20 text-gray-400'}`}
                        >
                          {m}
                        </span>
                      ))}
                    </div>
                    <Play className="w-4 h-4 text-neon-blue" />
                  </div>
                  <div className="flex items-center gap-2 text-xs text-text-muted">
                    <Clock className="w-3 h-3" />
                    <span>{formatDuration(session.duration_seconds)}</span>
                    <span className="truncate max-w-[120px]">{session.paths[0]}</span>
                  </div>
                  <div className="text-xs text-text-muted mt-1">
                    {formatTime(session.first_request)}
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Session Replay */}
        <div className="col-span-6 bg-bg-card rounded-xl border border-bg-hover flex flex-col overflow-hidden">
          <div className="p-4 border-b border-bg-hover flex items-center justify-between">
            <div>
              <h3 className="font-medium text-text-primary flex items-center gap-2">
                <Terminal className="w-4 h-4 text-neon-green" />
                Session Replay
              </h3>
              {sessionReplay && (
                <div className="text-xs text-text-muted mt-1">
                  {sessionReplay.total_events} events • {formatDuration(sessionReplay.duration_seconds)}
                </div>
              )}
            </div>
            {sessionReplay && (
              <button
                onClick={() => {
                  setSelectedSession(null);
                  setSessionReplay(null);
                }}
                className="p-1 rounded hover:bg-bg-hover"
              >
                <X className="w-4 h-4 text-text-muted" />
              </button>
            )}
          </div>

          <div className="flex-1 overflow-y-auto p-4">
            {!selectedSession ? (
              <div className="flex flex-col items-center justify-center h-full text-text-muted">
                <Eye className="w-12 h-12 mb-4 opacity-30" />
                <span className="text-lg mb-2">Select a session to replay</span>
                <span className="text-sm opacity-70">View the complete HTTP conversation</span>
              </div>
            ) : replayLoading ? (
              <div className="flex items-center justify-center h-full">
                <LoadingSpinner size="lg" />
              </div>
            ) : !sessionReplay ? (
              <div className="text-center text-text-muted py-8">
                Failed to load session
              </div>
            ) : (
              <div className="space-y-4">
                {/* Session Info */}
                {sessionReplay.info.source_ip && (
                  <div className="bg-bg-secondary rounded-lg p-3 text-sm">
                    <div className="flex items-center gap-4">
                      <div>
                        <span className="text-text-muted">IP: </span>
                        <IPLink ip={sessionReplay.info.source_ip} />
                      </div>
                      {sessionReplay.info.country && (
                        <div className="flex items-center gap-1">
                          <Globe className="w-3 h-3 text-text-muted" />
                          <span>{sessionReplay.info.city ? `${sessionReplay.info.city}, ` : ''}{sessionReplay.info.country}</span>
                        </div>
                      )}
                    </div>
                    {sessionReplay.info.user_agent && (
                      <div className="text-xs text-text-muted mt-2 truncate">
                        {sessionReplay.info.user_agent}
                      </div>
                    )}
                  </div>
                )}

                {/* Events */}
                {sessionReplay.events.map((event, index) => (
                  <div key={index} className="border border-bg-hover rounded-lg overflow-hidden">
                    {/* Request */}
                    <div className="bg-bg-secondary p-3 border-b border-bg-hover">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-xs bg-neon-green/20 text-neon-green px-2 py-0.5 rounded font-mono">
                          #{event.sequence}
                        </span>
                        <span className={`px-2 py-0.5 rounded text-xs font-mono ${METHOD_COLORS[event.method || 'GET'] || 'bg-gray-500/20 text-gray-400'}`}>
                          {event.method}
                        </span>
                        <span className="font-mono text-sm text-neon-blue truncate">
                          {event.path}{event.query ? `?${event.query}` : ''}
                        </span>
                        <span className="ml-auto text-xs text-text-muted">
                          {formatTime(event.timestamp)}
                        </span>
                      </div>
                      {event.request_body && (
                        <pre className="text-xs text-text-secondary bg-black/30 p-2 rounded mt-2 overflow-x-auto max-h-32 overflow-y-auto">
                          {event.request_body}
                        </pre>
                      )}
                    </div>

                    {/* Response */}
                    <div className="p-3">
                      <div className="flex items-center gap-2 mb-2">
                        <span className={`text-xs px-2 py-0.5 rounded font-mono ${
                          (event.response_status || 0) < 300 ? 'bg-neon-green/20 text-neon-green' :
                          (event.response_status || 0) < 400 ? 'bg-neon-blue/20 text-neon-blue' :
                          (event.response_status || 0) < 500 ? 'bg-neon-orange/20 text-neon-orange' :
                          'bg-neon-red/20 text-neon-red'
                        }`}>
                          {event.response_status || 'N/A'}
                        </span>
                        {event.response_mime && (
                          <span className="text-xs text-text-muted">{event.response_mime}</span>
                        )}
                        {event.ai_generated && (
                          <span className="flex items-center gap-1 text-xs bg-neon-purple/20 text-neon-purple px-2 py-0.5 rounded">
                            <Bot className="w-3 h-3" />
                            AI Generated
                            {event.ai_model && <span className="opacity-70">({event.ai_model})</span>}
                          </span>
                        )}
                      </div>
                      {event.response_body && (
                        <pre className="text-xs text-text-secondary bg-black/30 p-2 rounded overflow-x-auto max-h-48 overflow-y-auto whitespace-pre-wrap">
                          {event.response_body.length > 2000 
                            ? event.response_body.slice(0, 2000) + '\n... (truncated)'
                            : event.response_body}
                        </pre>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

