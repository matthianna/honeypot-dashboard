import { useState, useEffect } from 'react';
import { X, Terminal, Key, Clock, Globe, Server, ChevronDown, CheckCircle, XCircle, Play } from 'lucide-react';
import api from '../services/api';
import LoadingSpinner from './LoadingSpinner';
import SessionReplay from './SessionReplay';

interface SessionDetails {
  session_id: string;
  info: {
    src_ip?: string;
    country?: string;
    city?: string;
    sensor?: string;
    protocol?: string;
    start_time?: string;
    end_time?: string;
    duration?: number;
    client_version?: string;
  };
  commands: Array<{ command: string; timestamp: string }>;
  credentials: Array<{ username: string; password: string; success: boolean; timestamp: string }>;
  events: Array<{ type: string; timestamp: string; details: Record<string, unknown> }>;
  total_events: number;
}

interface CowrieSessionModalProps {
  sessionId: string;
  onClose: () => void;
}

export default function CowrieSessionModal({ sessionId, onClose }: CowrieSessionModalProps) {
  const [details, setDetails] = useState<SessionDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedEvents, setExpandedEvents] = useState(false);
  const [activeTab, setActiveTab] = useState<'replay' | 'commands' | 'credentials' | 'events'>('replay');

  useEffect(() => {
    const fetchDetails = async () => {
      try {
        setLoading(true);
        const data = await api.getCowrieSessionDetails(sessionId);
        setDetails(data);
      } catch (err) {
        setError('Failed to load session details');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    fetchDetails();
  }, [sessionId]);

  const formatTime = (ts?: string) => {
    if (!ts) return 'N/A';
    try {
      return new Date(ts).toLocaleString();
    } catch {
      return ts;
    }
  };

  const formatDuration = (seconds?: number) => {
    if (!seconds) return 'N/A';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  };

  const sensorColor = (sensor?: string) => {
    if (sensor === 'cowrie_plain') return 'text-neon-green';
    if (sensor === 'cowrie_llm') return 'text-neon-blue';
    if (sensor === 'cowrie_openai') return 'text-neon-orange';
    return 'text-text-secondary';
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/80 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative bg-bg-secondary rounded-xl border border-bg-hover shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-bg-hover bg-bg-card/50">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-lg bg-neon-green/20 flex items-center justify-center">
              <Terminal className="w-5 h-5 text-neon-green" />
            </div>
            <div>
              <h2 className="text-lg font-display font-bold text-text-primary">
                Session Details
              </h2>
              <p className="text-sm font-mono text-text-secondary">{sessionId}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-text-secondary hover:text-text-primary transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        {loading ? (
          <div className="flex items-center justify-center py-16">
            <LoadingSpinner size="lg" />
          </div>
        ) : error ? (
          <div className="flex items-center justify-center py-16 text-neon-red">
            {error}
          </div>
        ) : details ? (
          <div className="flex-1 overflow-hidden flex flex-col">
            {/* Session Info */}
            <div className="p-4 border-b border-bg-hover">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4 text-neon-blue" />
                  <div>
                    <div className="text-xs text-text-secondary">Source IP</div>
                    <div className="font-mono text-sm text-neon-blue">{details.info.src_ip || 'Unknown'}</div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Server className="w-4 h-4 text-neon-orange" />
                  <div>
                    <div className="text-xs text-text-secondary">Variant</div>
                    <div className={`font-mono text-sm ${sensorColor(details.info.sensor)}`}>
                      {details.info.sensor?.replace('cowrie_', '') || 'Unknown'}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Clock className="w-4 h-4 text-neon-green" />
                  <div>
                    <div className="text-xs text-text-secondary">Duration</div>
                    <div className="font-mono text-sm text-text-primary">{formatDuration(details.info.duration)}</div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4 text-text-secondary" />
                  <div>
                    <div className="text-xs text-text-secondary">Location</div>
                    <div className="text-sm text-text-primary">
                      {details.info.city && details.info.country 
                        ? `${details.info.city}, ${details.info.country}` 
                        : details.info.country || 'Unknown'}
                    </div>
                  </div>
                </div>
              </div>
              <div className="mt-3 text-xs text-text-muted">
                {formatTime(details.info.start_time)} — {formatTime(details.info.end_time)}
              </div>
            </div>

            {/* Tabs */}
            <div className="flex border-b border-bg-hover">
              {[
                { id: 'replay', label: 'Session Replay', icon: Play },
                { id: 'commands', label: `Commands (${details.commands.length})`, icon: Terminal },
                { id: 'credentials', label: `Credentials (${details.credentials.length})`, icon: Key },
                { id: 'events', label: `Events (${details.total_events})`, icon: Clock },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as typeof activeTab)}
                  className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                    activeTab === tab.id
                      ? 'border-neon-green text-neon-green'
                      : 'border-transparent text-text-secondary hover:text-text-primary'
                  }`}
                >
                  <tab.icon className="w-4 h-4" />
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="flex-1 overflow-y-auto p-4">
              {/* Replay Tab */}
              {activeTab === 'replay' && (
                <SessionReplay 
                  commands={details.commands} 
                  autoPlay={false}
                  speed={2}
                />
              )}

              {/* Commands Tab */}
              {activeTab === 'commands' && (
                <div className="space-y-2">
                  {details.commands.length === 0 ? (
                    <div className="text-center py-8 text-text-secondary">No commands executed</div>
                  ) : (
                    details.commands.map((cmd, i) => (
                      <div
                        key={i}
                        className="flex items-start gap-3 p-3 bg-bg-card rounded-lg border border-bg-hover hover:border-neon-green/30 transition-colors"
                      >
                        <div className="text-xs text-text-muted font-mono w-12 pt-0.5">{i + 1}.</div>
                        <div className="flex-1 min-w-0">
                          <pre className="font-mono text-sm text-neon-green whitespace-pre-wrap break-all">
                            {cmd.command}
                          </pre>
                          <div className="text-xs text-text-muted mt-1">
                            {formatTime(cmd.timestamp)}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Credentials Tab */}
              {activeTab === 'credentials' && (
                <div className="space-y-2">
                  {details.credentials.length === 0 ? (
                    <div className="text-center py-8 text-text-secondary">No login attempts</div>
                  ) : (
                    details.credentials.map((cred, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between p-3 bg-bg-card rounded-lg border border-bg-hover"
                      >
                        <div className="flex items-center gap-4">
                          {cred.success ? (
                            <CheckCircle className="w-5 h-5 text-neon-green" />
                          ) : (
                            <XCircle className="w-5 h-5 text-neon-red" />
                          )}
                          <div>
                            <span className="font-mono text-neon-blue">{cred.username}</span>
                            <span className="text-text-muted mx-2">:</span>
                            <span className="font-mono text-neon-orange">{cred.password}</span>
                          </div>
                        </div>
                        <div className="text-xs text-text-muted">{formatTime(cred.timestamp)}</div>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Events Tab */}
              {activeTab === 'events' && (
                <div className="space-y-1">
                  {details.events.slice(0, expandedEvents ? undefined : 20).map((event, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-3 p-2 text-sm hover:bg-bg-card rounded transition-colors"
                    >
                      <div className="text-xs text-text-muted w-36">{formatTime(event.timestamp)}</div>
                      <div className="font-mono text-xs text-neon-blue flex-shrink-0">
                        {event.type.replace('cowrie.', '')}
                      </div>
                      {Object.keys(event.details).length > 0 && (
                        <div className="text-xs text-text-secondary truncate">
                          {JSON.stringify(event.details)}
                        </div>
                      )}
                    </div>
                  ))}
                  {details.events.length > 20 && !expandedEvents && (
                    <button
                      onClick={() => setExpandedEvents(true)}
                      className="flex items-center gap-1 text-sm text-neon-green hover:underline mt-2"
                    >
                      <ChevronDown className="w-4 h-4" />
                      Show all {details.events.length} events
                    </button>
                  )}
                </div>
              )}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

