import { useEffect, useState } from 'react';
import { X, Globe, Clock, Terminal, Key, Eye, Activity, List, FileJson, FileSpreadsheet } from 'lucide-react';
import api from '../services/api';
import type { AttackerProfile } from '../types';
import LoadingSpinner from './LoadingSpinner';
import RawLogModal from './RawLogModal';
import { HONEYPOT_COLORS, HONEYPOT_NAMES, HoneypotType } from '../types';

interface TimelineEvent {
  timestamp: string;
  honeypot: string;
  event_type: string;
  detail: string;
}

interface AttackerModalProps {
  ip: string;
  onClose: () => void;
}

export default function AttackerModal({ ip, onClose }: AttackerModalProps) {
  const [profile, setProfile] = useState<AttackerProfile | null>(null);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [timelineLoading, setTimelineLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'timeline' | 'credentials' | 'commands' | 'raw'>('overview');
  const [selectedRaw, setSelectedRaw] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        setLoading(true);
        const data = await api.getAttackerProfile(ip);
        setProfile(data);
      } catch (err) {
        setError('Failed to load attacker profile');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    fetchProfile();
  }, [ip]);

  useEffect(() => {
    const fetchTimeline = async () => {
      if (activeTab !== 'timeline' || timeline.length > 0) return;
      
      try {
        setTimelineLoading(true);
        const data = await api.getAttackerTimeline(ip);
        setTimeline((data.timeline as TimelineEvent[]) || []);
      } catch (err) {
        console.error('Failed to load timeline:', err);
      } finally {
        setTimelineLoading(false);
      }
    };

    fetchTimeline();
  }, [activeTab, ip, timeline.length]);

  const handleExport = async (format: 'json' | 'csv') => {
    try {
      const data = await api.exportAttackerData(ip, format);
      
      if (format === 'json') {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `attacker_${ip.replace(/\./g, '_')}.json`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        const csvData = data as { content: string; filename: string };
        const blob = new Blob([csvData.content], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = csvData.filename;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch (err) {
      console.error('Export failed:', err);
    }
  };

  const formatDate = (dateStr: string) => {
    try {
      return new Date(dateStr).toLocaleString();
    } catch {
      return dateStr;
    }
  };

  const formatTime = (dateStr: string) => {
    try {
      return new Date(dateStr).toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit',
        second: '2-digit',
        hour12: false 
      });
    } catch {
      return dateStr;
    }
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: <Activity className="w-4 h-4" /> },
    { id: 'timeline', label: 'Timeline', icon: <Clock className="w-4 h-4" /> },
    { id: 'credentials', label: 'Credentials', icon: <Key className="w-4 h-4" /> },
    { id: 'commands', label: 'Commands', icon: <Terminal className="w-4 h-4" /> },
    { id: 'raw', label: 'Raw Data', icon: <List className="w-4 h-4" /> },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative bg-bg-secondary rounded-xl border border-bg-hover shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-bg-hover bg-bg-card/50">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-lg bg-neon-red/20 flex items-center justify-center">
              <Globe className="w-5 h-5 text-neon-red" />
            </div>
            <div>
              <h2 className="text-lg font-display font-bold text-text-primary">
                Attacker Profile
              </h2>
              <p className="text-sm font-mono text-neon-blue">{ip}</p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => handleExport('json')}
              className="p-2 text-text-secondary hover:text-neon-green transition-colors"
              title="Export JSON"
            >
              <FileJson className="w-5 h-5" />
            </button>
            <button
              onClick={() => handleExport('csv')}
              className="p-2 text-text-secondary hover:text-neon-blue transition-colors"
              title="Export CSV"
            >
              <FileSpreadsheet className="w-5 h-5" />
            </button>
            <button
              onClick={onClose}
              className="p-2 text-text-secondary hover:text-text-primary transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="overflow-y-auto" style={{ maxHeight: 'calc(90vh - 80px)' }}>
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <LoadingSpinner size="lg" />
            </div>
          ) : error ? (
            <div className="flex items-center justify-center py-12 text-neon-red">
              {error}
            </div>
          ) : profile ? (
            <>
              {/* Tabs */}
              <div className="flex border-b border-bg-hover px-4 overflow-x-auto">
                {tabs.map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as typeof activeTab)}
                    className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors flex items-center space-x-2 whitespace-nowrap ${
                      activeTab === tab.id
                        ? 'border-neon-green text-neon-green'
                        : 'border-transparent text-text-secondary hover:text-text-primary'
                    }`}
                  >
                    {tab.icon}
                    <span>{tab.label}</span>
                  </button>
                ))}
              </div>

              <div className="p-4">
                {/* Overview Tab */}
                {activeTab === 'overview' && (
                  <div className="space-y-6">
                    {/* Behavior Classification Banner */}
                    {profile.behavior_classification && (
                      <div className={`flex items-center justify-between p-4 rounded-lg ${
                        profile.behavior_classification === 'Script' ? 'bg-neon-red/10 border border-neon-red/30' :
                        profile.behavior_classification === 'Human' ? 'bg-neon-green/10 border border-neon-green/30' :
                        'bg-neon-orange/10 border border-neon-orange/30'
                      }`}>
                        <div className="flex items-center gap-3">
                          <span className="text-2xl">
                            {profile.behavior_classification === 'Script' ? '⚡' :
                             profile.behavior_classification === 'Human' ? '👤' : '🤖'}
                          </span>
                          <div>
                            <div className={`font-display font-bold ${
                              profile.behavior_classification === 'Script' ? 'text-neon-red' :
                              profile.behavior_classification === 'Human' ? 'text-neon-green' :
                              'text-neon-orange'
                            }`}>
                              {profile.behavior_classification} Attack Pattern
                            </div>
                            <div className="text-xs text-text-secondary">
                              {profile.behavior_classification === 'Script' 
                                ? 'Fast automated attacks (<5s avg session)'
                                : profile.behavior_classification === 'Human'
                                ? 'Interactive exploration (>60s avg session)'
                                : 'Automated with some interaction (5-60s avg)'}
                            </div>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="text-lg font-mono text-text-primary">
                            {profile.avg_session_duration ? `${profile.avg_session_duration.toFixed(1)}s` : 'N/A'}
                          </div>
                          <div className="text-xs text-text-secondary">avg session</div>
                        </div>
                      </div>
                    )}

                    {/* Stats Grid */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="bg-bg-card rounded-lg p-3">
                        <div className="text-xs text-text-secondary mb-1">Total Events</div>
                        <div className="text-xl font-display font-bold text-neon-green">
                          {profile.total_events.toLocaleString()}
                        </div>
                      </div>
                      <div className="bg-bg-card rounded-lg p-3">
                        <div className="text-xs text-text-secondary mb-1">Sessions</div>
                        <div className="text-xl font-display font-bold text-neon-blue">
                          {profile.session_count || 0}
                        </div>
                      </div>
                      <div className="bg-bg-card rounded-lg p-3">
                        <div className="text-xs text-text-secondary mb-1">Total Duration</div>
                        <div className="text-xl font-display font-bold text-neon-orange">
                          {profile.total_duration_seconds 
                            ? profile.total_duration_seconds < 60 
                              ? `${Math.round(profile.total_duration_seconds)}s`
                              : profile.total_duration_seconds < 3600
                              ? `${Math.round(profile.total_duration_seconds / 60)}m`
                              : `${(profile.total_duration_seconds / 3600).toFixed(1)}h`
                            : 'N/A'}
                        </div>
                      </div>
                      <div className="bg-bg-card rounded-lg p-3">
                        <div className="text-xs text-text-secondary mb-1">Countries</div>
                        <div className="text-xl font-display font-bold text-neon-purple">
                          {profile.countries.length}
                        </div>
                      </div>
                    </div>

                    {/* Time Range */}
                    <div className="grid grid-cols-2 gap-4">
                      <div className="bg-bg-card rounded-lg p-3">
                        <div className="text-xs text-text-secondary mb-1">First Seen</div>
                        <div className="text-sm text-text-primary">
                          {formatDate(profile.first_seen)}
                        </div>
                      </div>
                      <div className="bg-bg-card rounded-lg p-3">
                        <div className="text-xs text-text-secondary mb-1">Last Seen</div>
                        <div className="text-sm text-text-primary">
                          {formatDate(profile.last_seen)}
                        </div>
                      </div>
                    </div>

                    {/* Countries */}
                    {profile.countries.length > 0 && (
                      <div>
                        <h3 className="text-sm font-semibold text-text-secondary mb-2 flex items-center">
                          <Globe className="w-4 h-4 mr-2" />
                          Countries
                        </h3>
                        <div className="flex flex-wrap gap-2">
                          {profile.countries.map((country) => (
                            <span
                              key={country}
                              className="px-2 py-1 text-xs bg-bg-card rounded-md text-text-primary"
                            >
                              {country}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Honeypot Activity */}
                    <div>
                      <h3 className="text-sm font-semibold text-text-secondary mb-3 flex items-center">
                        <Activity className="w-4 h-4 mr-2" />
                        Activity by Honeypot
                      </h3>
                      <div className="space-y-2">
                        {profile.honeypot_activity.map((activity) => {
                          const color = HONEYPOT_COLORS[activity.honeypot as HoneypotType] || '#ffffff';
                          const name = HONEYPOT_NAMES[activity.honeypot as HoneypotType] || activity.honeypot;
                          
                          return (
                            <div
                              key={activity.honeypot}
                              className="flex items-center justify-between bg-bg-card rounded-lg p-3"
                            >
                              <div className="flex items-center space-x-3">
                                <div
                                  className="w-3 h-3 rounded-full"
                                  style={{ backgroundColor: color }}
                                />
                                <div>
                                  <span className="text-text-primary">{name}</span>
                                  {activity.session_count && activity.duration_seconds && (
                                    <div className="text-xs text-text-secondary">
                                      {activity.session_count} sessions · {
                                        activity.duration_seconds < 60 
                                          ? `${Math.round(activity.duration_seconds)}s`
                                          : activity.duration_seconds < 3600
                                          ? `${Math.round(activity.duration_seconds / 60)}m`
                                          : `${(activity.duration_seconds / 3600).toFixed(1)}h`
                                      } total
                                    </div>
                                  )}
                                </div>
                              </div>
                              <div className="text-right">
                                <div className="font-mono" style={{ color }}>
                                  {activity.event_count.toLocaleString()}
                                </div>
                                <div className="text-xs text-text-secondary">
                                  {formatDate(activity.last_seen)}
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                )}

                {/* Timeline Tab */}
                {activeTab === 'timeline' && (
                  <div>
                    <h3 className="text-sm font-semibold text-text-secondary mb-3 flex items-center">
                      <Clock className="w-4 h-4 mr-2" />
                      Activity Timeline
                    </h3>
                    {timelineLoading ? (
                      <div className="flex items-center justify-center py-8">
                        <LoadingSpinner />
                      </div>
                    ) : timeline.length > 0 ? (
                      <div className="relative">
                        {/* Timeline line */}
                        <div className="absolute left-3 top-0 bottom-0 w-0.5 bg-bg-hover" />
                        
                        <div className="space-y-3 max-h-96 overflow-y-auto pr-2">
                          {timeline.map((event, idx) => {
                            const color = HONEYPOT_COLORS[event.honeypot as HoneypotType] || '#ffffff';
                            const name = HONEYPOT_NAMES[event.honeypot as HoneypotType] || event.honeypot;
                            
                            return (
                              <div key={idx} className="relative pl-8">
                                {/* Dot */}
                                <div 
                                  className="absolute left-1.5 top-2 w-3 h-3 rounded-full border-2 border-bg-secondary"
                                  style={{ backgroundColor: color }}
                                />
                                
                                <div className="bg-bg-card rounded-lg p-3">
                                  <div className="flex items-center justify-between mb-1">
                                    <span className="text-xs font-mono text-text-secondary">
                                      {formatTime(event.timestamp)}
                                    </span>
                                    <span 
                                      className="text-xs px-2 py-0.5 rounded-full"
                                      style={{ backgroundColor: `${color}20`, color }}
                                    >
                                      {name}
                                    </span>
                                  </div>
                                  <div className="text-sm text-text-primary">
                                    <span className="text-text-secondary">{event.event_type}:</span>{' '}
                                    <span className="font-mono text-neon-green">{event.detail}</span>
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ) : (
                      <p className="text-text-secondary text-sm py-4 text-center">
                        No timeline events available
                      </p>
                    )}
                  </div>
                )}

                {/* Credentials Tab */}
                {activeTab === 'credentials' && (
                  <div>
                    <h3 className="text-sm font-semibold text-text-secondary mb-3 flex items-center">
                      <Key className="w-4 h-4 mr-2" />
                      Credentials Attempted ({profile.credentials_tried?.length || 0})
                    </h3>
                    {profile.credentials_tried && profile.credentials_tried.length > 0 ? (
                      <div className="space-y-2 max-h-96 overflow-y-auto">
                        {profile.credentials_tried.map((cred, idx) => (
                          <div
                            key={idx}
                            className="flex items-center justify-between bg-bg-card rounded-lg p-3"
                          >
                            <div className="font-mono text-sm">
                              <span className="text-neon-blue">{cred.username || '(empty)'}</span>
                              <span className="text-text-secondary mx-2">:</span>
                              <span className="text-neon-orange">{cred.password || '(empty)'}</span>
                            </div>
                            <span className="text-text-secondary text-sm font-mono">
                              ×{cred.count}
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-text-secondary text-sm py-4 text-center">
                        No credentials recorded
                      </p>
                    )}
                  </div>
                )}

                {/* Commands Tab */}
                {activeTab === 'commands' && (
                  <div>
                    <h3 className="text-sm font-semibold text-text-secondary mb-3 flex items-center">
                      <Terminal className="w-4 h-4 mr-2" />
                      Commands Executed ({profile.commands_executed?.length || 0})
                    </h3>
                    {profile.commands_executed && profile.commands_executed.length > 0 ? (
                      <div className="space-y-2 max-h-96 overflow-y-auto">
                        {profile.commands_executed.map((cmd, idx) => (
                          <div
                            key={idx}
                            className="bg-bg-card rounded-lg p-3 font-mono text-sm text-neon-green overflow-x-auto"
                          >
                            <span className="text-text-secondary select-none">$ </span>
                            {cmd}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-text-secondary text-sm py-4 text-center">
                        No commands recorded
                      </p>
                    )}
                  </div>
                )}

                {/* Raw Data Tab */}
                {activeTab === 'raw' && (
                  <div>
                    <h3 className="text-sm font-semibold text-text-secondary mb-3 flex items-center">
                      <List className="w-4 h-4 mr-2" />
                      Raw Profile Data
                    </h3>
                    <div className="bg-bg-card rounded-lg p-4">
                      <div className="flex justify-end mb-2">
                        <button
                          onClick={() => setSelectedRaw(profile as unknown as Record<string, unknown>)}
                          className="text-xs text-text-secondary hover:text-neon-blue transition-colors flex items-center space-x-1"
                        >
                          <Eye className="w-3 h-3" />
                          <span>Full view</span>
                        </button>
                      </div>
                      <pre className="text-xs font-mono text-text-primary overflow-x-auto whitespace-pre-wrap max-h-80">
                        {JSON.stringify(profile, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : null}
        </div>
      </div>

      {/* Raw Log Modal */}
      {selectedRaw && (
        <RawLogModal
          log={selectedRaw}
          title="Attacker Profile Data"
          onClose={() => setSelectedRaw(null)}
        />
      )}
    </div>
  );
}
