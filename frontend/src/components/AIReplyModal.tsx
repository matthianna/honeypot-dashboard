import { X, Copy, Check, Globe, Clock, Server, ArrowRight } from 'lucide-react';
import { useState } from 'react';

interface GalahInteraction {
  id: string;
  timestamp: string;
  source_ip: string;
  source_port: number;
  destination_port: number;
  method: string;
  path: string;
  message: string;
  session_id: string;
  geo: {
    country: string | null;
    city: string | null;
    location: { lat: number; lon: number } | null;
  };
  raw: {
    httpRequest?: {
      headers?: Record<string, string>;
      body?: string;
      protocolVersion?: string;
    };
    httpResponse?: {
      headers?: Record<string, string>;
      body?: string;
      statusCode?: number;
    };
    responseMetadata?: {
      generationSource?: string;
      info?: Record<string, unknown>;
    };
    user_agent?: {
      original?: string;
      name?: string;
      version?: string;
      os?: { name?: string; version?: string };
      device?: { name?: string };
    };
    [key: string]: unknown;
  };
}

interface AIReplyModalProps {
  interaction: GalahInteraction;
  onClose: () => void;
}

export default function AIReplyModal({ interaction, onClose }: AIReplyModalProps) {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'request' | 'response' | 'raw'>('overview');

  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const formatDate = (dateStr: string) => {
    try {
      return new Date(dateStr).toLocaleString();
    } catch {
      return dateStr;
    }
  };

  const request = interaction.raw.httpRequest;
  const response = interaction.raw.httpResponse;
  const metadata = interaction.raw.responseMetadata;
  const userAgent = interaction.raw.user_agent;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative bg-bg-secondary rounded-xl border border-bg-hover shadow-2xl w-full max-w-5xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-bg-hover">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-lg bg-neon-orange/20 flex items-center justify-center">
              <Server className="w-5 h-5 text-neon-orange" />
            </div>
            <div>
              <h2 className="text-lg font-display font-bold text-text-primary">
                HTTP Interaction
              </h2>
              <div className="flex items-center text-sm text-text-secondary space-x-2">
                <span className="font-mono text-neon-blue">{interaction.source_ip}</span>
                <ArrowRight className="w-4 h-4" />
                <span className="text-neon-orange">{interaction.method} {interaction.path}</span>
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 text-text-secondary hover:text-text-primary transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-bg-hover px-4 bg-bg-card/30">
          {[
            { id: 'overview', label: 'Overview' },
            { id: 'request', label: 'Request' },
            { id: 'response', label: 'Response' },
            { id: 'raw', label: 'Raw JSON' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-neon-orange text-neon-orange'
                  : 'border-transparent text-text-secondary hover:text-text-primary'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="overflow-y-auto" style={{ maxHeight: 'calc(90vh - 160px)' }}>
          <div className="p-4">
            {/* Overview Tab */}
            {activeTab === 'overview' && (
              <div className="space-y-6">
                {/* Info Grid */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-bg-card rounded-lg p-3">
                    <div className="text-xs text-text-secondary mb-1 flex items-center">
                      <Clock className="w-3 h-3 mr-1" />
                      Timestamp
                    </div>
                    <div className="text-sm text-text-primary">
                      {formatDate(interaction.timestamp)}
                    </div>
                  </div>
                  <div className="bg-bg-card rounded-lg p-3">
                    <div className="text-xs text-text-secondary mb-1 flex items-center">
                      <Globe className="w-3 h-3 mr-1" />
                      Location
                    </div>
                    <div className="text-sm text-text-primary">
                      {interaction.geo.country || 'Unknown'}
                      {interaction.geo.city && `, ${interaction.geo.city}`}
                    </div>
                  </div>
                  <div className="bg-bg-card rounded-lg p-3">
                    <div className="text-xs text-text-secondary mb-1">Message</div>
                    <div className="text-sm text-neon-green">
                      {interaction.message}
                    </div>
                  </div>
                  <div className="bg-bg-card rounded-lg p-3">
                    <div className="text-xs text-text-secondary mb-1">Generation</div>
                    <div className="text-sm text-neon-purple">
                      {metadata?.generationSource || 'N/A'}
                    </div>
                  </div>
                </div>

                {/* User Agent */}
                {userAgent && (
                  <div className="bg-bg-card rounded-lg p-4">
                    <h3 className="text-sm font-semibold text-text-secondary mb-2">
                      User Agent
                    </h3>
                    <div className="text-sm font-mono text-text-primary break-all">
                      {userAgent.original}
                    </div>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {userAgent.name && (
                        <span className="px-2 py-1 text-xs bg-neon-blue/20 text-neon-blue rounded">
                          {userAgent.name} {userAgent.version}
                        </span>
                      )}
                      {userAgent.os?.name && (
                        <span className="px-2 py-1 text-xs bg-neon-purple/20 text-neon-purple rounded">
                          {userAgent.os.name} {userAgent.os.version}
                        </span>
                      )}
                      {userAgent.device?.name && (
                        <span className="px-2 py-1 text-xs bg-neon-orange/20 text-neon-orange rounded">
                          {userAgent.device.name}
                        </span>
                      )}
                    </div>
                  </div>
                )}

                {/* Session ID */}
                <div className="bg-bg-card rounded-lg p-4">
                  <h3 className="text-sm font-semibold text-text-secondary mb-2">
                    Session ID
                  </h3>
                  <div className="font-mono text-sm text-text-primary break-all">
                    {interaction.session_id}
                  </div>
                </div>
              </div>
            )}

            {/* Request Tab */}
            {activeTab === 'request' && (
              <div className="space-y-4">
                {/* Request Line */}
                <div className="bg-bg-card rounded-lg p-4">
                  <div className="font-mono text-sm">
                    <span className="text-neon-green">{interaction.method}</span>
                    <span className="text-text-primary"> {interaction.path}</span>
                    <span className="text-text-secondary"> {request?.protocolVersion || 'HTTP/1.1'}</span>
                  </div>
                </div>

                {/* Headers */}
                {request?.headers && Object.keys(request.headers).length > 0 && (
                  <div className="bg-bg-card rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="text-sm font-semibold text-text-secondary">Headers</h3>
                      <button
                        onClick={() => handleCopy(JSON.stringify(request.headers, null, 2))}
                        className="text-text-secondary hover:text-neon-green"
                      >
                        {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                      </button>
                    </div>
                    <div className="space-y-1">
                      {Object.entries(request.headers).map(([key, value]) => (
                        <div key={key} className="font-mono text-sm">
                          <span className="text-neon-blue">{key}</span>
                          <span className="text-text-secondary">: </span>
                          <span className="text-text-primary">{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Body */}
                {request?.body && (
                  <div className="bg-bg-card rounded-lg p-4">
                    <h3 className="text-sm font-semibold text-text-secondary mb-2">Body</h3>
                    <pre className="font-mono text-sm text-text-primary whitespace-pre-wrap">
                      {request.body || '(empty)'}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {/* Response Tab */}
            {activeTab === 'response' && (
              <div className="space-y-4">
                {/* AI Generation Info */}
                {metadata?.generationSource && (
                  <div className="bg-neon-purple/10 border border-neon-purple/30 rounded-lg p-4">
                    <div className="flex items-center space-x-2 text-neon-purple">
                      <Server className="w-4 h-4" />
                      <span className="text-sm font-semibold">
                        Response generated via: {metadata.generationSource}
                      </span>
                    </div>
                  </div>
                )}

                {/* Response Headers */}
                {response?.headers && Object.keys(response.headers).length > 0 && (
                  <div className="bg-bg-card rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="text-sm font-semibold text-text-secondary">Response Headers</h3>
                      <button
                        onClick={() => handleCopy(JSON.stringify(response.headers, null, 2))}
                        className="text-text-secondary hover:text-neon-green"
                      >
                        {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                      </button>
                    </div>
                    <div className="space-y-1">
                      {Object.entries(response.headers).map(([key, value]) => (
                        <div key={key} className="font-mono text-sm">
                          <span className="text-neon-orange">{key}</span>
                          <span className="text-text-secondary">: </span>
                          <span className="text-text-primary">{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Response Body */}
                {response?.body && (
                  <div className="bg-bg-card rounded-lg p-4">
                    <h3 className="text-sm font-semibold text-text-secondary mb-2">Response Body</h3>
                    <pre className="font-mono text-sm text-text-primary whitespace-pre-wrap overflow-x-auto">
                      {response.body}
                    </pre>
                  </div>
                )}

                {!response && (
                  <div className="text-text-secondary text-center py-8">
                    No response body available for this interaction.
                  </div>
                )}
              </div>
            )}

            {/* Raw JSON Tab */}
            {activeTab === 'raw' && (
              <div className="bg-bg-card rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-semibold text-text-secondary">Raw Log Data</h3>
                  <button
                    onClick={() => handleCopy(JSON.stringify(interaction.raw, null, 2))}
                    className="flex items-center space-x-1 text-text-secondary hover:text-neon-green transition-colors"
                  >
                    {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                    <span className="text-xs">Copy</span>
                  </button>
                </div>
                <pre className="font-mono text-xs text-text-primary whitespace-pre-wrap overflow-x-auto max-h-96 overflow-y-auto">
                  {JSON.stringify(interaction.raw, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}


