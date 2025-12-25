import { useState, useEffect } from 'react';
import { X, Eye, Code, ExternalLink, Copy, Check } from 'lucide-react';
import api from '../services/api';
import LoadingSpinner from './LoadingSpinner';

interface GalahPreviewModalProps {
  interactionId: string;
  onClose: () => void;
}

export default function GalahPreviewModal({ interactionId, onClose }: GalahPreviewModalProps) {
  const [preview, setPreview] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'preview' | 'html' | 'request'>('preview');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const fetchPreview = async () => {
      try {
        setLoading(true);
        const data = await api.getGalahInteractionPreview(interactionId);
        setPreview(data);
      } catch (err) {
        setError('Failed to load preview');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    fetchPreview();
  }, [interactionId]);

  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const response = preview?.response as { body?: string; headers?: Record<string, string>; status_code?: number; content_type?: string; has_content?: boolean } | undefined;
  const request = preview?.request as { method?: string; path?: string; headers?: Record<string, string>; body?: string } | undefined;
  const sourceGeo = preview?.source_geo as { country_name?: string; city_name?: string; region_name?: string } | undefined;
  const msg = preview?.msg as string | undefined;
  const sessionId = preview?.session_id as string | undefined;
  const responseBody = response?.body || '';
  const hasContent = response?.has_content || !!responseBody;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/80 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative bg-bg-secondary rounded-xl border border-bg-hover shadow-2xl w-full max-w-7xl max-h-[95vh] h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-bg-hover bg-bg-card/50">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-lg bg-neon-orange/20 flex items-center justify-center">
              <Eye className="w-5 h-5 text-neon-orange" />
            </div>
            <div>
              <h2 className="text-lg font-display font-bold text-text-primary">
                AI-Generated Page Preview
              </h2>
              <p className="text-sm text-text-secondary">
                {request?.method} {request?.path}
              </p>
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
          <div className="flex items-center justify-center py-12 flex-grow">
            <LoadingSpinner size="lg" />
          </div>
        ) : error ? (
          <div className="flex items-center justify-center py-12 text-neon-red flex-grow">
            {error}
          </div>
        ) : preview ? (
          <div className="flex flex-col flex-grow overflow-hidden">
            {/* Tabs */}
            <div className="flex border-b border-bg-hover px-4">
              {[
                { id: 'preview', label: 'Page Preview', icon: <Eye className="w-4 h-4" /> },
                { id: 'html', label: 'HTML Source', icon: <Code className="w-4 h-4" /> },
                { id: 'request', label: 'Request Details', icon: <ExternalLink className="w-4 h-4" /> },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as typeof activeTab)}
                  className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors flex items-center space-x-2 ${
                    activeTab === tab.id
                      ? 'border-neon-orange text-neon-orange'
                      : 'border-transparent text-text-secondary hover:text-text-primary'
                  }`}
                >
                  {tab.icon}
                  <span>{tab.label}</span>
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="flex-grow overflow-hidden">
              {/* Preview Tab - Render the HTML */}
              {activeTab === 'preview' && (
                <div className="h-full flex flex-col">
                  <div className="p-3 bg-bg-card border-b border-bg-hover flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      <span className={`px-2 py-0.5 rounded text-xs font-mono ${
                        response?.status_code === 200 ? 'bg-neon-green/20 text-neon-green' : 'bg-neon-orange/20 text-neon-orange'
                      }`}>
                        HTTP {response?.status_code || 200}
                      </span>
                      <span className="text-xs text-text-secondary">
                        Content-Type: {response?.content_type || 'text/html'}
                      </span>
                    </div>
                    <span className="text-xs text-text-muted">
                      This is what the attacker saw
                    </span>
                  </div>
                  <div className="flex-grow overflow-auto bg-white">
                    {hasContent && responseBody ? (
                      <iframe
                        srcDoc={responseBody}
                        title="AI Generated Page"
                        className="w-full h-full border-0"
                        sandbox="allow-same-origin"
                      />
                    ) : (
                      <div className="flex flex-col items-center justify-center h-full text-text-secondary space-y-2 bg-bg-primary">
                        <span className="text-lg">No AI-generated response content</span>
                        <span className="text-sm text-text-muted">
                          {msg === 'successfulResponse' 
                            ? 'This request was successful but no response body was captured.'
                            : `Response status: ${msg || 'unknown'}`}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* HTML Source Tab */}
              {activeTab === 'html' && (
                <div className="h-full flex flex-col">
                  <div className="p-3 bg-bg-card border-b border-bg-hover flex items-center justify-between">
                    <span className="text-sm text-text-secondary">Raw HTML Response</span>
                    <button
                      onClick={() => handleCopy(responseBody)}
                      className="flex items-center space-x-1 text-xs text-text-secondary hover:text-neon-green transition-colors"
                    >
                      {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                      <span>{copied ? 'Copied!' : 'Copy'}</span>
                    </button>
                  </div>
                  <div className="flex-grow overflow-auto p-4 bg-bg-primary">
                    <pre className="text-sm font-mono text-text-primary whitespace-pre-wrap break-words">
                      {responseBody || 'No response body available'}
                    </pre>
                  </div>
                </div>
              )}

              {/* Request Details Tab */}
              {activeTab === 'request' && (
                <div className="h-full overflow-auto p-4 space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Request Info */}
                    <div className="bg-bg-card rounded-lg p-4">
                      <h3 className="text-sm font-semibold text-neon-blue mb-3">Request</h3>
                      <div className="space-y-2 text-sm">
                        <div className="flex items-center justify-between">
                          <span className="text-text-secondary">Method:</span>
                          <span className="font-mono text-neon-green">{request?.method}</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-text-secondary">Path:</span>
                          <span className="font-mono text-neon-orange">{request?.path}</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-text-secondary">Source IP:</span>
                          <span className="font-mono text-text-primary">{preview.source_ip as string}</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-text-secondary">Timestamp:</span>
                          <span className="font-mono text-text-primary text-xs">
                            {new Date(preview.timestamp as string).toLocaleString()}
                          </span>
                        </div>
                        {sourceGeo?.country_name && (
                          <div className="flex items-center justify-between">
                            <span className="text-text-secondary">Location:</span>
                            <span className="font-mono text-text-primary text-xs">
                              {[sourceGeo.city_name, sourceGeo.region_name, sourceGeo.country_name].filter(Boolean).join(', ')}
                            </span>
                          </div>
                        )}
                        {sessionId && (
                          <div className="flex items-center justify-between">
                            <span className="text-text-secondary">Session:</span>
                            <span className="font-mono text-text-muted text-xs truncate max-w-[200px]">
                              {sessionId}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Response Info */}
                    <div className="bg-bg-card rounded-lg p-4">
                      <h3 className="text-sm font-semibold text-neon-orange mb-3">Response</h3>
                      <div className="space-y-2 text-sm">
                        <div className="flex items-center justify-between">
                          <span className="text-text-secondary">AI Status:</span>
                          <span className={`font-mono ${msg === 'successfulResponse' ? 'text-neon-green' : 'text-neon-orange'}`}>
                            {msg || 'unknown'}
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-text-secondary">HTTP Status:</span>
                          <span className={`font-mono ${response?.status_code === 200 ? 'text-neon-green' : 'text-neon-orange'}`}>
                            {response?.status_code || 200}
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-text-secondary">Content-Type:</span>
                          <span className="font-mono text-text-primary text-xs">{response?.content_type}</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-text-secondary">Body Size:</span>
                          <span className="font-mono text-text-primary">{responseBody.length} bytes</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-text-secondary">Has Content:</span>
                          <span className={`font-mono ${hasContent ? 'text-neon-green' : 'text-neon-red'}`}>
                            {hasContent ? 'Yes' : 'No'}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Request Headers */}
                  {request?.headers && Object.keys(request.headers).length > 0 && (
                    <div className="bg-bg-card rounded-lg p-4">
                      <h3 className="text-sm font-semibold text-text-primary mb-3">Request Headers</h3>
                      <div className="space-y-1 text-xs font-mono">
                        {Object.entries(request.headers).map(([key, value]) => (
                          <div key={key} className="flex">
                            <span className="text-neon-blue w-40 flex-shrink-0">{key}:</span>
                            <span className="text-text-primary break-all">{value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Response Headers */}
                  {response?.headers && Object.keys(response.headers).length > 0 && (
                    <div className="bg-bg-card rounded-lg p-4">
                      <h3 className="text-sm font-semibold text-text-primary mb-3">Response Headers</h3>
                      <div className="space-y-1 text-xs font-mono">
                        {Object.entries(response.headers).map(([key, value]) => (
                          <div key={key} className="flex">
                            <span className="text-neon-orange w-40 flex-shrink-0">{key}:</span>
                            <span className="text-text-primary break-all">{value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
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


