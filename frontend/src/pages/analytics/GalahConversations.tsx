import { useCallback, useEffect, useState } from 'react';
import { MessageSquare, Code, ChevronRight } from 'lucide-react';
import { useAnalytics } from './AnalyticsLayout';
import { ExportToolbar, exportToCSV } from '../../components/analytics';
import DataTable from '../../components/DataTable';
import LoadingSpinner from '../../components/LoadingSpinner';
import IPLink from '../../components/IPLink';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

export default function GalahConversations() {
  const { timeRange, setLastUpdated } = useAnalytics();
  const [selectedConversation, setSelectedConversation] = useState<string | null>(null);
  const [conversationDetail, setConversationDetail] = useState<any>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const { data: conversations, loading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsGalahConversations(timeRange, 50),
    [timeRange]),
    [timeRange],
    60000
  );

  useEffect(() => {
    if (conversations) setLastUpdated(new Date());
  }, [conversations, setLastUpdated]);

  const loadConversationDetail = async (id: string) => {
    setSelectedConversation(id);
    setDetailLoading(true);
    try {
      const detail = await api.getAnalyticsGalahConversation(id);
      setConversationDetail(detail);
    } catch (error) {
      console.error('Failed to load conversation:', error);
    } finally {
      setDetailLoading(false);
    }
  };

  const conversationColumns = [
    { key: 'timestamp', header: 'Time', render: (item: any) => {
      try {
        return new Date(item.timestamp).toLocaleString();
      } catch {
        return item.timestamp;
      }
    }},
    { key: 'method', header: 'Method', render: (item: any) => (
      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
        item.method === 'GET' ? 'bg-neon-green/20 text-neon-green' :
        item.method === 'POST' ? 'bg-neon-blue/20 text-neon-blue' :
        'bg-neon-orange/20 text-neon-orange'
      }`}>
        {item.method}
      </span>
    )},
    { key: 'path', header: 'Path', render: (item: any) => (
      <span className="font-mono text-sm text-neon-green max-w-xs truncate block">{item.path}</span>
    )},
    { key: 'src_ip', header: 'Source IP', render: (item: any) => 
      item.src_ip ? <IPLink ip={item.src_ip} /> : '-'
    },
    { key: 'response_status', header: 'Status', render: (item: any) => (
      <span className={`font-mono ${
        item.response_status < 400 ? 'text-neon-green' : 'text-neon-red'
      }`}>
        {item.response_status}
      </span>
    )},
    { key: 'msg', header: 'Result', render: (item: any) => (
      <span className={`text-xs ${
        item.msg?.includes('success') ? 'text-neon-green' : 'text-neon-orange'
      }`}>
        {item.msg?.slice(0, 30)}
      </span>
    )},
    { key: 'view', header: '', render: (item: any) => (
      <button
        onClick={() => loadConversationDetail(item.id)}
        className={`p-1 rounded hover:bg-bg-hover ${
          selectedConversation === item.id ? 'text-neon-green' : 'text-text-muted'
        }`}
      >
        <ChevronRight className="w-4 h-4" />
      </button>
    )},
  ];

  if (loading && !conversations) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-display font-bold text-white flex items-center gap-2">
            <MessageSquare className="w-6 h-6 text-neon-orange" />
            Galah LLM Conversations
          </h2>
          <p className="text-sm text-text-muted mt-1">
            HTTP honeypot interactions with AI-generated responses
          </p>
        </div>
        <ExportToolbar
          onExportCSV={() => exportToCSV(conversations?.conversations || [], 'galah_conversations')}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Conversations List */}
        <div className="lg:col-span-2">
          <div className="bg-bg-card rounded-xl border border-bg-hover">
            <div className="p-4 border-b border-bg-hover">
              <h3 className="font-medium text-white">
                Recent Interactions ({conversations?.conversations?.length || 0})
              </h3>
            </div>
            <DataTable
              columns={conversationColumns}
              data={conversations?.conversations || []}
              loading={loading}
              maxHeight="600px"
            />
          </div>
        </div>

        {/* Conversation Detail */}
        <div>
          {selectedConversation && conversationDetail ? (
            <div className="bg-bg-card rounded-xl border border-bg-hover p-4 space-y-4">
              <h3 className="font-medium text-white flex items-center gap-2">
                <Code className="w-4 h-4" />
                Conversation Detail
              </h3>
              
              {detailLoading ? (
                <LoadingSpinner />
              ) : conversationDetail.error ? (
                <div className="text-neon-red">{conversationDetail.error}</div>
              ) : (
                <>
                  {/* Metadata */}
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-text-muted">Source IP</span>
                      {conversationDetail.source?.ip && (
                        <IPLink ip={conversationDetail.source.ip} />
                      )}
                    </div>
                    <div className="flex justify-between">
                      <span className="text-text-muted">Country</span>
                      <span>{conversationDetail.source?.geo?.country_name || 'Unknown'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-text-muted">Duration</span>
                      <span>{conversationDetail.duration_ms || 0}ms</span>
                    </div>
                  </div>

                  {/* Request */}
                  <div>
                    <div className="text-xs text-text-muted mb-1">REQUEST</div>
                    <div className="bg-bg-secondary rounded-lg p-3 font-mono text-xs overflow-x-auto">
                      <div className="text-neon-blue">
                        {conversationDetail.request?.method} {conversationDetail.request?.path}
                      </div>
                      {conversationDetail.request?.body && (
                        <pre className="mt-2 text-text-muted whitespace-pre-wrap break-all">
                          {typeof conversationDetail.request.body === 'string' 
                            ? conversationDetail.request.body.slice(0, 500)
                            : JSON.stringify(conversationDetail.request.body, null, 2).slice(0, 500)}
                        </pre>
                      )}
                    </div>
                  </div>

                  {/* Response */}
                  <div>
                    <div className="text-xs text-text-muted mb-1">RESPONSE</div>
                    <div className="bg-bg-secondary rounded-lg p-3 font-mono text-xs overflow-x-auto">
                      <div className={`${
                        (conversationDetail.response?.status || 0) < 400 ? 'text-neon-green' : 'text-neon-red'
                      }`}>
                        Status: {conversationDetail.response?.status}
                      </div>
                      {conversationDetail.response?.body && (
                        <pre className="mt-2 text-text-muted whitespace-pre-wrap break-all">
                          {typeof conversationDetail.response.body === 'string' 
                            ? conversationDetail.response.body.slice(0, 1000)
                            : JSON.stringify(conversationDetail.response.body, null, 2).slice(0, 1000)}
                        </pre>
                      )}
                    </div>
                  </div>

                  {/* User Agent */}
                  {conversationDetail.user_agent?.original && (
                    <div>
                      <div className="text-xs text-text-muted mb-1">USER AGENT</div>
                      <div className="bg-bg-secondary rounded-lg p-3 font-mono text-xs text-text-muted break-all">
                        {conversationDetail.user_agent.original}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          ) : (
            <div className="bg-bg-card rounded-xl border border-bg-hover p-8 text-center">
              <MessageSquare className="w-12 h-12 text-text-muted mx-auto mb-3" />
              <p className="text-text-muted">Select a conversation to view details</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

