import { useState, useCallback, useEffect } from 'react';
import { Search, Clock, ChevronLeft, ChevronRight } from 'lucide-react';
import { useAnalytics } from './AnalyticsLayout';
import { DetailDrawer, ExportToolbar, exportToCSV } from '../../components/analytics';
import DataTable from '../../components/DataTable';
import IPLink from '../../components/IPLink';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

export default function Timeline() {
  const { timeRange, filters, setLastUpdated } = useAnalytics();
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(1);
  const [selectedEvent, setSelectedEvent] = useState<any>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const { data: events, loading } = useApiWithRefresh(
    useCallback(() => 
      api.getAnalyticsEventsSearch({
        time_range: timeRange,
        page,
        size: 50,
        q: searchQuery || undefined,
        honeypot: filters.honeypot || undefined,
        src_ip: filters.srcIp || undefined,
        session_id: filters.sessionId || undefined,
      }),
    [timeRange, page, searchQuery, filters.honeypot, filters.srcIp, filters.sessionId]),
    [timeRange, page, searchQuery, filters.honeypot, filters.srcIp, filters.sessionId],
    30000
  );

  useEffect(() => {
    if (events) setLastUpdated(new Date());
  }, [events, setLastUpdated]);

  useEffect(() => {
    setPage(1);
  }, [searchQuery, filters.honeypot]);

  const handleRowClick = async (event: any) => {
    setSelectedEvent(event);
    setDrawerOpen(true);
    
    // Fetch full event details
    try {
      const fullEvent = await api.getAnalyticsEventById(event.id, event.index);
      setSelectedEvent({ ...event, ...fullEvent });
    } catch (error) {
      console.error('Failed to fetch event details:', error);
    }
  };

  const columns = [
    {
      key: 'timestamp',
      header: 'Timestamp',
      render: (item: any) => (
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-text-muted" />
          <span className="font-mono text-xs">
            {new Date(item.timestamp).toLocaleString()}
          </span>
        </div>
      ),
    },
    {
      key: 'honeypot',
      header: 'Honeypot',
      render: (item: any) => {
        const colors: Record<string, string> = {
          cowrie: 'text-neon-green',
          dionaea: 'text-neon-blue',
          galah: 'text-neon-orange',
          rdpy: 'text-neon-purple',
          heralding: 'text-neon-red',
        };
        return (
          <span className={`font-medium ${colors[item.honeypot] || 'text-text-primary'}`}>
            {item.honeypot}
          </span>
        );
      },
    },
    {
      key: 'src_ip',
      header: 'Source IP',
      render: (item: any) => item.src_ip ? <IPLink ip={item.src_ip} /> : '-',
    },
    {
      key: 'event_type',
      header: 'Event Type',
      render: (item: any) => (
        <span className="text-xs bg-bg-hover px-2 py-1 rounded">
          {item.event_type || 'unknown'}
        </span>
      ),
    },
    {
      key: 'summary',
      header: 'Summary',
      render: (item: any) => (
        <span className="text-sm text-text-secondary truncate max-w-xs block">
          {item.summary}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      {/* Search Bar */}
      <div className="flex items-center gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-text-muted" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by IP, session ID, username, command, URL..."
            className="w-full pl-10 pr-4 py-3 bg-bg-card border border-bg-hover rounded-lg text-text-primary placeholder-text-muted focus:border-neon-green focus:outline-none"
          />
        </div>
        <ExportToolbar
          onExportCSV={() => exportToCSV(events?.events || [], 'timeline_events')}
        />
      </div>

      {/* Results Count */}
      {events && (
        <div className="flex items-center justify-between text-sm text-text-muted">
          <span>
            Showing {((page - 1) * 50) + 1} - {Math.min(page * 50, events.total)} of {events.total.toLocaleString()} events
          </span>
          <span>Query time: {events.query_time_ms}ms</span>
        </div>
      )}

      {/* Events Table */}
      <div className="bg-bg-card rounded-xl border border-bg-hover">
        <DataTable
          columns={columns}
          data={events?.events || []}
          loading={loading}
          onRowClick={handleRowClick}
          maxHeight="500px"
          emptyMessage="No events found matching your search criteria"
        />
      </div>

      {/* Pagination */}
      {events && events.pages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="p-2 bg-bg-card border border-bg-hover rounded-lg hover:border-neon-green/50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronLeft className="w-5 h-5" />
          </button>
          
          <div className="flex items-center gap-1">
            {Array.from({ length: Math.min(5, events.pages) }, (_, i) => {
              const pageNum = Math.max(1, Math.min(page - 2, events.pages - 4)) + i;
              if (pageNum > events.pages) return null;
              return (
                <button
                  key={pageNum}
                  onClick={() => setPage(pageNum)}
                  className={`w-10 h-10 rounded-lg text-sm font-medium transition-colors ${
                    pageNum === page
                      ? 'bg-neon-green text-black'
                      : 'bg-bg-card border border-bg-hover hover:border-neon-green/50'
                  }`}
                >
                  {pageNum}
                </button>
              );
            })}
          </div>

          <button
            onClick={() => setPage(p => Math.min(events.pages, p + 1))}
            disabled={page === events.pages}
            className="p-2 bg-bg-card border border-bg-hover rounded-lg hover:border-neon-green/50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronRight className="w-5 h-5" />
          </button>
        </div>
      )}

      {/* Detail Drawer */}
      <DetailDrawer
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title="Event Details"
        subtitle={selectedEvent?.event_type}
        data={selectedEvent?.source || selectedEvent}
        normalizedFields={selectedEvent ? [
          { label: 'Honeypot', value: selectedEvent.honeypot, color: 'text-neon-green' },
          { label: 'Source IP', value: selectedEvent.src_ip, color: 'text-neon-blue' },
          { label: 'Timestamp', value: selectedEvent.timestamp ? new Date(selectedEvent.timestamp).toLocaleString() : null },
          { label: 'Event Type', value: selectedEvent.event_type },
        ] : []}
      />
    </div>
  );
}

