import { Clock, Database, CheckCircle } from 'lucide-react';

interface EvidenceFooterProps {
  totalRecords?: number;
  lastUpdated?: Date | string;
  queryTimeMs?: number;
  filters?: Record<string, string | number | undefined>;
  className?: string;
}

export default function EvidenceFooter({
  totalRecords,
  lastUpdated,
  queryTimeMs,
  filters,
  className = '',
}: EvidenceFooterProps) {
  const formatTime = (time: Date | string) => {
    const date = typeof time === 'string' ? new Date(time) : time;
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short',
    });
  };

  const activeFilters = filters
    ? Object.entries(filters).filter(([, value]) => value !== undefined)
    : [];

  return (
    <div className={`flex flex-wrap items-center gap-4 text-xs text-text-muted py-2 border-t border-bg-hover ${className}`}>
      {/* Total Records */}
      {totalRecords !== undefined && (
        <div className="flex items-center gap-1.5">
          <Database className="w-3.5 h-3.5" />
          <span>
            <span className="font-medium text-text-secondary">{totalRecords.toLocaleString()}</span>
            {' '}records
          </span>
        </div>
      )}

      {/* Last Updated */}
      {lastUpdated && (
        <div className="flex items-center gap-1.5">
          <Clock className="w-3.5 h-3.5" />
          <span>
            Updated: <span className="font-medium text-text-secondary">{formatTime(lastUpdated)}</span>
          </span>
        </div>
      )}

      {/* Query Time */}
      {queryTimeMs !== undefined && (
        <div className="flex items-center gap-1.5">
          <CheckCircle className="w-3.5 h-3.5 text-neon-green" />
          <span>
            Query: <span className="font-medium text-text-secondary">{queryTimeMs}ms</span>
          </span>
        </div>
      )}

      {/* Active Filters */}
      {activeFilters.length > 0 && (
        <div className="flex items-center gap-1.5 ml-auto">
          <span>Filters:</span>
          {activeFilters.map(([key, value]) => (
            <span
              key={key}
              className="px-1.5 py-0.5 bg-neon-green/10 text-neon-green rounded"
            >
              {key}={value}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}


