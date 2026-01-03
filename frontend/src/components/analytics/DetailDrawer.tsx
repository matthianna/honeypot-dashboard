import { X, Copy, Check, ChevronRight } from 'lucide-react';
import { useState } from 'react';

interface DetailDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  data: Record<string, unknown> | null;
  normalizedFields?: { label: string; value: string | number | null; color?: string }[];
}

export default function DetailDrawer({
  isOpen,
  onClose,
  title,
  subtitle,
  data,
  normalizedFields,
}: DetailDrawerProps) {
  const [copied, setCopied] = useState(false);
  const [expandedKeys, setExpandedKeys] = useState<Set<string>>(new Set());

  const copyToClipboard = () => {
    if (!data) return;
    navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const toggleExpand = (key: string) => {
    const newExpanded = new Set(expandedKeys);
    if (newExpanded.has(key)) {
      newExpanded.delete(key);
    } else {
      newExpanded.add(key);
    }
    setExpandedKeys(newExpanded);
  };

  const renderValue = (value: unknown, key: string, depth = 0): React.ReactNode => {
    if (value === null || value === undefined) {
      return <span className="text-text-muted italic">null</span>;
    }

    if (typeof value === 'boolean') {
      return (
        <span className={value ? 'text-neon-green' : 'text-neon-red'}>
          {String(value)}
        </span>
      );
    }

    if (typeof value === 'number') {
      return <span className="text-neon-blue">{value}</span>;
    }

    if (typeof value === 'string') {
      // Check if it looks like a timestamp
      if (/^\d{4}-\d{2}-\d{2}T/.test(value)) {
        return (
          <span className="text-neon-orange">
            {new Date(value).toLocaleString()}
          </span>
        );
      }
      // Check if it looks like an IP
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) {
        return <span className="text-neon-purple font-mono">{value}</span>;
      }
      return <span className="text-neon-green">{`"${value}"`}</span>;
    }

    if (Array.isArray(value)) {
      if (value.length === 0) {
        return <span className="text-text-muted">[]</span>;
      }
      const isExpanded = expandedKeys.has(key);
      return (
        <div>
          <button
            onClick={() => toggleExpand(key)}
            className="flex items-center gap-1 text-text-secondary hover:text-text-primary"
          >
            <ChevronRight className={`w-3 h-3 transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
            <span className="text-text-muted">[{value.length} items]</span>
          </button>
          {isExpanded && (
            <div className="pl-4 border-l border-bg-hover ml-1 mt-1">
              {value.map((item, i) => (
                <div key={i} className="py-0.5">
                  {renderValue(item, `${key}.${i}`, depth + 1)}
                </div>
              ))}
            </div>
          )}
        </div>
      );
    }

    if (typeof value === 'object') {
      const entries = Object.entries(value as Record<string, unknown>);
      if (entries.length === 0) {
        return <span className="text-text-muted">{'{}'}</span>;
      }
      const isExpanded = expandedKeys.has(key);
      return (
        <div>
          <button
            onClick={() => toggleExpand(key)}
            className="flex items-center gap-1 text-text-secondary hover:text-text-primary"
          >
            <ChevronRight className={`w-3 h-3 transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
            <span className="text-text-muted">{`{${entries.length} fields}`}</span>
          </button>
          {isExpanded && (
            <div className="pl-4 border-l border-bg-hover ml-1 mt-1">
              {entries.map(([k, v]) => (
                <div key={k} className="py-0.5">
                  <span className="text-neon-blue">{k}</span>
                  <span className="text-text-muted">: </span>
                  {renderValue(v, `${key}.${k}`, depth + 1)}
                </div>
              ))}
            </div>
          )}
        </div>
      );
    }

    return <span>{String(value)}</span>;
  };

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 z-40"
        onClick={onClose}
      />

      {/* Drawer */}
      <div className="fixed right-0 top-0 h-full w-full max-w-xl bg-bg-card border-l border-bg-hover shadow-xl z-50 flex flex-col animate-slide-in">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-bg-hover">
          <div>
            <h2 className="text-lg font-display font-bold text-white">{title}</h2>
            {subtitle && <p className="text-sm text-text-muted">{subtitle}</p>}
          </div>
          <button
            onClick={onClose}
            className="p-2 text-text-secondary hover:text-text-primary hover:bg-bg-hover rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Normalized Fields */}
        {normalizedFields && normalizedFields.length > 0 && (
          <div className="p-4 border-b border-bg-hover">
            <h3 className="text-sm font-medium text-text-secondary mb-3">Key Fields</h3>
            <div className="grid grid-cols-2 gap-3">
              {normalizedFields.map((field, i) => (
                <div key={i} className="bg-bg-secondary rounded-lg p-3">
                  <div className="text-xs text-text-muted mb-1">{field.label}</div>
                  <div className={`text-sm font-medium ${field.color || 'text-text-primary'}`}>
                    {field.value ?? '-'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Raw JSON */}
        <div className="flex-1 overflow-auto p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium text-text-secondary">Raw Data</h3>
            <button
              onClick={copyToClipboard}
              className="flex items-center gap-1.5 px-2 py-1 text-xs text-text-secondary hover:text-text-primary transition-colors"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-neon-green" />
                  <span className="text-neon-green">Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy JSON</span>
                </>
              )}
            </button>
          </div>

          {data ? (
            <div className="bg-bg-secondary rounded-lg p-4 font-mono text-sm overflow-auto">
              {Object.entries(data).map(([key, value]) => (
                <div key={key} className="py-1">
                  <span className="text-neon-blue">{key}</span>
                  <span className="text-text-muted">: </span>
                  {renderValue(value, key)}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center text-text-muted py-8">No data available</div>
          )}
        </div>
      </div>
    </>
  );
}

