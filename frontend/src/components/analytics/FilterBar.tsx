import { useState } from 'react';
import { Filter, X, ChevronDown } from 'lucide-react';

export interface AnalyticsFilters {
  honeypot?: string;
  protocol?: string;
  country?: string;
  srcIp?: string;
  dstPort?: number;
  aiVariant?: string;
  sessionId?: string;
}

interface FilterBarProps {
  filters: AnalyticsFilters;
  onFiltersChange: (filters: AnalyticsFilters) => void;
  availableHoneypots?: string[];
  availableProtocols?: string[];
  availableCountries?: string[];
  availableVariants?: string[];
}

const HONEYPOTS = ['cowrie', 'dionaea', 'galah', 'rdpy', 'heralding', 'firewall'];
const PROTOCOLS = ['SSH', 'Telnet', 'HTTP', 'HTTPS', 'RDP', 'FTP', 'SMB', 'MySQL', 'VNC'];
const VARIANTS = ['plain', 'openai', 'ollama'];

export default function FilterBar({
  filters,
  onFiltersChange,
  availableHoneypots = HONEYPOTS,
  availableProtocols = PROTOCOLS,
  availableVariants = VARIANTS,
}: FilterBarProps) {
  const [showAdvanced, setShowAdvanced] = useState(false);

  const updateFilter = (key: keyof AnalyticsFilters, value: string | number | undefined) => {
    onFiltersChange({ ...filters, [key]: value || undefined });
  };

  const clearFilters = () => {
    onFiltersChange({});
  };

  const activeFiltersCount = Object.values(filters).filter(Boolean).length;

  return (
    <div className="bg-bg-card border border-bg-hover rounded-lg p-3">
      <div className="flex flex-wrap items-center gap-3">
        {/* Filter Icon */}
        <div className="flex items-center gap-2 text-text-secondary">
          <Filter className="w-4 h-4" />
          <span className="text-sm font-medium">Filters</span>
          {activeFiltersCount > 0 && (
            <span className="px-1.5 py-0.5 bg-neon-green/20 text-neon-green text-xs rounded-full">
              {activeFiltersCount}
            </span>
          )}
        </div>

        {/* Honeypot Filter */}
        <select
          value={filters.honeypot || ''}
          onChange={(e) => updateFilter('honeypot', e.target.value)}
          className="px-3 py-1.5 bg-bg-secondary border border-bg-hover rounded-md text-sm text-text-primary focus:border-neon-green focus:outline-none"
        >
          <option value="">All Honeypots</option>
          {availableHoneypots.map((hp) => (
            <option key={hp} value={hp}>
              {hp.charAt(0).toUpperCase() + hp.slice(1)}
            </option>
          ))}
        </select>

        {/* Protocol Filter */}
        <select
          value={filters.protocol || ''}
          onChange={(e) => updateFilter('protocol', e.target.value)}
          className="px-3 py-1.5 bg-bg-secondary border border-bg-hover rounded-md text-sm text-text-primary focus:border-neon-green focus:outline-none"
        >
          <option value="">All Protocols</option>
          {availableProtocols.map((proto) => (
            <option key={proto} value={proto}>
              {proto}
            </option>
          ))}
        </select>

        {/* AI Variant Filter */}
        <select
          value={filters.aiVariant || ''}
          onChange={(e) => updateFilter('aiVariant', e.target.value)}
          className="px-3 py-1.5 bg-bg-secondary border border-bg-hover rounded-md text-sm text-text-primary focus:border-neon-green focus:outline-none"
        >
          <option value="">All Variants</option>
          {availableVariants.map((variant) => (
            <option key={variant} value={variant}>
              {variant.charAt(0).toUpperCase() + variant.slice(1)}
            </option>
          ))}
        </select>

        {/* Advanced Toggle */}
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex items-center gap-1 px-3 py-1.5 text-sm text-text-secondary hover:text-text-primary transition-colors"
        >
          <span>Advanced</span>
          <ChevronDown className={`w-4 h-4 transition-transform ${showAdvanced ? 'rotate-180' : ''}`} />
        </button>

        {/* Clear Filters */}
        {activeFiltersCount > 0 && (
          <button
            onClick={clearFilters}
            className="flex items-center gap-1 px-3 py-1.5 text-sm text-neon-red hover:text-neon-red/80 transition-colors"
          >
            <X className="w-4 h-4" />
            <span>Clear</span>
          </button>
        )}
      </div>

      {/* Advanced Filters */}
      {showAdvanced && (
        <div className="flex flex-wrap items-center gap-3 mt-3 pt-3 border-t border-bg-hover">
          {/* Source IP */}
          <div className="flex items-center gap-2">
            <label className="text-xs text-text-secondary">Source IP:</label>
            <input
              type="text"
              value={filters.srcIp || ''}
              onChange={(e) => updateFilter('srcIp', e.target.value)}
              placeholder="e.g., 192.168.1.1"
              className="px-3 py-1.5 bg-bg-secondary border border-bg-hover rounded-md text-sm text-text-primary focus:border-neon-green focus:outline-none w-40"
            />
          </div>

          {/* Destination Port */}
          <div className="flex items-center gap-2">
            <label className="text-xs text-text-secondary">Dest Port:</label>
            <input
              type="number"
              value={filters.dstPort || ''}
              onChange={(e) => updateFilter('dstPort', e.target.value ? parseInt(e.target.value) : undefined)}
              placeholder="e.g., 22"
              className="px-3 py-1.5 bg-bg-secondary border border-bg-hover rounded-md text-sm text-text-primary focus:border-neon-green focus:outline-none w-24"
            />
          </div>

          {/* Country */}
          <div className="flex items-center gap-2">
            <label className="text-xs text-text-secondary">Country:</label>
            <input
              type="text"
              value={filters.country || ''}
              onChange={(e) => updateFilter('country', e.target.value)}
              placeholder="e.g., United States"
              className="px-3 py-1.5 bg-bg-secondary border border-bg-hover rounded-md text-sm text-text-primary focus:border-neon-green focus:outline-none w-40"
            />
          </div>

          {/* Session ID */}
          <div className="flex items-center gap-2">
            <label className="text-xs text-text-secondary">Session ID:</label>
            <input
              type="text"
              value={filters.sessionId || ''}
              onChange={(e) => updateFilter('sessionId', e.target.value)}
              placeholder="Session ID"
              className="px-3 py-1.5 bg-bg-secondary border border-bg-hover rounded-md text-sm text-text-primary focus:border-neon-green focus:outline-none w-48"
            />
          </div>
        </div>
      )}
    </div>
  );
}


