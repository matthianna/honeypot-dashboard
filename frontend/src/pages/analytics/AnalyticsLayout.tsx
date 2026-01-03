import { useState, createContext, useContext, ReactNode } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import {
  LayoutDashboard,
  HeartPulse,
  Clock,
  Key,
  Terminal,
  Command,
  Shield,
  Globe,
  Bug,
  Monitor,
  Cpu,
  FileText,
  Flame,
  Ban,
  Users,
  Search,
  GitCompare,
  MessageSquare,
} from 'lucide-react';
import { DateRangePicker, FilterBar, EvidenceFooter } from '../../components/analytics';
import type { AnalyticsFilters } from '../../components/analytics';
import type { TimeRange } from '../../types';

// Context for sharing filters across analytics pages
interface AnalyticsContextType {
  timeRange: TimeRange;
  setTimeRange: (range: TimeRange) => void;
  filters: AnalyticsFilters;
  setFilters: (filters: AnalyticsFilters) => void;
  lastUpdated: Date;
  setLastUpdated: (date: Date) => void;
}

const AnalyticsContext = createContext<AnalyticsContextType | null>(null);

export function useAnalytics() {
  const context = useContext(AnalyticsContext);
  if (!context) {
    throw new Error('useAnalytics must be used within AnalyticsLayout');
  }
  return context;
}

// Navigation items - organized by category
const NAV_ITEMS = [
  // General
  { path: '/analytics', label: 'Overview', icon: LayoutDashboard, end: true },
  { path: '/analytics/health', label: 'Health & Coverage', icon: HeartPulse },
  { path: '/analytics/timeline', label: 'Timeline Explorer', icon: Clock },
  // Honeypot Analysis  
  { path: '/analytics/credentials', label: 'Credentials', icon: Key },
  { path: '/analytics/cowrie-sessions', label: 'Cowrie Sessions', icon: Terminal },
  { path: '/analytics/commands', label: 'Commands', icon: Command },
  { path: '/analytics/mitre', label: 'MITRE ATT&CK', icon: Shield },
  { path: '/analytics/web', label: 'Web Patterns', icon: Globe },
  { path: '/analytics/malware', label: 'Malware', icon: Bug },
  { path: '/analytics/rdp', label: 'RDP Overview', icon: Monitor },
  { path: '/analytics/ai-performance', label: 'AI Performance', icon: Cpu },
  // Firewall Analytics
  { path: '/analytics/firewall', label: 'FW: Pressure', icon: Flame },
  { path: '/analytics/firewall/closed-ports', label: 'FW: Closed Ports', icon: Ban },
  { path: '/analytics/firewall/rules', label: 'FW: Rule Hits', icon: Shield },
  { path: '/analytics/firewall/attackers', label: 'FW: Top Attackers', icon: Users },
  { path: '/analytics/firewall/scanners', label: 'FW: Scan Detection', icon: Search },
  { path: '/analytics/firewall/correlation', label: 'FW: Correlation', icon: GitCompare },
  // Other
  { path: '/analytics/galah-conversations', label: 'Galah LLM', icon: MessageSquare },
  { path: '/analytics/case-study', label: 'Case Study', icon: FileText },
];

interface AnalyticsLayoutProps {
  children?: ReactNode;
}

export default function AnalyticsLayout({ children }: AnalyticsLayoutProps) {
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');
  const [filters, setFilters] = useState<AnalyticsFilters>({});
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  return (
    <AnalyticsContext.Provider value={{ timeRange, setTimeRange, filters, setFilters, lastUpdated, setLastUpdated }}>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <h1 className="text-2xl font-display font-bold text-white">
              Analytics Dashboard
            </h1>
            <p className="text-sm text-text-muted mt-1">
              Evidence-ready analysis for thesis documentation
            </p>
          </div>
          <DateRangePicker value={timeRange} onChange={setTimeRange} />
        </div>

        {/* Sub Navigation */}
        <div className="bg-bg-card border border-bg-hover rounded-lg p-2 overflow-x-auto">
          <nav className="flex items-center gap-1 min-w-max">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  end={item.end}
                  className={({ isActive }) =>
                    `flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors whitespace-nowrap ${
                      isActive
                        ? 'bg-neon-green/20 text-neon-green'
                        : 'text-text-secondary hover:text-text-primary hover:bg-bg-hover'
                    }`
                  }
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </nav>
        </div>

        {/* Filter Bar */}
        <FilterBar filters={filters} onFiltersChange={setFilters} />

        {/* Page Content */}
        <div className="min-h-[600px]">
          {children || <Outlet />}
        </div>

        {/* Evidence Footer */}
        <EvidenceFooter
          lastUpdated={lastUpdated}
          filters={Object.fromEntries(
            Object.entries(filters).filter(([, v]) => v !== undefined)
          ) as Record<string, string | number | undefined>}
        />
      </div>
    </AnalyticsContext.Provider>
  );
}

