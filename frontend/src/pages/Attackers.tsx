import React, { useState, useMemo, useCallback } from 'react';
import { 
  Globe, Users, Activity, ChevronRight, 
  Clock, ExternalLink, AlertTriangle, Search,
  Eye, MapPin
} from 'lucide-react';
import Card, { CardHeader, CardContent } from '../components/Card';
import TimeRangeSelector from '../components/TimeRangeSelector';
import LoadingSpinner from '../components/LoadingSpinner';
import { useApiWithRefresh } from '../hooks/useApi';
import AttackerModal from '../components/AttackerModal';
import api from '../services/api';

type TimeRange = '1h' | '24h' | '7d' | '30d';

// Type definitions
interface HoneypotData {
  events: number;
  ips: number;
  color: string;
}

interface CountryData {
  country: string;
  total_events: number;
  unique_ips: number;
  honeypots: Record<string, HoneypotData>;
}

interface TopAttacker {
  ip: string;
  country: string;
  total_events: number;
  honeypots: string[];
  first_seen: string;
  last_seen: string;
}

interface CountryAttacker {
  ip: string;
  country: string;
  city: string | null;
  total_events: number;
  first_seen: string;
  last_seen: string;
  honeypots_attacked: string[];
  honeypot_details: Record<string, { events: number; color: string }>;
}

const HONEYPOT_COLORS: Record<string, string> = {
  cowrie: '#39ff14',
  dionaea: '#00d4ff',
  galah: '#ff6600',
  rdpy: '#bf00ff',
  heralding: '#ff3366',
};

const HONEYPOT_ICONS: Record<string, string> = {
  cowrie: '🐚',
  dionaea: '🪴',
  galah: '🦜',
  rdpy: '🖥️',
  heralding: '📢',
};

// Country flag emoji helper
const getCountryFlag = (countryName: string): string => {
  const countryFlags: Record<string, string> = {
    'United States': '🇺🇸',
    'China': '🇨🇳',
    'Russia': '🇷🇺',
    'Germany': '🇩🇪',
    'France': '🇫🇷',
    'United Kingdom': '🇬🇧',
    'Netherlands': '🇳🇱',
    'Brazil': '🇧🇷',
    'India': '🇮🇳',
    'South Korea': '🇰🇷',
    'Japan': '🇯🇵',
    'Vietnam': '🇻🇳',
    'Indonesia': '🇮🇩',
    'Singapore': '🇸🇬',
    'Taiwan': '🇹🇼',
    'Hong Kong': '🇭🇰',
    'Canada': '🇨🇦',
    'Australia': '🇦🇺',
    'Italy': '🇮🇹',
    'Spain': '🇪🇸',
    'Poland': '🇵🇱',
    'Ukraine': '🇺🇦',
    'Romania': '🇷🇴',
    'Bulgaria': '🇧🇬',
    'Turkey': '🇹🇷',
    'Iran': '🇮🇷',
    'Pakistan': '🇵🇰',
    'Thailand': '🇹🇭',
    'Malaysia': '🇲🇾',
    'Argentina': '🇦🇷',
    'Mexico': '🇲🇽',
    'Colombia': '🇨🇴',
    'Chile': '🇨🇱',
    'South Africa': '🇿🇦',
    'Nigeria': '🇳🇬',
    'Egypt': '🇪🇬',
    'Morocco': '🇲🇦',
    'Kenya': '🇰🇪',
    'Switzerland': '🇨🇭',
    'Austria': '🇦🇹',
    'Belgium': '🇧🇪',
    'Sweden': '🇸🇪',
    'Norway': '🇳🇴',
    'Denmark': '🇩🇰',
    'Finland': '🇫🇮',
    'Ireland': '🇮🇪',
    'Portugal': '🇵🇹',
    'Greece': '🇬🇷',
    'Czech Republic': '🇨🇿',
    'Hungary': '🇭🇺',
  };
  return countryFlags[countryName] || '🌍';
};

export const Attackers: React.FC = () => {
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');
  const [selectedCountry, setSelectedCountry] = useState<string | null>(null);
  const [selectedAttacker, setSelectedAttacker] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState<'countries' | 'top' | 'cross-honeypot'>('countries');

  // Fetch countries data
  const { data: countriesData, loading: countriesLoading } = useApiWithRefresh(
    useCallback(() => api.getAttackersByCountry(timeRange), [timeRange]),
    [timeRange],
    60000
  );

  // Fetch top attackers
  const { data: topAttackersData, loading: topLoading } = useApiWithRefresh(
    useCallback(() => api.getTopAttackersList(timeRange, 100), [timeRange]),
    [timeRange],
    60000
  );

  // Fetch country-specific attackers when a country is selected
  const { data: countryAttackersData, loading: countryAttackersLoading } = useApiWithRefresh(
    useCallback(() => selectedCountry ? api.getCountryAttackers(selectedCountry, timeRange) : Promise.resolve(null), [selectedCountry, timeRange]),
    [selectedCountry, timeRange],
    60000
  );

  // Fetch cross-honeypot threat intel
  const { data: threatIntel, loading: threatIntelLoading } = useApiWithRefresh(
    useCallback(() => api.getThreatIntel(timeRange), [timeRange]),
    [timeRange],
    60000
  );

  // Filter countries based on search
  const filteredCountries = useMemo((): CountryData[] => {
    if (!countriesData?.countries) return [];
    if (!searchQuery) return countriesData.countries;
    return countriesData.countries.filter((c: CountryData) => 
      c.country.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }, [countriesData, searchQuery]);

  // Filter top attackers based on search
  const filteredTopAttackers = useMemo((): TopAttacker[] => {
    if (!topAttackersData?.attackers) return [];
    if (!searchQuery) return topAttackersData.attackers;
    return topAttackersData.attackers.filter((a: TopAttacker) => 
      a.ip.includes(searchQuery) || a.country.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }, [topAttackersData, searchQuery]);

  const formatNumber = (num: number): string => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toLocaleString();
  };

  const formatTimeAgo = (timestamp: string): string => {
    const diff = Date.now() - new Date(timestamp).getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    
    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    return `${minutes}m ago`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-display font-bold text-neon-green">Attacker Profiles</h1>
          <p className="text-text-secondary">Attackers organized by country with detailed profiles</p>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-gradient-to-br from-neon-green/10 to-transparent">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-neon-green/20">
                <Globe className="w-5 h-5 text-neon-green" />
              </div>
              <div>
                <div className="text-2xl font-display font-bold text-neon-green">
                  {countriesData?.total_countries || 0}
                </div>
                <div className="text-xs text-text-secondary">Countries</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-neon-blue/10 to-transparent">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-neon-blue/20">
                <Users className="w-5 h-5 text-neon-blue" />
              </div>
              <div>
                <div className="text-2xl font-display font-bold text-neon-blue">
                  {formatNumber(topAttackersData?.total || 0)}
                </div>
                <div className="text-xs text-text-secondary">Unique Attackers</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-neon-orange/10 to-transparent">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-neon-orange/20">
                <Activity className="w-5 h-5 text-neon-orange" />
              </div>
              <div>
                <div className="text-2xl font-display font-bold text-neon-orange">
                  {formatNumber(countriesData?.countries?.reduce((acc: number, c: CountryData) => acc + c.total_events, 0) || 0)}
                </div>
                <div className="text-xs text-text-secondary">Total Events</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-neon-red/10 to-transparent">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-neon-red/20">
                <AlertTriangle className="w-5 h-5 text-neon-red" />
              </div>
              <div>
                <div className="text-2xl font-display font-bold text-neon-red">
                  {countriesData?.countries?.filter((c: CountryData) => Object.keys(c.honeypots).length > 2).length || 0}
                </div>
                <div className="text-xs text-text-secondary">Multi-Honeypot Sources</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* View Toggle & Search */}
      <div className="flex flex-col sm:flex-row gap-4 items-center justify-between">
        <div className="flex bg-bg-secondary rounded-lg p-1">
          <button
            onClick={() => setViewMode('countries')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              viewMode === 'countries' 
                ? 'bg-neon-green text-bg-primary' 
                : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            <Globe className="w-4 h-4 inline mr-2" />
            By Country
          </button>
          <button
            onClick={() => setViewMode('top')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              viewMode === 'top' 
                ? 'bg-neon-green text-bg-primary' 
                : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            <Users className="w-4 h-4 inline mr-2" />
            Top Attackers
          </button>
          <button
            onClick={() => setViewMode('cross-honeypot')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              viewMode === 'cross-honeypot' 
                ? 'bg-neon-purple text-bg-primary' 
                : 'text-text-secondary hover:text-text-primary'
            }`}
          >
            <Activity className="w-4 h-4 inline mr-2" />
            Cross-Honeypot
          </button>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-text-muted" />
          <input
            type="text"
            placeholder={viewMode === 'countries' ? 'Search countries...' : 'Search IP or country...'}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-bg-secondary border border-bg-hover rounded-lg text-text-primary placeholder-text-muted focus:outline-none focus:border-neon-green"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Countries/Top Attackers List */}
        <div className="lg:col-span-1">
          <Card className="h-[700px] flex flex-col">
            <CardHeader 
              title={viewMode === 'countries' ? 'Attack Sources' : viewMode === 'top' ? 'Top Attackers' : 'Multi-Honeypot Actors'}
              subtitle={viewMode === 'countries' 
                ? `${filteredCountries.length} countries` 
                : viewMode === 'top' 
                  ? `${filteredTopAttackers.length} attackers`
                  : `${threatIntel?.cross_honeypot_actors?.length || 0} actors (${threatIntel?.summary?.multi_percentage || 0}% of total)`}
              icon={viewMode === 'countries' ? <Globe className="w-5 h-5" /> : viewMode === 'top' ? <Users className="w-5 h-5" /> : <Activity className="w-5 h-5" />}
            />
            <CardContent className="flex-1 overflow-y-auto p-0">
              {(viewMode === 'countries' ? countriesLoading : topLoading) ? (
                <div className="h-full flex items-center justify-center">
                  <LoadingSpinner />
                </div>
              ) : viewMode === 'countries' ? (
                <div className="divide-y divide-bg-hover">
                  {filteredCountries.map((country) => (
                    <button
                      key={country.country}
                      onClick={() => setSelectedCountry(country.country)}
                      className={`w-full p-4 text-left hover:bg-bg-hover transition-colors ${
                        selectedCountry === country.country ? 'bg-bg-hover border-l-2 border-neon-green' : ''
                      }`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span className="text-xl">{getCountryFlag(country.country)}</span>
                          <span className="font-medium text-text-primary">{country.country}</span>
                        </div>
                        <ChevronRight className="w-4 h-4 text-text-muted" />
                      </div>
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-text-secondary">{country.unique_ips} IPs</span>
                        <span className="font-mono text-neon-green">{formatNumber(country.total_events)}</span>
                      </div>
                      <div className="flex gap-1 mt-2">
                        {Object.entries(country.honeypots).map(([hp, data]: [string, HoneypotData]) => (
                          <div
                            key={hp}
                            className="flex items-center gap-1 px-2 py-0.5 rounded-full text-xs"
                            style={{ backgroundColor: `${data.color}20`, color: data.color }}
                          >
                            {HONEYPOT_ICONS[hp]} {data.ips}
                          </div>
                        ))}
                      </div>
                    </button>
                  ))}
                </div>
              ) : viewMode === 'top' ? (
                <div className="divide-y divide-bg-hover">
                  {filteredTopAttackers.map((attacker: TopAttacker, index: number) => (
                    <button
                      key={attacker.ip}
                      onClick={() => setSelectedAttacker(attacker.ip)}
                      className="w-full p-4 text-left hover:bg-bg-hover transition-colors"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono text-text-muted w-6">#{index + 1}</span>
                          <span className="font-mono text-neon-green">{attacker.ip}</span>
                        </div>
                        <span className="font-mono text-neon-orange">{formatNumber(attacker.total_events)}</span>
                      </div>
                      <div className="flex items-center justify-between text-sm">
                        <div className="flex items-center gap-1">
                          <span>{getCountryFlag(attacker.country)}</span>
                          <span className="text-text-secondary">{attacker.country}</span>
                        </div>
                        <span className="text-text-muted text-xs">{formatTimeAgo(attacker.last_seen)}</span>
                      </div>
                      <div className="flex gap-1 mt-2">
                        {attacker.honeypots.map((hp: string) => (
                          <span
                            key={hp}
                            className="px-2 py-0.5 rounded-full text-xs"
                            style={{ backgroundColor: `${HONEYPOT_COLORS[hp]}20`, color: HONEYPOT_COLORS[hp] }}
                          >
                            {HONEYPOT_ICONS[hp]}
                          </span>
                        ))}
                      </div>
                    </button>
                  ))}
                </div>
              ) : (
                /* Cross-Honeypot View */
                threatIntelLoading ? (
                  <div className="h-full flex items-center justify-center">
                    <LoadingSpinner />
                  </div>
                ) : (
                  <div className="divide-y divide-bg-hover">
                    {threatIntel?.cross_honeypot_actors?.map((actor, index) => (
                      <button
                        key={actor.ip}
                        onClick={() => setSelectedAttacker(actor.ip)}
                        className="w-full p-4 text-left hover:bg-bg-hover transition-colors"
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono text-text-muted w-6">#{index + 1}</span>
                            <span className="font-mono text-neon-purple">{actor.ip}</span>
                          </div>
                          <span className="px-2 py-0.5 rounded-full text-xs bg-neon-purple/20 text-neon-purple">
                            {actor.honeypot_count} honeypots
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-sm mb-2">
                          <span className="text-neon-orange">{formatNumber(actor.total_events)} events</span>
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {actor.honeypots.map((hp: string) => (
                            <span
                              key={hp}
                              className="px-2 py-0.5 rounded-full text-xs"
                              style={{ backgroundColor: `${HONEYPOT_COLORS[hp]}20`, color: HONEYPOT_COLORS[hp] }}
                            >
                              {HONEYPOT_ICONS[hp]} {hp}
                            </span>
                          ))}
                        </div>
                      </button>
                    ))}
                    {(!threatIntel?.cross_honeypot_actors || threatIntel.cross_honeypot_actors.length === 0) && (
                      <div className="p-8 text-center text-text-muted">
                        No cross-honeypot attackers found
                      </div>
                    )}
                  </div>
                )
              )}
            </CardContent>
          </Card>
        </div>

        {/* Country Details Panel */}
        <div className="lg:col-span-2">
          {selectedCountry ? (
            <Card className="h-[700px] flex flex-col">
              <div className="p-4 border-b border-bg-hover">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-2xl">{getCountryFlag(selectedCountry)}</span>
                    <h3 className="text-lg font-display font-semibold text-text-primary">{selectedCountry}</h3>
                  </div>
                  <button
                    onClick={() => setSelectedCountry(null)}
                    className="text-text-muted hover:text-text-primary"
                  >
                    ✕
                  </button>
                </div>
                <p className="text-sm text-text-secondary mt-1">
                  {countryAttackersData 
                    ? `${countryAttackersData.total_attackers} attackers · ${formatNumber(countryAttackersData.total_events)} events`
                    : 'Loading...'
                  }
                </p>
              </div>
              <CardContent className="flex-1 overflow-y-auto">
                {countryAttackersLoading ? (
                  <div className="h-full flex items-center justify-center">
                    <LoadingSpinner />
                  </div>
                ) : countryAttackersData?.attackers ? (
                  <div className="space-y-3">
                    {countryAttackersData.attackers.map((attacker: CountryAttacker, index: number) => (
                      <div
                        key={attacker.ip}
                        className="p-4 bg-bg-secondary rounded-lg hover:bg-bg-hover transition-colors cursor-pointer"
                        onClick={() => setSelectedAttacker(attacker.ip)}
                      >
                        <div className="flex items-start justify-between mb-3">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-xs font-mono text-text-muted">#{index + 1}</span>
                              <span className="font-mono text-lg text-neon-green">{attacker.ip}</span>
                              <Eye className="w-4 h-4 text-text-muted hover:text-neon-blue cursor-pointer" />
                            </div>
                            {attacker.city && (
                              <div className="flex items-center gap-1 text-sm text-text-secondary">
                                <MapPin className="w-3 h-3" />
                                {attacker.city}
                              </div>
                            )}
                          </div>
                          <div className="text-right">
                            <div className="text-2xl font-display font-bold text-neon-orange">
                              {formatNumber(attacker.total_events)}
                            </div>
                            <div className="text-xs text-text-muted">events</div>
                          </div>
                        </div>

                        <div className="flex flex-wrap gap-2 mb-3">
                          {Object.entries(attacker.honeypot_details).map(([hp, data]: [string, { events: number; color: string }]) => (
                            <div
                              key={hp}
                              className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
                              style={{ backgroundColor: `${data.color}15` }}
                            >
                              <span>{HONEYPOT_ICONS[hp]}</span>
                              <span className="text-sm capitalize" style={{ color: data.color }}>{hp}</span>
                              <span className="font-mono text-xs text-text-muted">{data.events}</span>
                            </div>
                          ))}
                        </div>

                        <div className="flex items-center justify-between text-xs text-text-muted">
                          <div className="flex items-center gap-4">
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              First: {new Date(attacker.first_seen).toLocaleDateString()}
                            </span>
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              Last: {formatTimeAgo(attacker.last_seen)}
                            </span>
                          </div>
                          <div className="flex items-center gap-1 text-neon-blue">
                            View Profile <ExternalLink className="w-3 h-3" />
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="h-full flex items-center justify-center text-text-secondary">
                    No attackers found for this country
                  </div>
                )}
              </CardContent>
            </Card>
          ) : (
            <Card className="h-[700px] flex flex-col">
              <CardContent className="flex-1 flex items-center justify-center">
                <div className="text-center">
                  <div className="w-20 h-20 mx-auto mb-4 rounded-full bg-bg-secondary flex items-center justify-center">
                    <Globe className="w-10 h-10 text-text-muted" />
                  </div>
                  <h3 className="text-lg font-medium text-text-primary mb-2">Select a Country</h3>
                  <p className="text-text-secondary text-sm max-w-xs">
                    Click on a country from the list to view detailed attacker information and profiles
                  </p>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* Attacker Profile Modal */}
      {selectedAttacker && (
        <AttackerModal
          ip={selectedAttacker}
          onClose={() => setSelectedAttacker(null)}
        />
      )}
    </div>
  );
};

export default Attackers;

