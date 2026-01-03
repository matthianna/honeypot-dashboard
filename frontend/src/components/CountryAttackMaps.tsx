import { useState, useEffect, useMemo } from 'react';
import { ComposableMap, Geographies, Geography, ZoomableGroup } from 'react-simple-maps';
import { scaleLinear } from 'd3-scale';
import { Globe, TrendingUp, Shield, Server } from 'lucide-react';
import api from '../services/api';
import LoadingSpinner from './LoadingSpinner';
import ExportButton from './ExportButton';

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

// Country name to ISO mapping for common mismatches
const COUNTRY_NAME_TO_ISO: Record<string, string> = {
  'United States': 'USA',
  'United Kingdom': 'GBR',
  'Russia': 'RUS',
  'China': 'CHN',
  'South Korea': 'KOR',
  'North Korea': 'PRK',
  'Vietnam': 'VNM',
  'Taiwan': 'TWN',
  'Iran': 'IRN',
  'The Netherlands': 'NLD',
  'Netherlands': 'NLD',
  'Germany': 'DEU',
  'France': 'FRA',
  'Brazil': 'BRA',
  'India': 'IND',
  'Indonesia': 'IDN',
  'Japan': 'JPN',
  'Canada': 'CAN',
  'Australia': 'AUS',
  'Mexico': 'MEX',
  'Singapore': 'SGP',
  'Hong Kong': 'HKG',
  'Thailand': 'THA',
  'Malaysia': 'MYS',
  'Philippines': 'PHL',
  'Ukraine': 'UKR',
  'Poland': 'POL',
  'Romania': 'ROU',
  'Bulgaria': 'BGR',
  'Czech Republic': 'CZE',
  'Czechia': 'CZE',
  'Hungary': 'HUN',
  'Argentina': 'ARG',
  'Chile': 'CHL',
  'Colombia': 'COL',
  'Peru': 'PER',
  'Venezuela': 'VEN',
  'South Africa': 'ZAF',
  'Egypt': 'EGY',
  'Nigeria': 'NGA',
  'Kenya': 'KEN',
  'Morocco': 'MAR',
  'Turkey': 'TUR',
  'Saudi Arabia': 'SAU',
  'United Arab Emirates': 'ARE',
  'Israel': 'ISR',
  'Pakistan': 'PAK',
  'Bangladesh': 'BGD',
  'Sri Lanka': 'LKA',
  'Nepal': 'NPL',
  'New Zealand': 'NZL',
  'Ireland': 'IRL',
  'Belgium': 'BEL',
  'Austria': 'AUT',
  'Switzerland': 'CHE',
  'Sweden': 'SWE',
  'Norway': 'NOR',
  'Denmark': 'DNK',
  'Finland': 'FIN',
  'Spain': 'ESP',
  'Portugal': 'PRT',
  'Italy': 'ITA',
  'Greece': 'GRC',
};

interface CountryData {
  country: string;
  count: number;
  percentage?: number;
}

interface HoneypotGeoData {
  honeypot: string;
  color: string;
  countries: CountryData[];
  total: number;
}

interface TooltipData {
  name: string;
  x: number;
  y: number;
  data: {
    honeypot: string;
    color: string;
    count: number;
    percentage: number;
  }[];
  total: number;
}

const HONEYPOT_COLORS: Record<string, string> = {
  cowrie: '#39ff14',
  dionaea: '#00d4ff',
  galah: '#ff6600',
  rdpy: '#bf00ff',
  heralding: '#ff3366',
};

// Global attack heatmap
export function GlobalAttackHeatmap() {
  const [geoData, setGeoData] = useState<CountryData[]>([]);
  const [loading, setLoading] = useState(true);
  const [tooltip, setTooltip] = useState<TooltipData | null>(null);
  const [totalAttacks, setTotalAttacks] = useState(0);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await api.getGeoDistribution('30d');
        const data = response.data || [];
        const total = data.reduce((sum: number, c: CountryData) => sum + c.count, 0);
        setTotalAttacks(total);
        setGeoData(data.map((c: CountryData) => ({
          ...c,
          percentage: total > 0 ? (c.count / total) * 100 : 0
        })));
      } catch (err) {
        console.error('Failed to fetch geo data:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const colorScale = useMemo(() => {
    const maxCount = Math.max(...geoData.map(c => c.count), 1);
    return scaleLinear<string>()
      .domain([0, maxCount * 0.1, maxCount * 0.5, maxCount])
      .range(['#1a1a2e', '#2d1f3d', '#6b2d5b', '#ff3366']);
  }, [geoData]);

  const getCountryData = (geoName: string): CountryData | undefined => {
    // Try direct match first
    let data = geoData.find(c => c.country === geoName);
    if (data) return data;
    
    // Try ISO code match
    const iso = COUNTRY_NAME_TO_ISO[geoName];
    if (iso) {
      data = geoData.find(c => c.country === iso || COUNTRY_NAME_TO_ISO[c.country] === iso);
    }
    return data;
  };

  if (loading) {
    return (
      <div className="h-96 flex items-center justify-center bg-bg-secondary rounded-xl">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="bg-bg-secondary rounded-xl border border-bg-hover overflow-hidden">
      <div className="px-4 py-3 border-b border-bg-hover flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="w-5 h-5 text-neon-pink" />
          <h3 className="font-display font-bold text-text-primary">Global Attack Heatmap</h3>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-sm text-text-muted">Last 30 days • {totalAttacks.toLocaleString()} attacks</span>
          <ExportButton 
            data={geoData}
            filename="global_attacks_by_country"
            timeRange="30d"
            disabled={loading || geoData.length === 0}
          />
        </div>
      </div>
      
      <div className="relative h-80">
        <ComposableMap
          projection="geoMercator"
          projectionConfig={{ scale: 120, center: [0, 20] }}
          style={{ width: '100%', height: '100%' }}
        >
          <ZoomableGroup>
            <Geographies geography={GEO_URL}>
              {({ geographies }) =>
                geographies.map(geo => {
                  const geoName = geo.properties.name as string;
                  const countryData = getCountryData(geoName);
                  const fillColor = countryData ? colorScale(countryData.count) : '#1a1a2e';
                  
                  return (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill={fillColor}
                      stroke="#2a2a4a"
                      strokeWidth={0.5}
                      style={{
                        default: { outline: 'none' },
                        hover: { outline: 'none', fill: countryData ? '#ff6600' : '#252545', cursor: 'pointer' },
                        pressed: { outline: 'none' },
                      }}
                      onMouseEnter={(evt) => {
                        if (countryData) {
                          setTooltip({
                            name: geoName,
                            x: evt.clientX,
                            y: evt.clientY,
                            data: [{
                              honeypot: 'All',
                              color: '#ff3366',
                              count: countryData.count,
                              percentage: countryData.percentage || 0
                            }],
                            total: countryData.count
                          });
                        }
                      }}
                      onMouseLeave={() => setTooltip(null)}
                    />
                  );
                })
              }
            </Geographies>
          </ZoomableGroup>
        </ComposableMap>
        
        {/* Tooltip */}
        {tooltip && (
          <div
            className="fixed z-50 bg-bg-card border border-bg-hover rounded-lg shadow-xl p-3 pointer-events-none"
            style={{ left: tooltip.x + 10, top: tooltip.y - 10 }}
          >
            <div className="font-bold text-text-primary mb-2">{tooltip.name}</div>
            <div className="text-sm text-text-secondary">
              <div className="flex justify-between gap-4">
                <span>Attacks:</span>
                <span className="font-mono text-neon-pink">{tooltip.total.toLocaleString()}</span>
              </div>
              <div className="flex justify-between gap-4">
                <span>Percentage:</span>
                <span className="font-mono text-neon-orange">{tooltip.data[0]?.percentage.toFixed(2)}%</span>
              </div>
            </div>
          </div>
        )}
        
        {/* Legend */}
        <div className="absolute bottom-4 left-4 bg-black/70 backdrop-blur-sm rounded-lg p-3">
          <div className="text-xs text-text-muted mb-2">Attack Intensity</div>
          <div className="flex items-center gap-1">
            <div className="w-4 h-3 rounded" style={{ backgroundColor: '#1a1a2e' }} />
            <div className="w-4 h-3 rounded" style={{ backgroundColor: '#2d1f3d' }} />
            <div className="w-4 h-3 rounded" style={{ backgroundColor: '#6b2d5b' }} />
            <div className="w-4 h-3 rounded" style={{ backgroundColor: '#ff3366' }} />
          </div>
          <div className="flex justify-between text-xs text-text-muted mt-1">
            <span>Low</span>
            <span>High</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// Per-honeypot attack maps
export function HoneypotAttackMaps() {
  const [honeypotData, setHoneypotData] = useState<HoneypotGeoData[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedHoneypot, setSelectedHoneypot] = useState<string>('cowrie');
  const [tooltip, setTooltip] = useState<TooltipData | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Fetch geo data for each honeypot
        const honeypots = ['cowrie', 'dionaea', 'galah', 'rdpy', 'heralding'];
        const results = await Promise.all(
          honeypots.map(async (hp) => {
            try {
              const response = await api.getHoneypotGeoDistribution(hp, '30d');
              const countries = response.data || [];
              const total = countries.reduce((sum: number, c: CountryData) => sum + c.count, 0);
              return {
                honeypot: hp,
                color: HONEYPOT_COLORS[hp],
                countries: countries.map((c: CountryData) => ({
                  ...c,
                  percentage: total > 0 ? (c.count / total) * 100 : 0
                })),
                total
              };
            } catch {
              return { honeypot: hp, color: HONEYPOT_COLORS[hp], countries: [], total: 0 };
            }
          })
        );
        setHoneypotData(results);
      } catch (err) {
        console.error('Failed to fetch honeypot geo data:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const currentData = honeypotData.find(h => h.honeypot === selectedHoneypot);

  const colorScale = useMemo(() => {
    if (!currentData) return scaleLinear<string>().domain([0, 1]).range(['#1a1a2e', '#1a1a2e']);
    const maxCount = Math.max(...currentData.countries.map(c => c.count), 1);
    const color = HONEYPOT_COLORS[selectedHoneypot];
    return scaleLinear<string>()
      .domain([0, maxCount * 0.1, maxCount * 0.5, maxCount])
      .range(['#1a1a2e', '#252545', color + '66', color]);
  }, [currentData, selectedHoneypot]);

  const getCountryData = (geoName: string): CountryData | undefined => {
    if (!currentData) return undefined;
    let data = currentData.countries.find(c => c.country === geoName);
    if (data) return data;
    
    const iso = COUNTRY_NAME_TO_ISO[geoName];
    if (iso) {
      data = currentData.countries.find(c => c.country === iso || COUNTRY_NAME_TO_ISO[c.country] === iso);
    }
    return data;
  };

  if (loading) {
    return (
      <div className="h-96 flex items-center justify-center bg-bg-secondary rounded-xl">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="bg-bg-secondary rounded-xl border border-bg-hover overflow-hidden">
      <div className="px-4 py-3 border-b border-bg-hover flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <Server className="w-5 h-5 text-neon-blue" />
          <h3 className="font-display font-bold text-text-primary">Attacks by Honeypot</h3>
        </div>
        
        {/* Honeypot selector */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex gap-2 flex-wrap">
            {honeypotData.map(hp => (
              <button
                key={hp.honeypot}
                onClick={() => setSelectedHoneypot(hp.honeypot)}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
                  selectedHoneypot === hp.honeypot
                    ? 'ring-2 ring-offset-2 ring-offset-bg-secondary'
                    : 'opacity-60 hover:opacity-100'
                }`}
                style={{
                  backgroundColor: selectedHoneypot === hp.honeypot ? hp.color + '33' : 'transparent',
                  color: hp.color,
                  borderColor: hp.color,
                  border: '1px solid',
                  boxShadow: selectedHoneypot === hp.honeypot ? `0 0 10px ${hp.color}40` : 'none'
                }}
              >
                {hp.honeypot.charAt(0).toUpperCase() + hp.honeypot.slice(1)}
                <span className="ml-2 opacity-70">({hp.total.toLocaleString()})</span>
              </button>
            ))}
          </div>
          <ExportButton 
            data={currentData?.countries || []}
            filename={`${selectedHoneypot}_attacks_by_country`}
            timeRange="30d"
            disabled={loading || !currentData || currentData.countries.length === 0}
          />
        </div>
      </div>
      
      <div className="relative h-80">
        <ComposableMap
          projection="geoMercator"
          projectionConfig={{ scale: 120, center: [0, 20] }}
          style={{ width: '100%', height: '100%' }}
        >
          <ZoomableGroup>
            <Geographies geography={GEO_URL}>
              {({ geographies }) =>
                geographies.map(geo => {
                  const geoName = geo.properties.name as string;
                  const countryData = getCountryData(geoName);
                  const fillColor = countryData ? colorScale(countryData.count) : '#1a1a2e';
                  
                  return (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill={fillColor}
                      stroke="#2a2a4a"
                      strokeWidth={0.5}
                      style={{
                        default: { outline: 'none' },
                        hover: { outline: 'none', fill: countryData ? HONEYPOT_COLORS[selectedHoneypot] : '#252545', cursor: 'pointer' },
                        pressed: { outline: 'none' },
                      }}
                      onMouseEnter={(evt) => {
                        if (countryData) {
                          setTooltip({
                            name: geoName,
                            x: evt.clientX,
                            y: evt.clientY,
                            data: [{
                              honeypot: selectedHoneypot,
                              color: HONEYPOT_COLORS[selectedHoneypot],
                              count: countryData.count,
                              percentage: countryData.percentage || 0
                            }],
                            total: countryData.count
                          });
                        }
                      }}
                      onMouseLeave={() => setTooltip(null)}
                    />
                  );
                })
              }
            </Geographies>
          </ZoomableGroup>
        </ComposableMap>
        
        {/* Tooltip */}
        {tooltip && (
          <div
            className="fixed z-50 bg-bg-card border border-bg-hover rounded-lg shadow-xl p-3 pointer-events-none"
            style={{ left: tooltip.x + 10, top: tooltip.y - 10 }}
          >
            <div className="font-bold text-text-primary mb-2">{tooltip.name}</div>
            <div className="space-y-1">
              {tooltip.data.map((d, i) => (
                <div key={i} className="text-sm flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} />
                  <span className="text-text-secondary capitalize">{d.honeypot}:</span>
                  <span className="font-mono" style={{ color: d.color }}>{d.count.toLocaleString()}</span>
                  <span className="text-text-muted">({d.percentage.toFixed(2)}%)</span>
                </div>
              ))}
            </div>
          </div>
        )}
        
        {/* Top countries list */}
        {currentData && currentData.countries.length > 0 && (
          <div className="absolute top-4 right-4 bg-black/70 backdrop-blur-sm rounded-lg p-3 max-h-64 overflow-y-auto">
            <div className="text-xs text-text-muted mb-2 uppercase tracking-wide">Top Countries</div>
            <div className="space-y-1">
              {currentData.countries.slice(0, 10).map((c, i) => (
                <div key={c.country} className="flex items-center justify-between gap-3 text-sm">
                  <span className="text-text-secondary">{i + 1}. {c.country}</span>
                  <div className="flex items-center gap-2">
                    <span className="font-mono" style={{ color: HONEYPOT_COLORS[selectedHoneypot] }}>
                      {c.count.toLocaleString()}
                    </span>
                    <span className="text-text-muted text-xs">({c.percentage?.toFixed(1)}%)</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// Combined view showing all honeypots on hover
export function CombinedHoneypotMap() {
  const [allData, setAllData] = useState<Record<string, HoneypotGeoData>>({});
  const [loading, setLoading] = useState(true);
  const [tooltip, setTooltip] = useState<TooltipData | null>(null);
  const [totalByCountry, setTotalByCountry] = useState<Record<string, number>>({});

  useEffect(() => {
    const fetchData = async () => {
      try {
        const honeypots = ['cowrie', 'dionaea', 'galah', 'rdpy', 'heralding'];
        const results: Record<string, HoneypotGeoData> = {};
        const totals: Record<string, number> = {};
        
        await Promise.all(
          honeypots.map(async (hp) => {
            try {
              const response = await api.getHoneypotGeoDistribution(hp, '30d');
              const countries = response.data || [];
              const total = countries.reduce((sum: number, c: CountryData) => sum + c.count, 0);
              
              results[hp] = {
                honeypot: hp,
                color: HONEYPOT_COLORS[hp],
                countries: countries.map((c: CountryData) => ({
                  ...c,
                  percentage: total > 0 ? (c.count / total) * 100 : 0
                })),
                total
              };
              
              // Aggregate totals by country
              countries.forEach((c: CountryData) => {
                totals[c.country] = (totals[c.country] || 0) + c.count;
              });
            } catch {
              results[hp] = { honeypot: hp, color: HONEYPOT_COLORS[hp], countries: [], total: 0 };
            }
          })
        );
        
        setAllData(results);
        setTotalByCountry(totals);
      } catch (err) {
        console.error('Failed to fetch combined geo data:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const colorScale = useMemo(() => {
    const maxCount = Math.max(...Object.values(totalByCountry), 1);
    return scaleLinear<string>()
      .domain([0, maxCount * 0.1, maxCount * 0.5, maxCount])
      .range(['#1a1a2e', '#252545', '#3d3d6d', '#6b6bff']);
  }, [totalByCountry]);

  const getCountryDetails = (geoName: string) => {
    const honeypots = ['cowrie', 'dionaea', 'galah', 'rdpy', 'heralding'];
    const details: { honeypot: string; color: string; count: number; percentage: number }[] = [];
    let total = 0;
    
    honeypots.forEach(hp => {
      const hpData = allData[hp];
      if (!hpData) return;
      
      let countryData = hpData.countries.find(c => c.country === geoName);
      if (!countryData) {
        const iso = COUNTRY_NAME_TO_ISO[geoName];
        if (iso) {
          countryData = hpData.countries.find(c => c.country === iso || COUNTRY_NAME_TO_ISO[c.country] === iso);
        }
      }
      
      if (countryData) {
        details.push({
          honeypot: hp,
          color: HONEYPOT_COLORS[hp],
          count: countryData.count,
          percentage: countryData.percentage || 0
        });
        total += countryData.count;
      }
    });
    
    return { details, total };
  };

  if (loading) {
    return (
      <div className="h-96 flex items-center justify-center bg-bg-secondary rounded-xl">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="bg-bg-secondary rounded-xl border border-bg-hover overflow-hidden">
      <div className="px-4 py-3 border-b border-bg-hover flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-neon-purple" />
          <h3 className="font-display font-bold text-text-primary">Combined Attack Sources</h3>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-sm text-text-muted">Hover to see breakdown by honeypot</span>
          <ExportButton 
            data={Object.entries(totalByCountry).map(([country, count]) => ({ country, count }))}
            filename="combined_attacks_by_country"
            timeRange="30d"
            disabled={loading || Object.keys(totalByCountry).length === 0}
          />
        </div>
      </div>
      
      <div className="relative h-80">
        <ComposableMap
          projection="geoMercator"
          projectionConfig={{ scale: 120, center: [0, 20] }}
          style={{ width: '100%', height: '100%' }}
        >
          <ZoomableGroup>
            <Geographies geography={GEO_URL}>
              {({ geographies }) =>
                geographies.map(geo => {
                  const geoName = geo.properties.name as string;
                  const countryTotal = totalByCountry[geoName] || 
                    totalByCountry[COUNTRY_NAME_TO_ISO[geoName] || ''] || 0;
                  const fillColor = countryTotal > 0 ? colorScale(countryTotal) : '#1a1a2e';
                  
                  return (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill={fillColor}
                      stroke="#2a2a4a"
                      strokeWidth={0.5}
                      style={{
                        default: { outline: 'none' },
                        hover: { outline: 'none', fill: countryTotal > 0 ? '#8b5cf6' : '#252545', cursor: 'pointer' },
                        pressed: { outline: 'none' },
                      }}
                      onMouseEnter={(evt) => {
                        const { details, total } = getCountryDetails(geoName);
                        if (total > 0) {
                          setTooltip({
                            name: geoName,
                            x: evt.clientX,
                            y: evt.clientY,
                            data: details.sort((a, b) => b.count - a.count),
                            total
                          });
                        }
                      }}
                      onMouseLeave={() => setTooltip(null)}
                    />
                  );
                })
              }
            </Geographies>
          </ZoomableGroup>
        </ComposableMap>
        
        {/* Tooltip with honeypot breakdown */}
        {tooltip && (
          <div
            className="fixed z-50 bg-bg-card border border-bg-hover rounded-lg shadow-xl p-4 pointer-events-none min-w-48"
            style={{ left: tooltip.x + 10, top: tooltip.y - 10 }}
          >
            <div className="font-bold text-text-primary mb-2 pb-2 border-b border-bg-hover">
              {tooltip.name}
              <span className="ml-2 text-sm font-normal text-text-muted">
                ({tooltip.total.toLocaleString()} total)
              </span>
            </div>
            <div className="space-y-2">
              {tooltip.data.map((d, i) => (
                <div key={i} className="flex items-center justify-between gap-4">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: d.color }} />
                    <span className="text-text-secondary capitalize">{d.honeypot}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm" style={{ color: d.color }}>
                      {d.count.toLocaleString()}
                    </span>
                    <span className="text-text-muted text-xs">
                      ({((d.count / tooltip.total) * 100).toFixed(1)}%)
                    </span>
                  </div>
                </div>
              ))}
            </div>
            
            {/* Progress bars */}
            <div className="mt-3 pt-2 border-t border-bg-hover space-y-1">
              {tooltip.data.map((d, i) => (
                <div key={i} className="h-1.5 bg-bg-hover rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{
                      width: `${(d.count / tooltip.total) * 100}%`,
                      backgroundColor: d.color
                    }}
                  />
                </div>
              ))}
            </div>
          </div>
        )}
        
        {/* Legend */}
        <div className="absolute bottom-4 left-4 bg-black/70 backdrop-blur-sm rounded-lg p-3">
          <div className="text-xs text-text-muted mb-2">Honeypot Legend</div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1">
            {Object.entries(HONEYPOT_COLORS).map(([hp, color]) => (
              <div key={hp} className="flex items-center gap-2 text-xs">
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                <span className="text-text-secondary capitalize">{hp}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// Attack trend by region
export function AttackTrendMap() {
  const [geoData, setGeoData] = useState<CountryData[]>([]);
  const [loading, setLoading] = useState(true);
  const [tooltip, setTooltip] = useState<TooltipData | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await api.getGeoDistribution('7d');
        setGeoData(response.data || []);
      } catch (err) {
        console.error('Failed to fetch trend data:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const totalAttacks = geoData.reduce((sum, c) => sum + c.count, 0);

  const colorScale = useMemo(() => {
    const maxCount = Math.max(...geoData.map(c => c.count), 1);
    return scaleLinear<string>()
      .domain([0, maxCount * 0.2, maxCount])
      .range(['#1a1a2e', '#2d4a2d', '#39ff14']);
  }, [geoData]);

  const getCountryData = (geoName: string): CountryData | undefined => {
    let data = geoData.find(c => c.country === geoName);
    if (data) return data;
    
    const iso = COUNTRY_NAME_TO_ISO[geoName];
    if (iso) {
      data = geoData.find(c => c.country === iso || COUNTRY_NAME_TO_ISO[c.country] === iso);
    }
    return data;
  };

  if (loading) {
    return (
      <div className="h-96 flex items-center justify-center bg-bg-secondary rounded-xl">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="bg-bg-secondary rounded-xl border border-bg-hover overflow-hidden">
      <div className="px-4 py-3 border-b border-bg-hover flex items-center justify-between">
        <div className="flex items-center gap-2">
          <TrendingUp className="w-5 h-5 text-neon-green" />
          <h3 className="font-display font-bold text-text-primary">Weekly Attack Trends</h3>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-sm text-text-muted">Last 7 days • {totalAttacks.toLocaleString()} attacks</span>
          <ExportButton 
            data={geoData}
            filename="weekly_attack_trends"
            timeRange="7d"
            disabled={loading || geoData.length === 0}
          />
        </div>
      </div>
      
      <div className="relative h-80">
        <ComposableMap
          projection="geoMercator"
          projectionConfig={{ scale: 120, center: [0, 20] }}
          style={{ width: '100%', height: '100%' }}
        >
          <ZoomableGroup>
            <Geographies geography={GEO_URL}>
              {({ geographies }) =>
                geographies.map(geo => {
                  const geoName = geo.properties.name as string;
                  const countryData = getCountryData(geoName);
                  const fillColor = countryData ? colorScale(countryData.count) : '#1a1a2e';
                  
                  return (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill={fillColor}
                      stroke="#2a2a4a"
                      strokeWidth={0.5}
                      style={{
                        default: { outline: 'none' },
                        hover: { outline: 'none', fill: countryData ? '#39ff14' : '#252545', cursor: 'pointer' },
                        pressed: { outline: 'none' },
                      }}
                      onMouseEnter={(evt) => {
                        if (countryData) {
                          const percentage = totalAttacks > 0 ? (countryData.count / totalAttacks) * 100 : 0;
                          setTooltip({
                            name: geoName,
                            x: evt.clientX,
                            y: evt.clientY,
                            data: [{
                              honeypot: 'All',
                              color: '#39ff14',
                              count: countryData.count,
                              percentage
                            }],
                            total: countryData.count
                          });
                        }
                      }}
                      onMouseLeave={() => setTooltip(null)}
                    />
                  );
                })
              }
            </Geographies>
          </ZoomableGroup>
        </ComposableMap>
        
        {/* Tooltip */}
        {tooltip && (
          <div
            className="fixed z-50 bg-bg-card border border-bg-hover rounded-lg shadow-xl p-3 pointer-events-none"
            style={{ left: tooltip.x + 10, top: tooltip.y - 10 }}
          >
            <div className="font-bold text-text-primary mb-2">{tooltip.name}</div>
            <div className="text-sm text-text-secondary space-y-1">
              <div className="flex justify-between gap-4">
                <span>Attacks (7d):</span>
                <span className="font-mono text-neon-green">{tooltip.total.toLocaleString()}</span>
              </div>
              <div className="flex justify-between gap-4">
                <span>Share:</span>
                <span className="font-mono text-neon-blue">{tooltip.data[0]?.percentage.toFixed(2)}%</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

