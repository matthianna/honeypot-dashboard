import { useState, useEffect, useMemo } from 'react';
import { MapContainer, TileLayer, CircleMarker, Tooltip, useMap } from 'react-leaflet';
import { scaleLinear, scaleSqrt } from 'd3-scale';
import { Globe, Filter } from 'lucide-react';
import api from '../services/api';
import LoadingSpinner from './LoadingSpinner';
import TimeRangeSelector from './TimeRangeSelector';
import TileLayerSwitcher, { TILE_LAYERS, type TileLayerType } from './TileLayerSwitcher';
import ExportButton from './ExportButton';
import type { TimeRange } from '../types';
import 'leaflet/dist/leaflet.css';

// Country coordinates (capitals/major cities)
const COUNTRY_COORDS: Record<string, [number, number]> = {
  'China': [35.8617, 104.1954],
  'United States': [37.0902, -95.7129],
  'Russia': [61.5240, 105.3188],
  'Brazil': [-14.2350, -51.9253],
  'India': [20.5937, 78.9629],
  'Germany': [51.1657, 10.4515],
  'Netherlands': [52.1326, 5.2913],
  'The Netherlands': [52.1326, 5.2913],
  'France': [46.2276, 2.2137],
  'United Kingdom': [55.3781, -3.4360],
  'Japan': [36.2048, 138.2529],
  'South Korea': [35.9078, 127.7669],
  'Vietnam': [14.0583, 108.2772],
  'Indonesia': [-0.7893, 113.9213],
  'Thailand': [15.8700, 100.9925],
  'Taiwan': [23.6978, 120.9605],
  'Singapore': [1.3521, 103.8198],
  'Hong Kong': [22.3193, 114.1694],
  'Malaysia': [4.2105, 101.9758],
  'Philippines': [12.8797, 121.7740],
  'Australia': [-25.2744, 133.7751],
  'Canada': [56.1304, -106.3468],
  'Mexico': [23.6345, -102.5528],
  'Argentina': [-38.4161, -63.6167],
  'Chile': [-35.6751, -71.5430],
  'Colombia': [4.5709, -74.2973],
  'Peru': [-9.1900, -75.0152],
  'Venezuela': [6.4238, -66.5897],
  'Ukraine': [48.3794, 31.1656],
  'Poland': [51.9194, 19.1451],
  'Romania': [45.9432, 24.9668],
  'Bulgaria': [42.7339, 25.4858],
  'Turkey': [38.9637, 35.2433],
  'Iran': [32.4279, 53.6880],
  'Saudi Arabia': [23.8859, 45.0792],
  'United Arab Emirates': [23.4241, 53.8478],
  'Israel': [31.0461, 34.8516],
  'Egypt': [26.8206, 30.8025],
  'South Africa': [-30.5595, 22.9375],
  'Nigeria': [9.0820, 8.6753],
  'Kenya': [-0.0236, 37.9062],
  'Morocco': [31.7917, -7.0926],
  'Pakistan': [30.3753, 69.3451],
  'Bangladesh': [23.6850, 90.3563],
  'Italy': [41.8719, 12.5674],
  'Spain': [40.4637, -3.7492],
  'Portugal': [39.3999, -8.2245],
  'Greece': [39.0742, 21.8243],
  'Sweden': [60.1282, 18.6435],
  'Norway': [60.4720, 8.4689],
  'Denmark': [56.2639, 9.5018],
  'Finland': [61.9241, 25.7482],
  'Belgium': [50.5039, 4.4699],
  'Austria': [47.5162, 14.5501],
  'Switzerland': [46.8182, 8.2275],
  'Ireland': [53.4129, -8.2439],
  'New Zealand': [-40.9006, 174.8860],
  'Czech Republic': [49.8175, 15.4730],
  'Czechia': [49.8175, 15.4730],
  'Hungary': [47.1625, 19.5033],
};

const HONEYPOT_COLORS: Record<string, string> = {
  cowrie: '#39ff14',
  dionaea: '#00d4ff',
  galah: '#ff6600',
  rdpy: '#bf00ff',
  heralding: '#ff3366',
  all: '#8b5cf6',
};

interface CountryData {
  country: string;
  count: number;
  percentage?: number;
  coords?: [number, number];
}

interface HoneypotData {
  honeypot: string;
  countries: CountryData[];
  total: number;
}

// Component to update map view
function MapUpdater({ center, zoom }: { center: [number, number]; zoom: number }) {
  const map = useMap();
  useEffect(() => {
    map.setView(center, zoom);
  }, [map, center, zoom]);
  return null;
}

export default function LeafletGeoMap() {
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<HoneypotData[]>([]);
  const [selectedHoneypot, setSelectedHoneypot] = useState<string>('all');
  const [tileLayer, setTileLayer] = useState<TileLayerType>('dark');
  const [showLayerSwitcher, setShowLayerSwitcher] = useState(false);
  const [mapCenter] = useState<[number, number]>([30, 10]);
  const [mapZoom] = useState(2);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const honeypots = ['cowrie', 'dionaea', 'galah', 'rdpy', 'heralding'];
        const results = await Promise.all(
          honeypots.map(async (hp) => {
            try {
              const response = await api.getHoneypotGeoDistribution(hp, timeRange);
              const countries = response.data || [];
              const total = countries.reduce((sum: number, c: CountryData) => sum + c.count, 0);
              return {
                honeypot: hp,
                countries: countries.map((c: CountryData) => ({
                  ...c,
                  coords: COUNTRY_COORDS[c.country],
                  percentage: total > 0 ? (c.count / total) * 100 : 0
                })).filter((c: CountryData) => c.coords),
                total
              };
            } catch {
              return { honeypot: hp, countries: [], total: 0 };
            }
          })
        );
        setData(results);
      } catch (err) {
        console.error('Failed to fetch geo data:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [timeRange]);

  // Combine all honeypot data or filter by selected
  const displayData = useMemo(() => {
    if (selectedHoneypot === 'all') {
      // Aggregate all honeypots
      const countryMap = new Map<string, { count: number; coords: [number, number]; honeypots: Record<string, number> }>();
      
      data.forEach(hp => {
        hp.countries.forEach(c => {
          if (!c.coords) return;
          const existing = countryMap.get(c.country);
          if (existing) {
            existing.count += c.count;
            existing.honeypots[hp.honeypot] = c.count;
          } else {
            countryMap.set(c.country, {
              count: c.count,
              coords: c.coords,
              honeypots: { [hp.honeypot]: c.count }
            });
          }
        });
      });
      
      return Array.from(countryMap.entries()).map(([country, d]) => ({
        country,
        count: d.count,
        coords: d.coords,
        honeypots: d.honeypots,
      }));
    } else {
      const hpData = data.find(d => d.honeypot === selectedHoneypot);
      return hpData?.countries.map(c => ({
        country: c.country,
        count: c.count,
        coords: c.coords,
        honeypots: { [selectedHoneypot]: c.count },
      })) || [];
    }
  }, [data, selectedHoneypot]);

  const totalAttacks = useMemo(() => {
    return displayData.reduce((sum, d) => sum + d.count, 0);
  }, [displayData]);

  // Radius scale based on attack count
  const radiusScale = useMemo(() => {
    const maxCount = Math.max(...displayData.map(d => d.count), 1);
    return scaleSqrt().domain([0, maxCount]).range([5, 50]);
  }, [displayData]);

  // Color intensity based on attack count
  const colorScale = useMemo(() => {
    const maxCount = Math.max(...displayData.map(d => d.count), 1);
    return scaleLinear<number>().domain([0, maxCount]).range([0.3, 0.9]);
  }, [displayData]);

  const currentTileConfig = TILE_LAYERS[tileLayer];

  if (loading) {
    return (
      <div className="h-[500px] flex items-center justify-center bg-bg-secondary rounded-xl">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="bg-bg-secondary rounded-xl border border-bg-hover overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-bg-hover flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-neon-purple/20 rounded-lg">
            <Globe className="w-5 h-5 text-neon-purple" />
          </div>
          <div>
            <h3 className="font-display font-bold text-text-primary">Interactive Attack Map</h3>
            <p className="text-sm text-text-muted">
              {totalAttacks.toLocaleString()} attacks from {displayData.length} countries
            </p>
          </div>
        </div>
        
        <div className="flex items-center gap-3">
          <ExportButton 
            data={displayData}
            filename={`geo_attacks_${selectedHoneypot}`}
            timeRange={timeRange}
            disabled={loading || displayData.length === 0}
          />
          <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
        </div>
      </div>

      {/* Honeypot Filter */}
      <div className="px-4 py-3 border-b border-bg-hover flex items-center gap-3 flex-wrap">
        <Filter className="w-4 h-4 text-text-muted" />
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={() => setSelectedHoneypot('all')}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
              selectedHoneypot === 'all'
                ? 'bg-neon-purple/20 text-neon-purple ring-2 ring-neon-purple/50'
                : 'bg-bg-hover text-text-secondary hover:text-white'
            }`}
          >
            All Honeypots
          </button>
          {data.map(hp => (
            <button
              key={hp.honeypot}
              onClick={() => setSelectedHoneypot(hp.honeypot)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${
                selectedHoneypot === hp.honeypot
                  ? 'ring-2 ring-offset-1 ring-offset-bg-secondary'
                  : 'opacity-60 hover:opacity-100'
              }`}
              style={{
                backgroundColor: selectedHoneypot === hp.honeypot ? `${HONEYPOT_COLORS[hp.honeypot]}20` : 'transparent',
                color: HONEYPOT_COLORS[hp.honeypot],
                borderColor: HONEYPOT_COLORS[hp.honeypot],
                border: '1px solid',
              }}
            >
              <div 
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: HONEYPOT_COLORS[hp.honeypot] }}
              />
              {hp.honeypot.charAt(0).toUpperCase() + hp.honeypot.slice(1)}
              <span className="opacity-70">({hp.total.toLocaleString()})</span>
            </button>
          ))}
        </div>
      </div>

      {/* Map */}
      <div className="relative h-[500px]">
        <MapContainer
          center={mapCenter}
          zoom={mapZoom}
          style={{ width: '100%', height: '100%', background: '#0a0a1a' }}
          scrollWheelZoom={true}
          zoomControl={true}
        >
          <MapUpdater center={mapCenter} zoom={mapZoom} />
          <TileLayer
            attribution={currentTileConfig.attribution}
            url={currentTileConfig.url}
          />
          
          {/* Attack markers */}
          {displayData.map((country) => {
            if (!country.coords) return null;
            const radius = radiusScale(country.count);
            const opacity = colorScale(country.count);
            const color = selectedHoneypot === 'all' ? HONEYPOT_COLORS.all : HONEYPOT_COLORS[selectedHoneypot];
            
            return (
              <CircleMarker
                key={country.country}
                center={country.coords}
                radius={radius}
                pathOptions={{
                  color: color,
                  fillColor: color,
                  fillOpacity: opacity,
                  weight: 2,
                  opacity: 0.8,
                }}
              >
                <Tooltip 
                  permanent={false}
                  direction="top"
                  className="leaflet-tooltip-custom"
                >
                  <div className="bg-bg-card border border-bg-hover rounded-lg p-3 shadow-xl min-w-[200px]">
                    <div className="font-bold text-text-primary mb-2 pb-2 border-b border-bg-hover">
                      {country.country}
                    </div>
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-text-secondary">Total Attacks:</span>
                        <span className="font-mono text-neon-purple">{country.count.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-text-secondary">Share:</span>
                        <span className="font-mono text-neon-blue">
                          {totalAttacks > 0 ? ((country.count / totalAttacks) * 100).toFixed(2) : 0}%
                        </span>
                      </div>
                      {selectedHoneypot === 'all' && country.honeypots && (
                        <div className="pt-2 border-t border-bg-hover space-y-1">
                          {Object.entries(country.honeypots)
                            .sort(([,a], [,b]) => b - a)
                            .map(([hp, count]) => (
                              <div key={hp} className="flex items-center justify-between text-xs">
                                <div className="flex items-center gap-2">
                                  <div 
                                    className="w-2 h-2 rounded-full"
                                    style={{ backgroundColor: HONEYPOT_COLORS[hp] }}
                                  />
                                  <span className="text-text-secondary capitalize">{hp}</span>
                                </div>
                                <span className="font-mono" style={{ color: HONEYPOT_COLORS[hp] }}>
                                  {count.toLocaleString()}
                                </span>
                              </div>
                            ))
                          }
                        </div>
                      )}
                    </div>
                  </div>
                </Tooltip>
              </CircleMarker>
            );
          })}
        </MapContainer>
        
        {/* Layer Switcher */}
        <div className="absolute top-4 right-4 z-[1000]">
          <TileLayerSwitcher
            currentLayer={tileLayer}
            onChange={setTileLayer}
            isOpen={showLayerSwitcher}
            onToggle={() => setShowLayerSwitcher(!showLayerSwitcher)}
          />
        </div>

        {/* Legend */}
        <div className="absolute bottom-4 left-4 z-[1000] bg-black/70 backdrop-blur-sm rounded-lg p-3">
          <div className="text-xs text-text-muted mb-2">Circle Size = Attack Count</div>
          <div className="flex items-center gap-2">
            <div 
              className="w-4 h-4 rounded-full border-2"
              style={{ 
                borderColor: selectedHoneypot === 'all' ? HONEYPOT_COLORS.all : HONEYPOT_COLORS[selectedHoneypot],
                opacity: 0.5 
              }}
            />
            <span className="text-text-muted text-xs">Low</span>
            <div 
              className="w-8 h-8 rounded-full border-2"
              style={{ 
                borderColor: selectedHoneypot === 'all' ? HONEYPOT_COLORS.all : HONEYPOT_COLORS[selectedHoneypot],
                backgroundColor: `${selectedHoneypot === 'all' ? HONEYPOT_COLORS.all : HONEYPOT_COLORS[selectedHoneypot]}60`
              }}
            />
            <span className="text-text-muted text-xs">High</span>
          </div>
        </div>

        {/* Top Countries Panel */}
        <div className="absolute top-4 left-4 z-[1000] bg-black/80 backdrop-blur-sm rounded-lg p-3 max-h-64 overflow-y-auto">
          <div className="text-xs uppercase tracking-wider text-text-muted mb-2">Top Countries</div>
          <div className="space-y-1.5">
            {displayData
              .sort((a, b) => b.count - a.count)
              .slice(0, 8)
              .map((country, i) => (
                <div key={country.country} className="flex items-center justify-between gap-3 text-sm">
                  <span className="text-text-secondary">
                    <span className="text-text-muted mr-2">{i + 1}.</span>
                    {country.country}
                  </span>
                  <span 
                    className="font-mono"
                    style={{ color: selectedHoneypot === 'all' ? HONEYPOT_COLORS.all : HONEYPOT_COLORS[selectedHoneypot] }}
                  >
                    {country.count.toLocaleString()}
                  </span>
                </div>
              ))
            }
          </div>
        </div>
      </div>
    </div>
  );
}

