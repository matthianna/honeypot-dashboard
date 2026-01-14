import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { ComposableMap, Geographies, Geography } from 'react-simple-maps';
import { scaleLinear } from 'd3-scale';
import { Maximize2, Minimize2, ZoomIn, ZoomOut, RotateCcw } from 'lucide-react';
import api from '../services/api';
import LoadingSpinner from './LoadingSpinner';

// World map TopoJSON
const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

// Country name to ISO3 mapping (for matching with TopoJSON)
// Map from our data country names to ISO3 codes
const NAME_TO_ISO3: Record<string, string> = {
  "United States of America": "USA",
  "United States": "USA",
  "China": "CHN",
  "Russia": "RUS",
  "Russian Federation": "RUS",
  "Germany": "DEU",
  "France": "FRA",
  "United Kingdom": "GBR",
  "Great Britain": "GBR",
  "India": "IND",
  "Brazil": "BRA",
  "Netherlands": "NLD",
  "The Netherlands": "NLD",
  "Holland": "NLD",
  "Vietnam": "VNM",
  "Viet Nam": "VNM",
  "South Korea": "KOR",
  "Korea": "KOR",
  "Republic of Korea": "KOR",
  "Japan": "JPN",
  "Indonesia": "IDN",
  "Taiwan": "TWN",
  "Ukraine": "UKR",
  "Poland": "POL",
  "Romania": "ROU",
  "Italy": "ITA",
  "Spain": "ESP",
  "Canada": "CAN",
  "Australia": "AUS",
  "Thailand": "THA",
  "Singapore": "SGP",
  "Malaysia": "MYS",
  "Philippines": "PHL",
  "Mexico": "MEX",
  "Argentina": "ARG",
  "Colombia": "COL",
  "Turkey": "TUR",
  "Pakistan": "PAK",
  "Bangladesh": "BGD",
  "Egypt": "EGY",
  "South Africa": "ZAF",
  "Nigeria": "NGA",
  "Iran": "IRN",
  "Saudi Arabia": "SAU",
  "Sweden": "SWE",
  "Norway": "NOR",
  "Finland": "FIN",
  "Denmark": "DNK",
  "Belgium": "BEL",
  "Austria": "AUT",
  "Switzerland": "CHE",
  "Czechia": "CZE",
  "Czech Republic": "CZE",
  "Hungary": "HUN",
  "Bulgaria": "BGR",
  "Greece": "GRC",
  "Portugal": "PRT",
  "Ireland": "IRL",
  "New Zealand": "NZL",
  "Hong Kong": "HKG",
  "Chile": "CHL",
  "Peru": "PER",
  "Kazakhstan": "KAZ",
  "Belarus": "BLR",
  "Serbia": "SRB",
  "Croatia": "HRV",
  "Morocco": "MAR",
  "Algeria": "DZA",
  "Kenya": "KEN",
  "Israel": "ISR",
  "United Arab Emirates": "ARE",
};

// ISO numeric codes used by world-atlas TopoJSON to ISO3
const ISO_NUMERIC_TO_ISO3: Record<string, string> = {
  "840": "USA", "156": "CHN", "643": "RUS", "276": "DEU", "250": "FRA",
  "826": "GBR", "356": "IND", "076": "BRA", "528": "NLD", "704": "VNM",
  "410": "KOR", "392": "JPN", "360": "IDN", "158": "TWN", "804": "UKR",
  "616": "POL", "642": "ROU", "380": "ITA", "724": "ESP", "124": "CAN",
  "036": "AUS", "764": "THA", "702": "SGP", "458": "MYS", "608": "PHL",
  "484": "MEX", "032": "ARG", "170": "COL", "792": "TUR", "586": "PAK",
  "050": "BGD", "818": "EGY", "710": "ZAF", "566": "NGA", "364": "IRN",
  "682": "SAU", "752": "SWE", "578": "NOR", "246": "FIN", "208": "DNK",
  "056": "BEL", "040": "AUT", "756": "CHE", "203": "CZE", "348": "HUN",
  "100": "BGR", "300": "GRC", "620": "PRT", "372": "IRL", "554": "NZL",
  "344": "HKG", "152": "CHL", "604": "PER", "398": "KAZ", "112": "BLR",
  "688": "SRB", "191": "HRV", "504": "MAR", "012": "DZA", "404": "KEN",
  "376": "ISR", "784": "ARE",
};

interface CountryData {
  name: string;
  iso3: string | null;
  count: number;
  unique_ips: number;
  honeypots: Record<string, number>;
}

interface WorldChoroplethMapProps {
  timeRange?: '1h' | '24h' | '7d' | '30d';
  height?: number;
}

export default function WorldChoroplethMap({ timeRange = '7d', height = 500 }: WorldChoroplethMapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [data, setData] = useState<{
    countries: CountryData[];
    total_countries: number;
    max_count: number;
    total_attacks: number;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [hoveredCountry, setHoveredCountry] = useState<CountryData | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [panX, setPanX] = useState(0);
  const [panY, setPanY] = useState(0);
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  // Fetch data
  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.getChoroplethMapData(timeRange);
      setData(result);
    } catch (error) {
      console.error('Failed to fetch choropleth data:', error);
    } finally {
      setLoading(false);
    }
  }, [timeRange]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Create lookup map
  const countryLookup = useMemo(() => {
    if (!data) return new Map<string, CountryData>();
    const lookup = new Map<string, CountryData>();
    data.countries.forEach(c => {
      if (c.iso3) {
        lookup.set(c.iso3, c);
      }
      const iso3 = NAME_TO_ISO3[c.name];
      if (iso3) {
        lookup.set(iso3, c);
      }
    });
    return lookup;
  }, [data]);

  // Color scale - from dark to bright with better distinction
  const colorScale = useMemo(() => {
    const maxCount = data?.max_count || 1;
    return scaleLinear<string>()
      .domain([0, maxCount * 0.005, maxCount * 0.02, maxCount * 0.08, maxCount * 0.25, maxCount * 0.5, maxCount])
      .range(['#1a1a2e', '#0d4f4f', '#0ea5e9', '#22c55e', '#eab308', '#f97316', '#ef4444']);
  }, [data]);

  // Get ISO3 code from geography properties
  const getISO3 = useCallback((geo: { properties: Record<string, unknown> }): string | null => {
    const props = geo.properties as { 
      name?: string; 
      NAME?: string; 
      ISO_A3?: string;
      iso_a3?: string;
      ISO_N3?: string;
      iso_n3?: string;
    };
    
    // Try direct ISO3
    if (props.ISO_A3 && props.ISO_A3 !== '-99') return props.ISO_A3;
    if (props.iso_a3 && props.iso_a3 !== '-99') return props.iso_a3;
    
    // Try numeric ISO code
    const numericCode = props.ISO_N3 || props.iso_n3;
    if (numericCode && ISO_NUMERIC_TO_ISO3[numericCode]) {
      return ISO_NUMERIC_TO_ISO3[numericCode];
    }
    
    // Try name mapping
    const name = props.name || props.NAME || '';
    if (NAME_TO_ISO3[name]) return NAME_TO_ISO3[name];
    
    return null;
  }, []);

  // Get country color
  const getCountryColor = useCallback((geo: { properties: Record<string, unknown> }) => {
    const iso3 = getISO3(geo);
    const countryData = iso3 ? countryLookup.get(iso3) : null;
    
    if (!countryData || countryData.count === 0) {
      return '#1a1a2e';
    }
    return colorScale(countryData.count);
  }, [countryLookup, colorScale, getISO3]);

  // Get country data for tooltip
  const getCountryData = useCallback((geo: { properties: Record<string, unknown> }): CountryData | null => {
    const iso3 = getISO3(geo);
    return iso3 ? countryLookup.get(iso3) || null : null;
  }, [countryLookup, getISO3]);

  // Fullscreen toggle
  const toggleFullscreen = useCallback(() => {
    if (!containerRef.current) return;
    
    if (!document.fullscreenElement) {
      containerRef.current.requestFullscreen();
      setIsFullscreen(true);
    } else {
      document.exitFullscreen();
      setIsFullscreen(false);
    }
  }, []);

  // Listen for fullscreen changes
  useEffect(() => {
    const handleFullscreenChange = () => {
      setIsFullscreen(!!document.fullscreenElement);
    };
    document.addEventListener('fullscreenchange', handleFullscreenChange);
    return () => document.removeEventListener('fullscreenchange', handleFullscreenChange);
  }, []);

  // Zoom controls
  const handleZoomIn = () => setZoom(z => Math.min(z * 1.5, 8));
  const handleZoomOut = () => setZoom(z => Math.max(z / 1.5, 0.5));
  const handleReset = () => {
    setZoom(1);
    setPanX(0);
    setPanY(0);
  };

  // Mouse wheel zoom
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setZoom(z => Math.min(Math.max(z * delta, 0.5), 8));
  }, []);

  // Drag to pan
  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX - panX, y: e.clientY - panY });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    setPanX(e.clientX - dragStart.x);
    setPanY(e.clientY - dragStart.y);
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center bg-[#0a0a12]" style={{ height }}>
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div 
      ref={containerRef}
      className={`relative bg-[#0a0a12] overflow-hidden ${isFullscreen ? 'rounded-none' : 'rounded-xl'}`}
      style={{ height: isFullscreen ? '100vh' : height, cursor: isDragging ? 'grabbing' : 'grab' }}
      onWheel={handleWheel}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
    >
      {/* Full Map with Transform */}
      <div
        style={{
          width: '100%',
          height: '100%',
          transform: `scale(${zoom}) translate(${panX / zoom}px, ${panY / zoom}px)`,
          transformOrigin: 'center center',
          transition: isDragging ? 'none' : 'transform 0.1s ease-out',
        }}
      >
        <ComposableMap
          projection="geoMercator"
          projectionConfig={{
            scale: 160,
            center: [0, 25],
          }}
          style={{ width: '100%', height: '100%' }}
        >
          <Geographies geography={GEO_URL}>
            {({ geographies }) =>
              geographies.map((geo) => {
                const countryData = getCountryData(geo);
                return (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill={getCountryColor(geo)}
                    stroke="#3a3a5a"
                    strokeWidth={0.5 / zoom}
                    onMouseEnter={() => setHoveredCountry(countryData)}
                    onMouseLeave={() => setHoveredCountry(null)}
                    style={{
                      default: { outline: 'none' },
                      hover: {
                        outline: 'none',
                        fill: countryData ? '#ff6600' : '#252545',
                        cursor: countryData ? 'pointer' : 'default',
                      },
                      pressed: { outline: 'none' },
                    }}
                  />
                );
              })
            }
          </Geographies>
        </ComposableMap>
      </div>

      {/* Controls - Top Right */}
      <div className="absolute top-4 right-4 flex flex-col gap-2">
        <button
          onClick={toggleFullscreen}
          className="p-2.5 rounded-lg bg-black/70 backdrop-blur-md border border-white/20 text-white hover:bg-black/90 transition-all"
          title={isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}
        >
          {isFullscreen ? <Minimize2 className="w-5 h-5" /> : <Maximize2 className="w-5 h-5" />}
        </button>
        <button
          onClick={handleZoomIn}
          className="p-2.5 rounded-lg bg-black/70 backdrop-blur-md border border-white/20 text-white hover:bg-black/90 transition-all"
          title="Zoom In"
        >
          <ZoomIn className="w-5 h-5" />
        </button>
        <button
          onClick={handleZoomOut}
          className="p-2.5 rounded-lg bg-black/70 backdrop-blur-md border border-white/20 text-white hover:bg-black/90 transition-all"
          title="Zoom Out"
        >
          <ZoomOut className="w-5 h-5" />
        </button>
        <button
          onClick={handleReset}
          className="p-2.5 rounded-lg bg-black/70 backdrop-blur-md border border-white/20 text-white hover:bg-black/90 transition-all"
          title="Reset View"
        >
          <RotateCcw className="w-5 h-5" />
        </button>
      </div>

      {/* Legend - Bottom Left */}
      <div className="absolute bottom-4 left-4 bg-black/70 backdrop-blur-md rounded-lg p-2 border border-white/20">
        <div className="flex items-center gap-0.5">
          <div className="w-5 h-3 rounded-l" style={{ backgroundColor: '#1a1a2e' }} />
          <div className="w-5 h-3" style={{ backgroundColor: '#0d4f4f' }} />
          <div className="w-5 h-3" style={{ backgroundColor: '#0ea5e9' }} />
          <div className="w-5 h-3" style={{ backgroundColor: '#22c55e' }} />
          <div className="w-5 h-3" style={{ backgroundColor: '#eab308' }} />
          <div className="w-5 h-3" style={{ backgroundColor: '#f97316' }} />
          <div className="w-5 h-3 rounded-r" style={{ backgroundColor: '#ef4444' }} />
        </div>
        <div className="flex justify-between text-[10px] text-white/70 mt-1 px-0.5">
          <span>Low</span>
          <span>High</span>
        </div>
      </div>

      {/* Hovered Country Tooltip - Follows mouse position conceptually, shown bottom right */}
      {hoveredCountry && (
        <div className="absolute bottom-4 right-4 bg-black/90 backdrop-blur-md rounded-lg p-3 border border-neon-orange/50 min-w-48">
          <div className="text-base font-semibold text-white mb-2">{hoveredCountry.name}</div>
          <div className="space-y-1 text-sm">
            <div className="flex justify-between">
              <span className="text-white/60">Attacks</span>
              <span className="font-mono font-bold text-neon-orange">{hoveredCountry.count.toLocaleString()}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-white/60">Unique IPs</span>
              <span className="font-mono text-neon-blue">{hoveredCountry.unique_ips.toLocaleString()}</span>
            </div>
            {hoveredCountry.honeypots && Object.keys(hoveredCountry.honeypots).length > 0 && (
              <div className="pt-1 mt-1 border-t border-white/10 space-y-0.5">
                {Object.entries(hoveredCountry.honeypots)
                  .filter(([, count]) => count > 0)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 4)
                  .map(([hp, count]) => (
                    <div key={hp} className="flex justify-between text-xs">
                      <span className="capitalize text-white/50">{hp}</span>
                      <span className="font-mono text-white/80">{count.toLocaleString()}</span>
                    </div>
                  ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Zoom indicator */}
      {zoom !== 1 && (
        <div className="absolute top-4 left-4 bg-black/70 backdrop-blur-md rounded-lg px-3 py-1.5 border border-white/20">
          <span className="text-sm text-white font-mono">{zoom.toFixed(1)}x</span>
        </div>
      )}

      {/* Top 10 Countries - Compact List */}
      <div className="absolute top-4 left-4 bg-black/80 backdrop-blur-md rounded-lg border border-white/20 text-xs" style={{ marginTop: zoom !== 1 ? '44px' : 0 }}>
        <div className="px-3 py-1.5 border-b border-white/10 text-white/80 font-medium">
          Top 10 Countries
        </div>
        <div className="py-1">
          {data?.countries.slice(0, 10).map((country, idx) => (
            <div 
              key={country.name}
              className="px-3 py-0.5 flex items-center justify-between gap-4 hover:bg-white/5"
            >
              <span className="text-white/60">{idx + 1}. {country.name}</span>
              <span className="font-mono text-neon-orange">{country.count.toLocaleString()}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
