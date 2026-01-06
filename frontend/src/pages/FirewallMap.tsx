import { useState, useEffect, useCallback, useRef } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from 'react-leaflet';
import { Globe, Shield, Layers, Target, ShieldOff, ShieldCheck } from 'lucide-react';
import 'leaflet/dist/leaflet.css';
import api from '../services/api';

// Action colors
const ACTION_COLORS: Record<string, string> = {
  block: '#ff3366',
  pass: '#39ff14',
  reject: '#ff6600',
};

// Map tile layers
const MAP_LAYERS = {
  dark: {
    url: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    name: 'Dark',
  },
  satellite: {
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
    name: 'Satellite',
  },
  terrain: {
    url: 'https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png',
    name: 'Terrain',
  },
  light: {
    url: 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png',
    name: 'Light',
  },
};

interface FirewallEvent {
  id: string;
  timestamp: string;
  src_ip: string;
  src_lat: number;
  src_lon: number;
  src_country?: string;
  port?: number;
  action: string;
  protocol?: string;
  addedAt: number;
}

interface TopCountry {
  country: string;
  count: number;
  blocked: number;
  passed: number;
}

// Layer switcher component
function LayerSwitcher({ currentLayer, onLayerChange }: { currentLayer: string; onLayerChange: (layer: string) => void }) {
  const [isOpen, setIsOpen] = useState(false);
  useMap(); // Keep map context active
  
  return (
    <div className="absolute top-4 right-4 z-[1000]">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="bg-black/80 backdrop-blur-sm border border-white/20 rounded-lg p-2 hover:bg-black/90 transition-colors"
      >
        <Layers className="w-5 h-5 text-white" />
      </button>
      {isOpen && (
        <div className="absolute top-12 right-0 bg-black/90 backdrop-blur-sm border border-white/20 rounded-lg p-2 min-w-[120px]">
          {Object.entries(MAP_LAYERS).map(([key, layer]) => (
            <button
              key={key}
              onClick={() => {
                onLayerChange(key);
                setIsOpen(false);
              }}
              className={`w-full text-left px-3 py-2 rounded text-sm transition-colors ${
                currentLayer === key ? 'bg-neon-yellow/20 text-neon-yellow' : 'text-white hover:bg-white/10'
              }`}
            >
              {layer.name}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default function FirewallMap() {
  const [sessionStats, setSessionStats] = useState({
    totalEvents: 0,
    blocked: 0,
    passed: 0,
    uniqueIps: new Set<string>(),
    countries: new Set<string>(),
    byCountry: {} as Record<string, { count: number; blocked: number; passed: number }>,
  });
  
  const [events, setEvents] = useState<FirewallEvent[]>([]);
  const [mapLayer, setMapLayer] = useState('satellite');
  
  // Compute top countries from session stats
  const topCountries: TopCountry[] = Object.entries(sessionStats.byCountry)
    .map(([country, data]) => ({ country, count: data.count, blocked: data.blocked, passed: data.passed }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
  
  const seenIds = useRef<Set<string>>(new Set());
  const sessionStart = useRef<Date>(new Date());
  const pollRef = useRef<NodeJS.Timeout | null>(null);

  const EVENT_LIFETIME = 10000;
  const POLL_INTERVAL = 5000;

  const addEvents = useCallback((newEvents: FirewallEvent[]) => {
    const now = Date.now();
    const eventsToAdd: FirewallEvent[] = [];
    
    newEvents.forEach(event => {
      if (!seenIds.current.has(event.id)) {
        seenIds.current.add(event.id);
        eventsToAdd.push({
          ...event,
          addedAt: now,
        });
        
        setSessionStats(prev => {
          const newIps = new Set(prev.uniqueIps);
          newIps.add(event.src_ip);
          
          const newCountries = new Set(prev.countries);
          if (event.src_country) newCountries.add(event.src_country);
          
          const newByCountry = { ...prev.byCountry };
          if (event.src_country) {
            if (!newByCountry[event.src_country]) {
              newByCountry[event.src_country] = { count: 0, blocked: 0, passed: 0 };
            }
            newByCountry[event.src_country].count += 1;
            if (event.action === 'block') {
              newByCountry[event.src_country].blocked += 1;
            } else if (event.action === 'pass') {
              newByCountry[event.src_country].passed += 1;
            }
          }
          
          return {
            totalEvents: prev.totalEvents + 1,
            blocked: prev.blocked + (event.action === 'block' ? 1 : 0),
            passed: prev.passed + (event.action === 'pass' ? 1 : 0),
            uniqueIps: newIps,
            countries: newCountries,
            byCountry: newByCountry,
          };
        });
      }
    });
    
    if (eventsToAdd.length > 0) {
      setEvents(prev => [...prev, ...eventsToAdd]);
    }
  }, []);

  useEffect(() => {
    const cleanupInterval = setInterval(() => {
      const now = Date.now();
      setEvents(prev => prev.filter(e => now - e.addedAt < EVENT_LIFETIME));
    }, 500);
    
    return () => clearInterval(cleanupInterval);
  }, []);

  const pollEvents = useCallback(async () => {
    try {
      const response = await api.getFirewallMapRecent(50, 60);
      if (Array.isArray(response)) {
        addEvents(response);
      }
    } catch (error) {
      console.error('Failed to poll events:', error);
    }
  }, [addEvents]);

  useEffect(() => {
    sessionStart.current = new Date();
    seenIds.current = new Set();
    setSessionStats({
      totalEvents: 0,
      blocked: 0,
      passed: 0,
      uniqueIps: new Set(),
      countries: new Set(),
      byCountry: {},
    });
    
    pollEvents();
    
    pollRef.current = setInterval(() => {
      pollEvents();
    }, POLL_INTERVAL);
    
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [pollEvents]);

  const getEventOpacity = (event: FirewallEvent): number => {
    const age = Date.now() - event.addedAt;
    const remaining = EVENT_LIFETIME - age;
    return Math.max(0.1, remaining / EVENT_LIFETIME);
  };

  const getEventRadius = (event: FirewallEvent): number => {
    const age = Date.now() - event.addedAt;
    const progress = age / EVENT_LIFETIME;
    if (progress < 0.3) {
      return 8 + (progress / 0.3) * 12;
    }
    return 20 - (progress - 0.3) / 0.7 * 12;
  };

  const activeBlocked = events.filter(e => e.action === 'block').length;
  const activePassed = events.filter(e => e.action === 'pass').length;

  return (
    <div className="h-[calc(100vh-6rem)] relative rounded-xl overflow-hidden border border-bg-hover">
      <MapContainer
        center={[25, 0]}
        zoom={2}
        className="h-full w-full"
        style={{ background: '#1a1a2e' }}
        maxBounds={[[-90, -180], [90, 180]]}
        minZoom={2}
        zoomControl={false}
      >
        <TileLayer
          key={mapLayer}
          url={MAP_LAYERS[mapLayer as keyof typeof MAP_LAYERS].url}
          attribution=""
        />
        <LayerSwitcher currentLayer={mapLayer} onLayerChange={setMapLayer} />
        
        {/* Event markers */}
        {events.map(event => {
          const opacity = getEventOpacity(event);
          const radius = getEventRadius(event);
          const color = ACTION_COLORS[event.action] || '#ff3366';
          
          return (
            <CircleMarker
              key={event.id}
              center={[event.src_lat, event.src_lon]}
              radius={radius}
              pathOptions={{
                color: color,
                fillColor: color,
                fillOpacity: opacity * 0.7,
                weight: 2,
                opacity: opacity,
              }}
            >
              <Popup>
                <div className="text-sm min-w-[150px]">
                  <div className="font-bold text-base" style={{ color }}>
                    {event.action === 'block' ? '🛑 BLOCKED' : '✅ PASSED'}
                  </div>
                  <div className="text-gray-700 font-mono">{event.src_ip}</div>
                  <div className="text-gray-600">{event.src_country || 'Unknown'}</div>
                  {event.port && <div className="text-gray-500">Port: {event.port}</div>}
                  {event.protocol && <div className="text-gray-500">Protocol: {event.protocol}</div>}
                </div>
              </Popup>
            </CircleMarker>
          );
        })}

        {/* Target marker (Lugano) */}
        <CircleMarker
          center={[46.0037, 8.9511]}
          radius={10}
          pathOptions={{
            color: '#ffff00',
            fillColor: '#ffff00',
            fillOpacity: 0.9,
            weight: 3,
          }}
        >
          <Popup>
            <div className="text-sm font-bold">🔥 Firewall</div>
            <div className="text-gray-500">Lugano, Switzerland</div>
          </Popup>
        </CircleMarker>
      </MapContainer>

      {/* Header Overlay */}
      <div className="absolute top-4 left-4 z-[1000]">
        <div className="bg-black/80 backdrop-blur-sm border border-neon-yellow/30 rounded-xl px-4 py-3">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-neon-yellow" />
            <div>
              <h2 className="text-lg font-display font-bold text-neon-yellow">Live Firewall Map</h2>
              <div className="flex items-center gap-2 text-xs text-text-muted">
                <span className="w-2 h-2 bg-neon-yellow rounded-full animate-pulse" />
                <span>Polling every 5s</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Overlay - Top Right */}
      <div className="absolute top-4 right-16 z-[1000] flex gap-2">
        <div className="bg-black/80 backdrop-blur-sm border border-neon-yellow/30 rounded-xl px-4 py-2 text-center">
          <div className="text-2xl font-display font-bold text-neon-yellow">{sessionStats.totalEvents}</div>
          <div className="text-xs text-text-muted">Total Events</div>
        </div>
        <div className="bg-black/80 backdrop-blur-sm border border-neon-blue/30 rounded-xl px-4 py-2 text-center">
          <div className="text-2xl font-display font-bold text-neon-blue">{events.length}</div>
          <div className="text-xs text-text-muted">On Map</div>
        </div>
      </div>

      {/* Legend Overlay - Bottom Left */}
      <div className="absolute bottom-4 left-4 z-[1000]">
        <div className="bg-black/80 backdrop-blur-sm border border-white/10 rounded-xl p-3">
          <div className="text-xs text-text-muted mb-2 font-semibold">ACTIONS</div>
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-2">
                <ShieldOff className="w-4 h-4 text-neon-red" />
                <div className="w-3 h-3 rounded-full bg-neon-red" />
                <span className="text-xs text-white">Blocked</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-text-muted">{sessionStats.blocked}</span>
                <span className="text-xs text-neon-red font-mono">({activeBlocked} live)</span>
              </div>
            </div>
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-neon-green" />
                <div className="w-3 h-3 rounded-full bg-neon-green" />
                <span className="text-xs text-white">Passed</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-text-muted">{sessionStats.passed}</span>
                <span className="text-xs text-neon-green font-mono">({activePassed} live)</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Top Countries Overlay - Left Side */}
      <div className="absolute top-24 left-4 z-[1000] w-60">
        <div className="bg-black/80 backdrop-blur-sm border border-neon-orange/30 rounded-xl p-3">
          <div className="flex items-center gap-2 mb-3">
            <Globe className="w-4 h-4 text-neon-orange" />
            <span className="text-sm font-semibold text-white">Top 10 Countries</span>
          </div>
          <div className="space-y-1.5 max-h-[350px] overflow-y-auto">
            {topCountries.length === 0 ? (
              <div className="text-center py-4 text-text-muted text-xs">
                <div className="text-lg mb-1">—</div>
                <div>Waiting for events...</div>
              </div>
            ) : (
              topCountries.map((country, index) => {
                const maxCount = topCountries[0]?.count || 1;
                const percentage = (country.count / maxCount) * 100;
                return (
                  <div key={country.country} className="relative">
                    <div 
                      className="absolute inset-0 bg-neon-orange/20 rounded"
                      style={{ width: `${percentage}%` }}
                    />
                    <div className="relative px-2 py-1.5">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-neon-orange font-bold w-4">{index + 1}</span>
                          <span className="text-xs text-white truncate max-w-[90px]">{country.country}</span>
                        </div>
                        <span className="text-xs font-mono text-neon-yellow font-bold">{country.count.toLocaleString()}</span>
                      </div>
                      <div className="flex gap-2 text-[10px] mt-0.5 pl-6">
                        <span className="text-neon-red">{country.blocked} blocked</span>
                        <span className="text-neon-green">{country.passed} passed</span>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Target Info - Bottom Right */}
      <div className="absolute bottom-4 right-4 z-[1000]">
        <div className="bg-black/80 backdrop-blur-sm border border-white/20 rounded-xl px-3 py-2 flex items-center gap-2">
          <Target className="w-4 h-4 text-neon-yellow" />
          <span className="text-xs text-white">Target: Lugano, CH</span>
        </div>
      </div>
    </div>
  );
}
