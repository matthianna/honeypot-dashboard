import { useState, useEffect, useCallback, useRef } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from 'react-leaflet';
import { Activity, Globe, Layers, Target } from 'lucide-react';
import 'leaflet/dist/leaflet.css';
import api from '../services/api';
import type { AttackEvent as ApiAttackEvent } from '../types';

// Honeypot colors
const HONEYPOT_COLORS: Record<string, string> = {
  cowrie: '#39ff14',
  dionaea: '#00d4ff',
  galah: '#ff6600',
  rdpy: '#bf00ff',
  heralding: '#ff3366',
};

const HONEYPOT_NAMES: Record<string, string> = {
  cowrie: 'Cowrie',
  dionaea: 'Dionaea',
  galah: 'Galah',
  rdpy: 'RDPY',
  heralding: 'Heralding',
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

interface MapAttackEvent {
  id: string;
  timestamp: string;
  honeypot: string;
  src_ip: string;
  src_lat: number;
  src_lon: number;
  src_country?: string;
  port?: number;
  addedAt: number;
}

function hasValidCoordinates(event: ApiAttackEvent): event is ApiAttackEvent & { src_lat: number; src_lon: number } {
  return typeof event.src_lat === 'number' && typeof event.src_lon === 'number';
}

interface TopCountry {
  country: string;
  count: number;
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
                currentLayer === key ? 'bg-neon-green/20 text-neon-green' : 'text-white hover:bg-white/10'
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

export default function AttackMap() {
  const [sessionStats, setSessionStats] = useState({
    totalAttacks: 0,
    uniqueIps: new Set<string>(),
    countries: new Set<string>(),
    byHoneypot: {} as Record<string, number>,
    byCountry: {} as Record<string, number>,
  });
  
  const [events, setEvents] = useState<MapAttackEvent[]>([]);
  const [mapLayer, setMapLayer] = useState('satellite');
  
  // Compute top countries from session stats
  const topCountries: TopCountry[] = Object.entries(sessionStats.byCountry)
    .map(([country, count]) => ({ country, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
  
  const seenIds = useRef<Set<string>>(new Set());
  const sessionStart = useRef<Date>(new Date());
  const pollRef = useRef<NodeJS.Timeout | null>(null);

  const EVENT_LIFETIME = 10000;
  const POLL_INTERVAL = 5000;

  const addEvents = useCallback((newEvents: ApiAttackEvent[]) => {
    const now = Date.now();
    const eventsToAdd: MapAttackEvent[] = [];
    
    newEvents.filter(hasValidCoordinates).forEach(event => {
      if (!seenIds.current.has(event.id)) {
        seenIds.current.add(event.id);
        eventsToAdd.push({
          id: event.id,
          timestamp: event.timestamp,
          honeypot: event.honeypot,
          src_ip: event.src_ip,
          src_lat: event.src_lat,
          src_lon: event.src_lon,
          src_country: event.src_country,
          port: event.port,
          addedAt: now,
        });
        
        setSessionStats(prev => {
          const newIps = new Set(prev.uniqueIps);
          newIps.add(event.src_ip);
          
          const newCountries = new Set(prev.countries);
          if (event.src_country) newCountries.add(event.src_country);
          
          const newByHoneypot = { ...prev.byHoneypot };
          newByHoneypot[event.honeypot] = (newByHoneypot[event.honeypot] || 0) + 1;
          
          const newByCountry = { ...prev.byCountry };
          if (event.src_country) {
            newByCountry[event.src_country] = (newByCountry[event.src_country] || 0) + 1;
          }
          
          return {
            totalAttacks: prev.totalAttacks + 1,
            uniqueIps: newIps,
            countries: newCountries,
            byHoneypot: newByHoneypot,
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
      const response = await api.getAttackMapRecent(50, 60);
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
      totalAttacks: 0,
      uniqueIps: new Set(),
      countries: new Set(),
      byHoneypot: {},
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

  const getEventOpacity = (event: MapAttackEvent): number => {
    const age = Date.now() - event.addedAt;
    const remaining = EVENT_LIFETIME - age;
    return Math.max(0.1, remaining / EVENT_LIFETIME);
  };

  const getEventRadius = (event: MapAttackEvent): number => {
    const age = Date.now() - event.addedAt;
    const progress = age / EVENT_LIFETIME;
    if (progress < 0.3) {
      return 8 + (progress / 0.3) * 12;
    }
    return 20 - (progress - 0.3) / 0.7 * 12;
  };

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
        
        {/* Attack markers */}
        {events.map(event => {
          const opacity = getEventOpacity(event);
          const radius = getEventRadius(event);
          const color = HONEYPOT_COLORS[event.honeypot] || '#39ff14';
          
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
                  <div className="font-bold text-base" style={{ color }}>{HONEYPOT_NAMES[event.honeypot]}</div>
                  <div className="text-gray-700 font-mono">{event.src_ip}</div>
                  <div className="text-gray-600">{event.src_country || 'Unknown'}</div>
                  {event.port && <div className="text-gray-500">Port: {event.port}</div>}
                </div>
              </Popup>
            </CircleMarker>
          );
        })}

        {/* Target marker (Zurich) */}
        <CircleMarker
          center={[47.3769, 8.5417]}
          radius={10}
          pathOptions={{
            color: '#ffffff',
            fillColor: '#ffffff',
            fillOpacity: 0.9,
            weight: 3,
          }}
        >
          <Popup>
            <div className="text-sm font-bold">🎯 Honeypot Server</div>
            <div className="text-gray-500">Zurich, Switzerland</div>
          </Popup>
        </CircleMarker>
      </MapContainer>

      {/* Header Overlay */}
      <div className="absolute top-4 left-4 z-[1000]">
        <div className="bg-black/80 backdrop-blur-sm border border-neon-green/30 rounded-xl px-4 py-3">
          <div className="flex items-center gap-3">
            <Activity className="w-6 h-6 text-neon-green" />
            <div>
              <h2 className="text-lg font-display font-bold text-neon-green">Live Attack Map</h2>
              <div className="flex items-center gap-2 text-xs text-text-muted">
                <span className="w-2 h-2 bg-neon-green rounded-full animate-pulse" />
                <span>Polling every 5s</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Overlay - Top Right */}
      <div className="absolute top-4 right-16 z-[1000] flex gap-2">
        <div className="bg-black/80 backdrop-blur-sm border border-neon-green/30 rounded-xl px-4 py-2 text-center">
          <div className="text-2xl font-display font-bold text-neon-green">{sessionStats.totalAttacks}</div>
          <div className="text-xs text-text-muted">Total Attacks</div>
        </div>
        <div className="bg-black/80 backdrop-blur-sm border border-neon-blue/30 rounded-xl px-4 py-2 text-center">
          <div className="text-2xl font-display font-bold text-neon-blue">{events.length}</div>
          <div className="text-xs text-text-muted">On Map</div>
        </div>
      </div>

      {/* Legend Overlay - Bottom Left */}
      <div className="absolute bottom-4 left-4 z-[1000]">
        <div className="bg-black/80 backdrop-blur-sm border border-white/10 rounded-xl p-3">
          <div className="text-xs text-text-muted mb-2 font-semibold">HONEYPOTS</div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1">
            {Object.entries(HONEYPOT_COLORS).map(([key, color]) => (
              <div key={key} className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: color }} />
                <span className="text-xs text-white">{HONEYPOT_NAMES[key]}</span>
                <span className="text-xs font-mono text-text-muted ml-auto">{sessionStats.byHoneypot[key] || 0}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top Countries Overlay - Left Side */}
      <div className="absolute top-24 left-4 z-[1000] w-56">
        <div className="bg-black/80 backdrop-blur-sm border border-neon-orange/30 rounded-xl p-3">
          <div className="flex items-center gap-2 mb-3">
            <Globe className="w-4 h-4 text-neon-orange" />
            <span className="text-sm font-semibold text-white">Top 10 Countries</span>
          </div>
          <div className="space-y-1.5 max-h-[350px] overflow-y-auto">
            {topCountries.length === 0 ? (
              <div className="text-center py-4 text-text-muted text-xs">
                <div className="text-lg mb-1">—</div>
                <div>Waiting for attacks...</div>
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
                    <div className="relative flex items-center justify-between px-2 py-1.5">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-neon-orange font-bold w-4">{index + 1}</span>
                        <span className="text-xs text-white truncate max-w-[100px]">{country.country}</span>
                      </div>
                      <span className="text-xs font-mono text-neon-green font-bold">{country.count.toLocaleString()}</span>
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
          <Target className="w-4 h-4 text-white" />
          <span className="text-xs text-white">Target: Zurich, CH</span>
        </div>
      </div>
    </div>
  );
}
