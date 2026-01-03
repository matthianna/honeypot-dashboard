import { useEffect, useRef, useState, useCallback } from 'react';
import { MapContainer, TileLayer, useMap } from 'react-leaflet';
import { Filter, Pause, Play, Maximize2, Minimize2, Zap, RefreshCw, Target, Clock } from 'lucide-react';
import AttackMarker, { TargetMarker, type AttackData } from '../components/AttackMarker';
import TileLayerSwitcher, { TILE_LAYERS, type TileLayerType } from '../components/TileLayerSwitcher';
import api from '../services/api';
import 'leaflet/dist/leaflet.css';

// Honeypot colors
const HONEYPOT_COLORS: Record<string, string> = {
  cowrie: '#39ff14',
  dionaea: '#00d4ff',
  galah: '#ff6600',
  rdpy: '#bf00ff',
  heralding: '#ff3366',
  firewall: '#ffcc00',
};

// Zurich target coordinates
const TARGET_CENTER: [number, number] = [47.3769, 8.5417];
const DEFAULT_CENTER: [number, number] = [30, 10];
const DEFAULT_ZOOM = 3;

// Polling interval in milliseconds
const POLL_INTERVAL = 5000;

interface Attack extends AttackData {
  age: number;
}

interface RawAttack {
  id: string;
  timestamp: string;
  honeypot: string;
  src_ip: string;
  src_lat?: number | null;
  src_lon?: number | null;
  src_country?: string | null;
  port?: number | null;
}

// Component to handle map recenter
function MapController({ center, shouldCenter }: { center: [number, number]; shouldCenter: boolean }) {
  const map = useMap();
  
  useEffect(() => {
    if (shouldCenter) {
      map.flyTo(center, 5, { duration: 1.5 });
    }
  }, [map, center, shouldCenter]);
  
  return null;
}

export default function AttackMap() {
  // Start with empty attacks - no initial data loaded
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const [recentList, setRecentList] = useState<Attack[]>([]);
  const [isPaused, setIsPaused] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [showLayerSwitcher, setShowLayerSwitcher] = useState(false);
  const [tileLayer, setTileLayer] = useState<TileLayerType>('dark');
  const [filters, setFilters] = useState<Record<string, boolean>>({
    cowrie: true,
    dionaea: true,
    galah: true,
    rdpy: true,
    heralding: true,
    firewall: true,
  });
  const [stats, setStats] = useState({ attacks: 0, ips: 0, countries: 0, newThisSession: 0 });
  const [lastPoll, setLastPoll] = useState<Date | null>(null);
  const [nextPoll, setNextPoll] = useState<number>(POLL_INTERVAL / 1000);
  const [isPolling, setIsPolling] = useState(false);
  const [shouldCenterTarget, setShouldCenterTarget] = useState(false);
  const [countryLeaderboard, setCountryLeaderboard] = useState<Map<string, number>>(new Map());
  
  const containerRef = useRef<HTMLDivElement>(null);
  const attackIdRef = useRef(0);
  const animationRef = useRef<number>();
  const filtersRef = useRef(filters);
  const seenIdsRef = useRef(new Set<string>());
  const countdownRef = useRef<ReturnType<typeof setInterval>>();
  const sessionStartRef = useRef<string>(new Date().toISOString());
  
  // Keep filters ref in sync
  useEffect(() => {
    filtersRef.current = filters;
  }, [filters]);
  
  // Add a new attack with animation
  const addAttack = useCallback((data: RawAttack) => {
    if (!data.src_lat || !data.src_lon) return;
    if (!filtersRef.current[data.honeypot]) return;
    
    const attack: Attack = {
      id: `${data.id}-${attackIdRef.current++}`,
      timestamp: data.timestamp,
      honeypot: data.honeypot,
      src_ip: data.src_ip,
      src_lat: data.src_lat,
      src_lon: data.src_lon,
      src_country: data.src_country ?? null,
      port: data.port ?? null,
      age: 0,
    };
    
    setAttacks(prev => [...prev.slice(-150), attack]);
    setRecentList(prev => [attack, ...prev.slice(0, 29)]);
    
    // Update country leaderboard
    if (data.src_country) {
      setCountryLeaderboard(prev => {
        const newMap = new Map(prev);
        const current = newMap.get(data.src_country!) || 0;
        newMap.set(data.src_country!, current + 1);
        return newMap;
      });
    }
  }, []);
  
  // Animation loop - update attack ages
  useEffect(() => {
    let lastTime = performance.now();
    
    const animate = (time: number) => {
      const delta = (time - lastTime) / 1000;
      lastTime = time;
      
      setAttacks(prev => prev
        .map(a => ({ ...a, age: a.age + delta }))
        .filter(a => a.age < 30) // Remove after 30 seconds
      );
      
      animationRef.current = requestAnimationFrame(animate);
    };
    
    animationRef.current = requestAnimationFrame(animate);
    return () => {
      if (animationRef.current) cancelAnimationFrame(animationRef.current);
    };
  }, []);
  
  // Poll for new attacks every 5 seconds
  const pollForAttacks = useCallback(async () => {
    if (isPaused) return;
    
    setIsPolling(true);
    try {
      // Get recent attacks from the API
      const attacksData = await api.getRecentAttacks(50);
      
      let newCount = 0;
      
      // Only add attacks we haven't seen before
      attacksData.forEach((attack, index) => {
        if (!seenIdsRef.current.has(attack.id)) {
          seenIdsRef.current.add(attack.id);
          newCount++;
          
          // Stagger the animations slightly
          setTimeout(() => {
            addAttack(attack);
          }, index * 100);
        }
      });
      
      // Update stats
      if (newCount > 0) {
        setStats(prev => ({ ...prev, newThisSession: prev.newThisSession + newCount }));
      }
      
      // Update overall stats
      const statsData = await api.getAttackMapStats();
      setStats(prev => ({
        attacks: statsData.total_attacks,
        ips: statsData.unique_ips,
        countries: statsData.countries,
        newThisSession: prev.newThisSession,
      }));
      
      setLastPoll(new Date());
      
      // Limit seen IDs set size to prevent memory issues
      if (seenIdsRef.current.size > 1000) {
        const arr = Array.from(seenIdsRef.current);
        seenIdsRef.current.clear();
        arr.slice(-500).forEach(id => seenIdsRef.current.add(id));
      }
    } catch (e) {
      console.error('Polling error:', e);
    } finally {
      setIsPolling(false);
    }
  }, [isPaused, addAttack]);
  
  // Countdown timer for next poll
  useEffect(() => {
    if (countdownRef.current) {
      clearInterval(countdownRef.current);
    }
    
    setNextPoll(POLL_INTERVAL / 1000);
    
    countdownRef.current = setInterval(() => {
      setNextPoll(prev => {
        if (prev <= 1) {
          return POLL_INTERVAL / 1000;
        }
        return prev - 1;
      });
    }, 1000);
    
    return () => {
      if (countdownRef.current) clearInterval(countdownRef.current);
    };
  }, [lastPoll]);
  
  // Main polling interval
  useEffect(() => {
    if (isPaused) return;
    
    // Initial poll after 1 second (give user time to see empty state)
    const initialTimeout = setTimeout(() => {
      pollForAttacks();
    }, 1000);
    
    // Then poll every 5 seconds
    const interval = setInterval(() => {
      pollForAttacks();
    }, POLL_INTERVAL);
    
    return () => {
      clearTimeout(initialTimeout);
      clearInterval(interval);
    };
  }, [isPaused, pollForAttacks]);
  
  // Fullscreen toggle
  const toggleFullscreen = () => {
    if (!containerRef.current) return;
    if (!document.fullscreenElement) {
      containerRef.current.requestFullscreen();
      setIsFullscreen(true);
    } else {
      document.exitFullscreen();
      setIsFullscreen(false);
    }
  };
  
  // Center on target
  const centerOnTarget = () => {
    setShouldCenterTarget(true);
    setTimeout(() => setShouldCenterTarget(false), 100);
  };
  
  // Manual refresh
  const handleRefresh = async () => {
    await pollForAttacks();
  };
  
  // Clear all and restart
  const handleClear = () => {
    setAttacks([]);
    setRecentList([]);
    seenIdsRef.current.clear();
    setStats(prev => ({ ...prev, newThisSession: 0 }));
    setCountryLeaderboard(new Map());
    sessionStartRef.current = new Date().toISOString();
  };
  
  const formatTime = (ts: string) => {
    try {
      return new Date(ts).toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit' 
      });
    } catch {
      return '';
    }
  };

  // Filter attacks by current filter settings
  const visibleAttacks = attacks.filter(a => filtersRef.current[a.honeypot]);
  const currentTileConfig = TILE_LAYERS[tileLayer];

  return (
    <div 
      ref={containerRef}
      className={`relative bg-[#0a0a12] rounded-xl overflow-hidden ${
        isFullscreen ? 'fixed inset-0 z-50' : 'h-[calc(100vh-120px)]'
      }`}
    >
      {/* Leaflet Map */}
      <MapContainer
        center={DEFAULT_CENTER}
        zoom={DEFAULT_ZOOM}
        minZoom={2}
        maxZoom={18}
        style={{ width: '100%', height: '100%', background: '#0a0a12' }}
        zoomControl={true}
        attributionControl={false}
      >
        <TileLayer
          url={currentTileConfig.url}
          attribution={currentTileConfig.attribution}
        />
        
        <MapController center={TARGET_CENTER} shouldCenter={shouldCenterTarget} />
        
        {/* Target marker - Zurich */}
        <TargetMarker />
        
        {/* Attack markers */}
        {visibleAttacks.map((attack) => (
          <AttackMarker key={attack.id} attack={attack} age={attack.age} />
        ))}
      </MapContainer>
      
      {/* Stats Overlay */}
      <div className="absolute top-4 left-4 bg-black/70 backdrop-blur-md rounded-xl p-5 border border-white/10 z-[1000]">
        <div className="flex items-center gap-2 mb-4">
          <Zap className="w-4 h-4 text-neon-green" />
          <span className="text-xs uppercase tracking-wider text-text-muted">Live Stats</span>
          {isPolling && (
            <span className="w-2 h-2 rounded-full bg-neon-green animate-ping ml-2" />
          )}
        </div>
        <div className="grid grid-cols-2 gap-x-8 gap-y-4">
          <div>
            <div className="text-3xl font-display font-bold text-neon-green">
              {stats.attacks.toLocaleString()}
            </div>
            <div className="text-xs text-text-secondary mt-1">Total Attacks (24h)</div>
          </div>
          <div>
            <div className="text-3xl font-display font-bold text-neon-blue">
              {stats.ips.toLocaleString()}
            </div>
            <div className="text-xs text-text-secondary mt-1">Unique IPs</div>
          </div>
          <div>
            <div className="text-3xl font-display font-bold text-neon-orange">
              {stats.newThisSession}
            </div>
            <div className="text-xs text-text-secondary mt-1">New This Session</div>
          </div>
          <div>
            <div className="text-3xl font-display font-bold text-neon-purple">
              {visibleAttacks.length}
            </div>
            <div className="text-xs text-text-secondary mt-1">On Map</div>
          </div>
        </div>
      </div>
      
      {/* Poll Timer */}
      <div className="absolute top-4 left-1/2 -translate-x-1/2 bg-black/70 backdrop-blur-md rounded-xl px-4 py-2 border border-white/10 z-[1000]">
        <div className="flex items-center gap-3">
          <Clock className={`w-4 h-4 ${isPaused ? 'text-neon-orange' : 'text-neon-green'}`} />
          <div className="text-sm">
            {isPaused ? (
              <span className="text-neon-orange">Paused</span>
            ) : (
              <>
                <span className="text-text-muted">Next poll in </span>
                <span className="text-neon-green font-mono font-bold">{nextPoll}s</span>
              </>
            )}
          </div>
          {lastPoll && (
            <div className="text-xs text-text-muted border-l border-white/10 pl-3">
              Last: {formatTime(lastPoll.toISOString())}
            </div>
          )}
        </div>
      </div>
      
      {/* Controls */}
      <div className="absolute top-4 right-4 flex gap-2 z-[1000]">
        <button
          onClick={handleRefresh}
          disabled={isPolling}
          className={`p-3 rounded-lg backdrop-blur-md border transition-all ${
            isPolling 
              ? 'bg-neon-green/20 border-neon-green text-neon-green' 
              : 'bg-black/50 border-white/10 text-text-secondary hover:text-neon-green'
          }`}
          title="Refresh Now"
        >
          <RefreshCw className={`w-5 h-5 ${isPolling ? 'animate-spin' : ''}`} />
        </button>
        <button
          onClick={handleClear}
          className="p-3 rounded-lg bg-black/50 backdrop-blur-md border border-white/10 text-text-secondary hover:text-neon-red transition-all"
          title="Clear Map"
        >
          <span className="text-sm font-bold">×</span>
        </button>
        <button
          onClick={centerOnTarget}
          className="p-3 rounded-lg bg-black/50 backdrop-blur-md border border-white/10 text-text-secondary hover:text-neon-orange transition-all"
          title="Center on Target (Zurich)"
        >
          <Target className="w-5 h-5" />
        </button>
        <TileLayerSwitcher
          currentLayer={tileLayer}
          onChange={setTileLayer}
          isOpen={showLayerSwitcher}
          onToggle={() => {
            setShowLayerSwitcher(!showLayerSwitcher);
            setShowFilters(false);
          }}
        />
        <button
          onClick={() => {
            setShowFilters(!showFilters);
            setShowLayerSwitcher(false);
          }}
          className={`p-3 rounded-lg backdrop-blur-md border transition-all ${
            showFilters 
              ? 'bg-neon-green/20 border-neon-green text-neon-green' 
              : 'bg-black/50 border-white/10 text-text-secondary hover:text-white'
          }`}
          title="Filter Honeypots"
        >
          <Filter className="w-5 h-5" />
        </button>
        <button
          onClick={() => setIsPaused(!isPaused)}
          className={`p-3 rounded-lg backdrop-blur-md border transition-all ${
            isPaused 
              ? 'bg-neon-orange/20 border-neon-orange text-neon-orange' 
              : 'bg-black/50 border-white/10 text-text-secondary hover:text-white'
          }`}
          title={isPaused ? 'Resume' : 'Pause'}
        >
          {isPaused ? <Play className="w-5 h-5" /> : <Pause className="w-5 h-5" />}
        </button>
        <button
          onClick={toggleFullscreen}
          className="p-3 rounded-lg bg-black/50 backdrop-blur-md border border-white/10 text-text-secondary hover:text-white transition-all"
          title="Toggle Fullscreen"
        >
          {isFullscreen ? <Minimize2 className="w-5 h-5" /> : <Maximize2 className="w-5 h-5" />}
        </button>
      </div>
      
      {/* Filters Panel */}
      {showFilters && (
        <div className="absolute top-20 right-4 bg-black/90 backdrop-blur-md rounded-xl p-4 border border-white/10 min-w-[200px] z-[1000]">
          <div className="text-sm font-medium text-white mb-3">Filter Honeypots</div>
          {Object.entries(HONEYPOT_COLORS).map(([honeypot, color]) => (
            <label key={honeypot} className="flex items-center gap-3 py-2 cursor-pointer group">
              <input
                type="checkbox"
                checked={filters[honeypot]}
                onChange={() => setFilters(prev => ({ ...prev, [honeypot]: !prev[honeypot] }))}
                className="w-4 h-4 rounded border-white/20 bg-transparent accent-neon-green"
              />
              <span 
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: color, boxShadow: `0 0 8px ${color}` }}
              />
              <span className="text-sm text-text-secondary group-hover:text-white capitalize">
                {honeypot}
              </span>
            </label>
          ))}
        </div>
      )}
      
      {/* Legend */}
      <div className="absolute bottom-4 left-4 bg-black/70 backdrop-blur-md rounded-xl p-4 border border-white/10 z-[1000]">
        <div className="grid grid-cols-3 gap-x-6 gap-y-2">
          {Object.entries(HONEYPOT_COLORS).map(([name, color]) => (
            <div key={name} className="flex items-center gap-2">
              <span 
                className="w-2.5 h-2.5 rounded-full"
                style={{ backgroundColor: color, boxShadow: `0 0 6px ${color}` }}
              />
              <span className="text-xs text-text-secondary capitalize">{name}</span>
            </div>
          ))}
        </div>
      </div>
      
      {/* Country Leaderboard */}
      <div className="absolute top-24 right-4 bg-black/80 backdrop-blur-md rounded-xl p-3 border border-white/10 z-[1000] min-w-[180px]">
        <div className="flex items-center gap-2 mb-2 text-white text-xs font-medium">
          <span className="text-lg">🏆</span>
          <span>Live Country Ranking</span>
        </div>
        <div className="space-y-1.5 max-h-[200px] overflow-y-auto">
          {Array.from(countryLeaderboard.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([country, count], index) => {
              const medals = ['🥇', '🥈', '🥉'];
              return (
                <div 
                  key={country} 
                  className="flex items-center justify-between text-xs group"
                >
                  <div className="flex items-center gap-2">
                    <span className="w-5 text-center">
                      {index < 3 ? medals[index] : <span className="text-text-muted">{index + 1}.</span>}
                    </span>
                    <span className="text-text-secondary group-hover:text-white transition-colors truncate max-w-[100px]">
                      {country}
                    </span>
                  </div>
                  <span className={`font-mono ${
                    index === 0 ? 'text-neon-orange' : 
                    index === 1 ? 'text-text-primary' : 
                    index === 2 ? 'text-neon-orange/70' : 
                    'text-text-muted'
                  }`}>
                    {count}
                  </span>
                </div>
              );
            })}
          {countryLeaderboard.size === 0 && (
            <div className="text-xs text-text-muted text-center py-2">
              Waiting for attacks...
            </div>
          )}
        </div>
        {countryLeaderboard.size > 0 && (
          <div className="mt-2 pt-2 border-t border-white/10 text-xs text-text-muted text-center">
            {countryLeaderboard.size} countries total
          </div>
        )}
      </div>
      
      {/* Live Feed */}
      <div className="absolute bottom-4 right-4 bg-black/80 backdrop-blur-md rounded-xl border border-white/10 w-96 max-h-80 overflow-hidden z-[1000]">
        <div className="px-4 py-3 border-b border-white/10 flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${
              !isPaused ? 'bg-neon-green animate-ping' : 'bg-gray-500'
            }`}></span>
            <span className={`relative inline-flex rounded-full h-2 w-2 ${
              !isPaused ? 'bg-neon-green' : 'bg-gray-500'
            }`}></span>
          </span>
          <span className="text-sm font-medium text-white">Live Feed</span>
          <span className="text-xs text-text-muted ml-auto">
            Polling every {POLL_INTERVAL / 1000}s
          </span>
        </div>
        <div className="overflow-y-auto max-h-60">
          {recentList.filter(a => filtersRef.current[a.honeypot]).map((attack, i) => (
            <div 
              key={attack.id}
              className="px-4 py-2.5 border-b border-white/5 hover:bg-white/5 transition-colors animate-slide-in"
              style={{ 
                opacity: 1 - i * 0.03,
                animationDelay: `${i * 20}ms`
              }}
            >
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span 
                    className="w-2 h-2 rounded-full animate-pulse"
                    style={{ backgroundColor: HONEYPOT_COLORS[attack.honeypot] }}
                  />
                  <span className="text-text-secondary">
                    {attack.src_country || 'Unknown'} → 
                    <span className="capitalize ml-1">{attack.honeypot}</span>
                    {attack.port && <span className="text-text-muted"> :{attack.port}</span>}
                  </span>
                </div>
                <span className="text-text-muted">{formatTime(attack.timestamp)}</span>
              </div>
              <div className="text-sm font-mono mt-1" style={{ color: HONEYPOT_COLORS[attack.honeypot] }}>
                {attack.src_ip}
              </div>
            </div>
          ))}
          {recentList.length === 0 && (
            <div className="px-4 py-12 text-center">
              <div className="text-4xl mb-3">🌍</div>
              <div className="text-text-secondary text-sm">Waiting for attacks...</div>
              <div className="text-text-muted text-xs mt-2">
                First poll in {nextPoll}s
              </div>
            </div>
          )}
        </div>
      </div>
      
      {/* Map type indicator */}
      <div className="absolute bottom-4 left-1/2 -translate-x-1/2 bg-black/50 backdrop-blur-md rounded-full px-4 py-1.5 border border-white/10 z-[1000]">
        <span className="text-xs text-text-muted">
          {TILE_LAYERS[tileLayer].name} • Zoom: scroll/pinch • Pan: drag
        </span>
      </div>
    </div>
  );
}
