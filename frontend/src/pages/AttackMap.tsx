import { useEffect, useRef, useState, useCallback } from 'react';
import { ComposableMap, Geographies, Geography, Marker, type Geography as GeoType } from 'react-simple-maps';
import { Filter, Pause, Play, Maximize2, Minimize2, Zap, RefreshCw } from 'lucide-react';
import api from '../services/api';

// World map TopoJSON
const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

// Zurich coordinates (target)
const TARGET_COORDS: [number, number] = [8.5417, 47.3769];

// Honeypot colors (no firewall - it has its own dedicated map)
const HONEYPOT_COLORS: Record<string, string> = {
  cowrie: '#39ff14',
  dionaea: '#00d4ff',
  galah: '#ff6600',
  rdpy: '#bf00ff',
  heralding: '#ff3366',
};

interface Attack {
  id: string;
  timestamp: string;
  honeypot: string;
  src_ip: string;
  src_lat: number;
  src_lon: number;
  src_country: string | null | undefined;
  port: number | null | undefined;
  age: number;
  opacity: number;
  pulsePhase: number;
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

export default function AttackMap() {
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const [recentList, setRecentList] = useState<Attack[]>([]);
  const [isPaused, setIsPaused] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters] = useState<Record<string, boolean>>({
    cowrie: true,
    dionaea: true,
    galah: true,
    rdpy: true,
    heralding: true,
  });
  const [stats, setStats] = useState({ attacks: 0, ips: 0, countries: 0 });
  const [wsStatus, setWsStatus] = useState<'connecting' | 'connected' | 'disconnected'>('disconnected');
  const [error, setError] = useState<string | null>(null);
  
  const containerRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const attackIdRef = useRef(0);
  const animationRef = useRef<number>();
  const filtersRef = useRef(filters);
  const pollIntervalRef = useRef<ReturnType<typeof setInterval>>();
  
  // Keep filters ref in sync
  useEffect(() => {
    filtersRef.current = filters;
  }, [filters]);
  
  // Add a new attack
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
      src_country: data.src_country,
      port: data.port,
      age: 0,
      opacity: 1,
      pulsePhase: 0,
    };
    
    setAttacks(prev => [...prev.slice(-100), attack]);
    setRecentList(prev => [attack, ...prev.slice(0, 14)]);
  }, []);
  
  // Animation loop
  useEffect(() => {
    let lastTime = performance.now();
    
    const animate = (time: number) => {
      const delta = (time - lastTime) / 1000;
      lastTime = time;
      
      setAttacks(prev => prev
        .map(a => ({
          ...a,
          age: a.age + delta,
          opacity: Math.max(0, 1 - a.age / 8),
          pulsePhase: (a.pulsePhase + delta * 3) % (Math.PI * 2),
        }))
        .filter(a => a.opacity > 0)
      );
      
      animationRef.current = requestAnimationFrame(animate);
    };
    
    animationRef.current = requestAnimationFrame(animate);
    return () => {
      if (animationRef.current) cancelAnimationFrame(animationRef.current);
    };
  }, []);
  
  // Polling fallback when WebSocket fails
  const startPolling = useCallback(() => {
    if (pollIntervalRef.current) return;
    
    const seenIds = new Set<string>();
    
    pollIntervalRef.current = setInterval(async () => {
      if (isPaused) return;
      
      try {
        const attacks = await api.getRecentAttacks(20);
        attacks.forEach(attack => {
          if (!seenIds.has(attack.id)) {
            seenIds.add(attack.id);
            addAttack(attack);
          }
        });
        
        // Limit seen IDs set size
        if (seenIds.size > 500) {
          const arr = Array.from(seenIds);
          seenIds.clear();
          arr.slice(-200).forEach(id => seenIds.add(id));
        }
      } catch (e) {
        console.error('Polling error:', e);
      }
    }, 3000);
  }, [addAttack, isPaused]);
  
  const stopPolling = useCallback(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = undefined;
    }
  }, []);
  
  // WebSocket connection
  useEffect(() => {
    if (isPaused) {
      stopPolling();
      return;
    }
    
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const hostname = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
      ? 'localhost'
      : window.location.hostname;
    const wsUrl = `${protocol}//${hostname}:8000/api/attackmap/ws`;
    
    let reconnectTimeout: ReturnType<typeof setTimeout>;
    let retryCount = 0;
    
    const connect = () => {
      try {
        setWsStatus('connecting');
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;
        
        ws.onopen = () => {
          console.log('Attack map WebSocket connected');
          setWsStatus('connected');
          setError(null);
          retryCount = 0;
          stopPolling();
        };
        
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'attack' && data.event) {
              addAttack(data.event);
            } else if (data.type === 'stats') {
              setStats({
                attacks: data.total_attacks || 0,
                ips: data.unique_ips || 0,
                countries: data.countries || 0,
              });
            }
          } catch (e) {
            console.error('WebSocket message error:', e);
          }
        };
        
        ws.onclose = () => {
          console.log('WebSocket closed');
          setWsStatus('disconnected');
          retryCount++;
          
          // After 3 retries, fall back to polling
          if (retryCount >= 3) {
            console.log('Falling back to polling');
            startPolling();
          } else {
            const delay = Math.min(1000 * Math.pow(2, retryCount), 10000);
            reconnectTimeout = setTimeout(connect, delay);
          }
        };
        
        ws.onerror = () => {
          setError('WebSocket error');
          ws.close();
        };
      } catch (e) {
        console.error('WebSocket connection failed:', e);
        setWsStatus('disconnected');
        startPolling();
      }
    };
    
    connect();
    
    return () => {
      clearTimeout(reconnectTimeout);
      stopPolling();
      wsRef.current?.close();
    };
  }, [isPaused, addAttack, startPolling, stopPolling]);
  
  // Fetch initial data
  useEffect(() => {
    const fetchInitial = async () => {
      try {
        const [statsData, attacksData] = await Promise.all([
          api.getAttackMapStats(),
          api.getRecentAttacks(30),
        ]);
        
        setStats({
          attacks: statsData.total_attacks,
          ips: statsData.unique_ips,
          countries: statsData.countries,
        });
        
        // Stagger initial attacks
        attacksData.forEach((attack, i) => {
          setTimeout(() => {
            addAttack(attack);
          }, i * 100);
        });
      } catch (e) {
        console.error('Failed to fetch initial data:', e);
        setError('Failed to load initial data');
      }
    };
    
    fetchInitial();
  }, [addAttack]);
  
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
  
  // Manual refresh
  const handleRefresh = async () => {
    try {
      const [statsData, attacksData] = await Promise.all([
        api.getAttackMapStats(),
        api.getRecentAttacks(20),
      ]);
      
      setStats({
        attacks: statsData.total_attacks,
        ips: statsData.unique_ips,
        countries: statsData.countries,
      });
      
      attacksData.forEach((attack, i) => {
        setTimeout(() => addAttack(attack), i * 50);
      });
    } catch (e) {
      console.error('Refresh failed:', e);
    }
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

  return (
    <div 
      ref={containerRef}
      className={`relative bg-[#0a0a12] rounded-xl overflow-hidden ${
        isFullscreen ? 'fixed inset-0 z-50' : 'h-[calc(100vh-120px)]'
      }`}
    >
      {/* Map */}
      <div className="absolute inset-0">
        <ComposableMap
          projection="geoMercator"
          projectionConfig={{
            scale: 140,
            center: [10, 35],
          }}
          style={{ width: '100%', height: '100%' }}
        >
          {/* World map */}
          <Geographies geography={GEO_URL}>
            {({ geographies }: { geographies: GeoType[] }) =>
              geographies.map((geo: GeoType) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill="#1a1a2e"
                  stroke="#2a2a4a"
                  strokeWidth={0.5}
                  style={{
                    default: { outline: 'none' },
                    hover: { outline: 'none', fill: '#252545' },
                    pressed: { outline: 'none' },
                  }}
                />
              ))
            }
          </Geographies>
          
          {/* Target marker (Zurich) */}
          <Marker coordinates={TARGET_COORDS}>
            <circle r={8} fill="#ffffff" fillOpacity={0.3} />
            <circle r={4} fill="#ffffff" />
            <circle r={12} fill="none" stroke="#ffffff" strokeWidth={1} strokeOpacity={0.5}>
              <animate attributeName="r" from="8" to="20" dur="2s" repeatCount="indefinite" />
              <animate attributeName="stroke-opacity" from="0.5" to="0" dur="2s" repeatCount="indefinite" />
            </circle>
          </Marker>
          
          {/* Attack markers */}
          {visibleAttacks.map((attack) => {
            const color = HONEYPOT_COLORS[attack.honeypot] || '#ffffff';
            const pulseSize = 6 + Math.sin(attack.pulsePhase) * 2;
            
            return (
              <Marker key={attack.id} coordinates={[attack.src_lon, attack.src_lat]}>
                {/* Outer pulse ring */}
                <circle
                  r={pulseSize + 8}
                  fill="none"
                  stroke={color}
                  strokeWidth={1}
                  opacity={attack.opacity * 0.3}
                />
                {/* Inner glow */}
                <circle
                  r={pulseSize + 3}
                  fill={color}
                  opacity={attack.opacity * 0.2}
                />
                {/* Core dot */}
                <circle
                  r={pulseSize}
                  fill={color}
                  opacity={attack.opacity}
                  style={{
                    filter: `drop-shadow(0 0 ${4 + attack.pulsePhase}px ${color})`,
                  }}
                />
              </Marker>
            );
          })}
        </ComposableMap>
      </div>
      
      {/* Stats Overlay */}
      <div className="absolute top-4 left-4 bg-black/70 backdrop-blur-md rounded-xl p-5 border border-white/10">
        <div className="flex items-center gap-2 mb-4">
          <Zap className="w-4 h-4 text-neon-green" />
          <span className="text-xs uppercase tracking-wider text-text-muted">Live Stats</span>
          <span className={`w-2 h-2 rounded-full ml-2 ${
            wsStatus === 'connected' ? 'bg-neon-green animate-pulse' : 
            wsStatus === 'connecting' ? 'bg-yellow-500 animate-pulse' : 'bg-red-500'
          }`} />
        </div>
        <div className="grid grid-cols-3 gap-8">
          <div>
            <div className="text-3xl font-display font-bold text-neon-green">
              {stats.attacks.toLocaleString()}
            </div>
            <div className="text-xs text-text-secondary mt-1">Attacks</div>
          </div>
          <div>
            <div className="text-3xl font-display font-bold text-neon-blue">
              {stats.ips.toLocaleString()}
            </div>
            <div className="text-xs text-text-secondary mt-1">Unique IPs</div>
          </div>
          <div>
            <div className="text-3xl font-display font-bold text-neon-orange">
              {stats.countries}
            </div>
            <div className="text-xs text-text-secondary mt-1">Countries</div>
          </div>
        </div>
        {error && (
          <div className="mt-2 text-xs text-red-400">{error}</div>
        )}
      </div>
      
      {/* Controls */}
      <div className="absolute top-4 right-4 flex gap-2">
        <button
          onClick={handleRefresh}
          className="p-3 rounded-lg bg-black/50 backdrop-blur-md border border-white/10 text-text-secondary hover:text-neon-green transition-all"
          title="Refresh Data"
        >
          <RefreshCw className="w-5 h-5" />
        </button>
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={`p-3 rounded-lg backdrop-blur-md border transition-all ${
            showFilters 
              ? 'bg-neon-green/20 border-neon-green text-neon-green' 
              : 'bg-black/50 border-white/10 text-text-secondary hover:text-white'
          }`}
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
        >
          {isPaused ? <Play className="w-5 h-5" /> : <Pause className="w-5 h-5" />}
        </button>
        <button
          onClick={toggleFullscreen}
          className="p-3 rounded-lg bg-black/50 backdrop-blur-md border border-white/10 text-text-secondary hover:text-white transition-all"
        >
          {isFullscreen ? <Minimize2 className="w-5 h-5" /> : <Maximize2 className="w-5 h-5" />}
        </button>
      </div>
      
      {/* Filters Panel */}
      {showFilters && (
        <div className="absolute top-20 right-4 bg-black/80 backdrop-blur-md rounded-xl p-4 border border-white/10 min-w-[200px]">
          <div className="text-sm font-medium text-white mb-3">Filter Honeypots</div>
          {Object.entries(HONEYPOT_COLORS).map(([honeypot, color]) => (
            <label key={honeypot} className="flex items-center gap-3 py-2 cursor-pointer group">
              <input
                type="checkbox"
                checked={filters[honeypot]}
                onChange={() => setFilters(prev => ({ ...prev, [honeypot]: !prev[honeypot] }))}
                className="w-4 h-4 rounded border-white/20 bg-transparent"
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
      <div className="absolute bottom-4 left-4 bg-black/70 backdrop-blur-md rounded-xl p-4 border border-white/10">
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
      
      {/* Live Feed */}
      <div className="absolute bottom-4 right-4 bg-black/80 backdrop-blur-md rounded-xl border border-white/10 w-80 max-h-72 overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${
              wsStatus === 'connected' ? 'bg-neon-green animate-ping' : 'bg-gray-500'
            }`}></span>
            <span className={`relative inline-flex rounded-full h-2 w-2 ${
              wsStatus === 'connected' ? 'bg-neon-green' : 'bg-gray-500'
            }`}></span>
          </span>
          <span className="text-sm font-medium text-white">Live Feed</span>
          <span className="text-xs text-text-muted ml-auto">
            {wsStatus === 'connected' ? 'Real-time' : wsStatus === 'connecting' ? 'Connecting...' : 'Polling'}
          </span>
        </div>
        <div className="overflow-y-auto max-h-56">
          {recentList.filter(a => filtersRef.current[a.honeypot]).map((attack, i) => (
            <div 
              key={attack.id}
              className="px-4 py-2.5 border-b border-white/5 hover:bg-white/5 transition-colors"
              style={{ opacity: 1 - i * 0.05 }}
            >
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span 
                    className="w-2 h-2 rounded-full"
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
            <div className="px-4 py-8 text-center text-text-muted text-sm">
              Waiting for attacks...
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
