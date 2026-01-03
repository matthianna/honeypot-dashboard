import { useEffect, useState } from 'react';
import { CircleMarker, Popup, useMap } from 'react-leaflet';
import type { LatLngExpression } from 'leaflet';

// Honeypot colors
const HONEYPOT_COLORS: Record<string, string> = {
  cowrie: '#39ff14',
  dionaea: '#00d4ff',
  galah: '#ff6600',
  rdpy: '#bf00ff',
  heralding: '#ff3366',
};

export interface AttackData {
  id: string;
  timestamp: string;
  honeypot: string;
  src_ip: string;
  src_lat: number;
  src_lon: number;
  src_country: string | null;
  port: number | null;
}

interface AttackMarkerProps {
  attack: AttackData;
  age: number; // Age in seconds
}

export default function AttackMarker({ attack, age }: AttackMarkerProps) {
  const [pulseSize, setPulseSize] = useState(8);
  const map = useMap();
  
  const color = HONEYPOT_COLORS[attack.honeypot] || '#ffffff';
  const position: LatLngExpression = [attack.src_lat, attack.src_lon];
  
  // Calculate opacity based on age (fade out over 15 seconds)
  const opacity = Math.max(0, 1 - age / 15);
  
  // Pulse animation
  useEffect(() => {
    const interval = setInterval(() => {
      setPulseSize(prev => {
        const newSize = prev + 0.5;
        return newSize > 20 ? 8 : newSize;
      });
    }, 50);
    
    return () => clearInterval(interval);
  }, []);
  
  if (opacity <= 0) return null;
  
  const zoom = map.getZoom();
  const baseRadius = Math.max(4, 12 - zoom / 2);
  
  return (
    <>
      {/* Outer ripple ring */}
      <CircleMarker
        center={position}
        radius={baseRadius + pulseSize}
        pathOptions={{
          color: color,
          fillColor: 'transparent',
          fillOpacity: 0,
          weight: 1,
          opacity: opacity * 0.3,
        }}
      />
      
      {/* Middle glow */}
      <CircleMarker
        center={position}
        radius={baseRadius + 4}
        pathOptions={{
          color: 'transparent',
          fillColor: color,
          fillOpacity: opacity * 0.3,
          weight: 0,
        }}
      />
      
      {/* Core marker */}
      <CircleMarker
        center={position}
        radius={baseRadius}
        pathOptions={{
          color: color,
          fillColor: color,
          fillOpacity: opacity * 0.9,
          weight: 2,
          opacity: opacity,
        }}
      >
        <Popup>
          <div className="text-sm">
            <div className="font-bold" style={{ color }}>
              {attack.honeypot.toUpperCase()}
            </div>
            <div className="mt-1">
              <strong>IP:</strong> {attack.src_ip}
            </div>
            <div>
              <strong>Country:</strong> {attack.src_country || 'Unknown'}
            </div>
            {attack.port && (
              <div>
                <strong>Port:</strong> {attack.port}
              </div>
            )}
            <div className="text-xs text-gray-500 mt-1">
              {new Date(attack.timestamp).toLocaleString()}
            </div>
          </div>
        </Popup>
      </CircleMarker>
    </>
  );
}

// Target marker for Zurich
export function TargetMarker() {
  const position: LatLngExpression = [47.3769, 8.5417];
  const [pulseSize, setPulseSize] = useState(0);
  
  useEffect(() => {
    const interval = setInterval(() => {
      setPulseSize(prev => (prev + 0.3) % 15);
    }, 50);
    return () => clearInterval(interval);
  }, []);
  
  return (
    <>
      {/* Outer pulse */}
      <CircleMarker
        center={position}
        radius={15 + pulseSize}
        pathOptions={{
          color: '#ffffff',
          fillColor: 'transparent',
          fillOpacity: 0,
          weight: 2,
          opacity: 0.5 - pulseSize / 30,
        }}
      />
      
      {/* Inner glow */}
      <CircleMarker
        center={position}
        radius={10}
        pathOptions={{
          color: '#ffffff',
          fillColor: '#ffffff',
          fillOpacity: 0.3,
          weight: 2,
          opacity: 0.8,
        }}
      />
      
      {/* Core */}
      <CircleMarker
        center={position}
        radius={5}
        pathOptions={{
          color: '#ffffff',
          fillColor: '#ffffff',
          fillOpacity: 1,
          weight: 2,
          opacity: 1,
        }}
      >
        <Popup>
          <div className="text-sm font-bold">
            🎯 Target: Zurich, Switzerland
          </div>
        </Popup>
      </CircleMarker>
    </>
  );
}







