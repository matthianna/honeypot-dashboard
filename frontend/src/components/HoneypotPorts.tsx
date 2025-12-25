import { Server, Network } from 'lucide-react';

interface PortInfo {
  port: number;
  protocol?: 'tcp' | 'udp';
  service?: string;
  internal?: number;
}

interface HoneypotPortsProps {
  honeypot: 'cowrie' | 'galah' | 'dionaea' | 'heralding' | 'rdpy';
  variant?: 'plain' | 'openai' | 'llm';
}

const HONEYPOT_PORTS: Record<string, { host: string; ports: PortInfo[] }> = {
  cowrie_plain: {
    host: '193.246.121.231',
    ports: [
      { port: 22, service: 'SSH', internal: 2222 },
    ],
  },
  cowrie_openai: {
    host: '193.246.121.232',
    ports: [
      { port: 22, service: 'SSH', internal: 2223 },
    ],
  },
  cowrie_llm: {
    host: '193.246.121.233',
    ports: [
      { port: 22, service: 'SSH', internal: 2224 },
    ],
  },
  rdpy: {
    host: '193.246.121.231',
    ports: [
      { port: 3389, service: 'RDP' },
    ],
  },
  galah: {
    host: '193.246.121.233',
    ports: [
      { port: 80, service: 'HTTP', internal: 8080 },
    ],
  },
  heralding: {
    host: '193.246.121.232',
    ports: [
      { port: 21, service: 'FTP' },
      { port: 23, service: 'Telnet' },
      { port: 25, service: 'SMTP' },
      { port: 80, service: 'HTTP' },
      { port: 110, service: 'POP3' },
      { port: 143, service: 'IMAP' },
      { port: 443, service: 'HTTPS' },
      { port: 993, service: 'IMAPS' },
      { port: 995, service: 'POP3S' },
      { port: 1080, service: 'SOCKS' },
      { port: 3306, service: 'MySQL' },
      { port: 5432, service: 'PostgreSQL' },
      { port: 5900, service: 'VNC' },
    ],
  },
  dionaea: {
    host: '192.168.211.6',
    ports: [
      { port: 21, service: 'FTP' },
      { port: 42, service: 'WINS' },
      { port: 69, protocol: 'udp', service: 'TFTP' },
      { port: 80, service: 'HTTP', internal: 8080 },
      { port: 135, service: 'MSRPC' },
      { port: 443, service: 'HTTPS' },
      { port: 445, service: 'SMB' },
      { port: 1433, service: 'MSSQL' },
      { port: 1723, service: 'PPTP' },
      { port: 1883, service: 'MQTT' },
      { port: 1900, protocol: 'udp', service: 'SSDP' },
      { port: 3306, service: 'MySQL' },
      { port: 5060, service: 'SIP' },
      { port: 5060, protocol: 'udp', service: 'SIP' },
      { port: 5061, service: 'SIPS' },
      { port: 11211, service: 'Memcached' },
    ],
  },
};

const PORT_COLORS: Record<string, string> = {
  FTP: '#ff6600',
  SSH: '#39ff14',
  Telnet: '#ff3366',
  SMTP: '#00d4ff',
  HTTP: '#ffff00',
  HTTPS: '#ffff00',
  POP3: '#bf00ff',
  IMAP: '#bf00ff',
  POP3S: '#bf00ff',
  IMAPS: '#bf00ff',
  SOCKS: '#ff9900',
  MySQL: '#00aaff',
  PostgreSQL: '#336791',
  VNC: '#00d4ff',
  RDP: '#bf00ff',
  SMB: '#ff3366',
  MSSQL: '#cc0000',
  MQTT: '#660099',
  SIP: '#00cc00',
  SIPS: '#00cc00',
  TFTP: '#ff6600',
  MSRPC: '#ff0066',
  WINS: '#999999',
  PPTP: '#6600cc',
  SSDP: '#cc6600',
  Memcached: '#00aa55',
};

export default function HoneypotPorts({ honeypot, variant }: HoneypotPortsProps) {
  let key: string = honeypot;
  if (honeypot === 'cowrie' && variant) {
    key = `cowrie_${variant}`;
  }
  
  const config = HONEYPOT_PORTS[key];
  
  if (!config) return null;
  
  return (
    <div className="bg-bg-secondary rounded-lg p-4 border border-bg-hover">
      <div className="flex items-center gap-2 mb-3">
        <Server className="w-4 h-4 text-neon-blue" />
        <span className="text-sm font-medium text-text-primary">Listening Ports</span>
        <span className="text-xs text-text-muted">({config.host})</span>
      </div>
      <div className="flex flex-wrap gap-2">
        {config.ports.map((port, idx) => (
          <div
            key={`${port.port}-${port.protocol || 'tcp'}-${idx}`}
            className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-bg-card border border-bg-hover"
            title={port.internal ? `Internal: ${port.internal}` : undefined}
          >
            <div 
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: PORT_COLORS[port.service || ''] || '#888888' }}
            />
            <span className="font-mono text-xs text-text-primary">
              {port.port}
              {port.protocol === 'udp' && <span className="text-text-muted">/udp</span>}
            </span>
            {port.service && (
              <span className="text-xs text-text-muted">({port.service})</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// For Cowrie, show all variants together
export function CowriePortsOverview() {
  const variants = [
    { name: 'Plain', key: 'cowrie_plain', color: '#39ff14' },
    { name: 'OpenAI', key: 'cowrie_openai', color: '#ff6600' },
    { name: 'LLM', key: 'cowrie_llm', color: '#00d4ff' },
  ];
  
  return (
    <div className="bg-bg-secondary rounded-lg p-4 border border-bg-hover">
      <div className="flex items-center gap-2 mb-3">
        <Network className="w-4 h-4 text-neon-green" />
        <span className="text-sm font-medium text-text-primary">Honeypot Deployment</span>
      </div>
      <div className="space-y-2">
        {variants.map((v) => {
          const config = HONEYPOT_PORTS[v.key];
          if (!config) return null;
          return (
            <div key={v.key} className="flex items-center justify-between p-2 bg-bg-card rounded-lg border border-bg-hover">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: v.color }} />
                <span className="text-sm text-text-primary">{v.name}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-text-muted">{config.host}</span>
                <span className="font-mono text-xs px-2 py-0.5 bg-neon-green/20 text-neon-green rounded">
                  :{config.ports[0]?.port}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

