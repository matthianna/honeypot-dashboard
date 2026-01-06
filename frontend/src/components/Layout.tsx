import { Outlet, NavLink, useLocation } from 'react-router-dom';
import { useState, useEffect } from 'react';
import {
  LayoutDashboard,
  Map,
  Terminal,
  Bug,
  Globe,
  Monitor,
  Shield,
  ShieldAlert,
  LogOut,
  Menu,
  X,
  ChevronDown,
  Users,
  PanelLeftClose,
  PanelLeft,
  Crosshair,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import SessionTimeoutWarning from './SessionTimeoutWarning';

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Attack Map', href: '/attack-map', icon: Map },
  { name: 'Firewall Map', href: '/firewall-map', icon: ShieldAlert },
  { name: 'MITRE ATT&CK', href: '/mitre', icon: Crosshair },
  { name: 'Attackers', href: '/attackers', icon: Users },
];

const honeypots = [
  { name: 'Cowrie (SSH)', href: '/cowrie', icon: Terminal, color: 'text-neon-green' },
  { name: 'Dionaea', href: '/dionaea', icon: Bug, color: 'text-neon-blue' },
  { name: 'Galah (Web)', href: '/galah', icon: Globe, color: 'text-neon-orange' },
  { name: 'RDPY (RDP)', href: '/rdpy', icon: Monitor, color: 'text-neon-purple' },
  { name: 'Heralding', href: '/heralding', icon: Shield, color: 'text-neon-red' },
  { name: 'Firewall', href: '/firewall', icon: ShieldAlert, color: 'text-neon-yellow' },
];

export default function Layout() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [honeypotsOpen, setHoneypotsOpen] = useState(true);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    const saved = localStorage.getItem('honeypot_sidebarCollapsed');
    return saved === 'true';
  });

  // Persist collapsed state
  useEffect(() => {
    localStorage.setItem('honeypot_sidebarCollapsed', String(sidebarCollapsed));
  }, [sidebarCollapsed]);

  const isActive = (path: string) => {
    if (path === '/') return location.pathname === '/';
    return location.pathname.startsWith(path);
  };

  return (
    <div className="min-h-screen bg-bg-primary grid-bg">
      {/* Mobile sidebar backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 bg-bg-secondary border-r border-bg-card transform transition-all duration-300 lg:translate-x-0 ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        } ${sidebarCollapsed ? 'lg:w-16' : 'lg:w-64'} w-64`}
      >
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="flex items-center justify-between h-16 px-3 border-b border-bg-card">
            <div className={`flex items-center ${sidebarCollapsed ? 'justify-center w-full' : 'space-x-2'}`}>
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-neon-green to-neon-blue flex items-center justify-center flex-shrink-0">
                <Shield className="w-5 h-5 text-bg-primary" />
              </div>
              {!sidebarCollapsed && (
                <span className="font-display font-bold text-lg text-neon-green">
                  HONEYPOT
                </span>
              )}
            </div>
            <button
              className="lg:hidden text-text-secondary hover:text-text-primary"
              onClick={() => setSidebarOpen(false)}
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Collapse Toggle - Desktop only */}
          <div className="hidden lg:flex items-center justify-center py-2 border-b border-bg-card">
            <button
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              className="p-2 rounded-lg text-text-muted hover:text-white hover:bg-bg-hover transition-colors"
              title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            >
              {sidebarCollapsed ? <PanelLeft className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
            </button>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-2 py-4 space-y-1 overflow-y-auto">
            {navigation.map((item) => (
              <NavLink
                key={item.name}
                to={item.href}
                className={`flex items-center ${sidebarCollapsed ? 'justify-center px-2' : 'px-3'} py-2 rounded-lg transition-all duration-200 ${
                  isActive(item.href)
                    ? 'bg-bg-card text-neon-green shadow-neon-green'
                    : 'text-text-secondary hover:text-text-primary hover:bg-bg-hover'
                }`}
                onClick={() => setSidebarOpen(false)}
                title={sidebarCollapsed ? item.name : undefined}
              >
                <item.icon className={`w-5 h-5 ${sidebarCollapsed ? '' : 'mr-3'}`} />
                {!sidebarCollapsed && item.name}
              </NavLink>
            ))}

            {/* Honeypots Section */}
            <div className="pt-4">
              {!sidebarCollapsed ? (
                <button
                  onClick={() => setHoneypotsOpen(!honeypotsOpen)}
                  className="flex items-center justify-between w-full px-3 py-2 text-text-secondary hover:text-text-primary transition-colors"
                >
                  <span className="text-xs font-semibold uppercase tracking-wider">
                    Honeypots
                  </span>
                  <ChevronDown
                    className={`w-4 h-4 transition-transform ${
                      honeypotsOpen ? 'rotate-180' : ''
                    }`}
                  />
                </button>
              ) : (
                <div className="border-t border-bg-card my-2" />
              )}

              {(honeypotsOpen || sidebarCollapsed) && (
                <div className="mt-1 space-y-1">
                  {honeypots.map((item) => (
                    <NavLink
                      key={item.name}
                      to={item.href}
                      className={`flex items-center ${sidebarCollapsed ? 'justify-center px-2' : 'px-3'} py-2 rounded-lg transition-all duration-200 ${
                        isActive(item.href)
                          ? `bg-bg-card ${item.color}`
                          : 'text-text-secondary hover:text-text-primary hover:bg-bg-hover'
                      }`}
                      onClick={() => setSidebarOpen(false)}
                      title={sidebarCollapsed ? item.name : undefined}
                    >
                      <item.icon className={`w-5 h-5 ${sidebarCollapsed ? '' : 'mr-3'} ${isActive(item.href) ? item.color : ''}`} />
                      {!sidebarCollapsed && item.name}
                    </NavLink>
                  ))}
                </div>
              )}
            </div>
          </nav>

          {/* User section */}
          <div className="p-3 border-t border-bg-card">
            <div className={`flex items-center ${sidebarCollapsed ? 'justify-center' : 'justify-between'}`}>
              {!sidebarCollapsed && (
                <div className="flex items-center">
                  <div className="w-8 h-8 rounded-full bg-bg-card flex items-center justify-center">
                    <span className="text-sm font-medium text-neon-blue">
                      {user?.username?.charAt(0).toUpperCase() || 'A'}
                    </span>
                  </div>
                  <span className="ml-3 text-sm text-text-primary">
                    {user?.username || 'Admin'}
                  </span>
                </div>
              )}
              <button
                onClick={logout}
                className="p-2 text-text-secondary hover:text-neon-red transition-colors"
                title="Logout"
              >
                <LogOut className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <div className={`transition-all duration-300 ${sidebarCollapsed ? 'lg:pl-16' : 'lg:pl-64'}`}>
        {/* Top bar */}
        <header className="sticky top-0 z-30 h-16 bg-bg-secondary/80 backdrop-blur-sm border-b border-bg-card flex items-center px-4 lg:px-6">
          <button
            className="lg:hidden text-text-secondary hover:text-text-primary mr-4"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu className="w-6 h-6" />
          </button>

          <div className="flex-1">
            <h1 className="text-lg font-display font-semibold text-text-primary">
              {location.pathname === '/' && 'Dashboard'}
              {location.pathname === '/attack-map' && 'Attack Map'}
              {location.pathname === '/firewall-map' && 'Firewall Attack Map'}
              {location.pathname === '/cowrie' && 'Cowrie SSH Honeypot'}
              {location.pathname === '/dionaea' && 'Dionaea Honeypot'}
              {location.pathname === '/galah' && 'Galah Web Honeypot'}
              {location.pathname === '/rdpy' && 'RDPY RDP Honeypot'}
              {location.pathname === '/heralding' && 'Heralding Honeypot'}
              {location.pathname === '/firewall' && 'Firewall (OPNsense)'}
              {location.pathname === '/attackers' && 'Attackers'}
              {location.pathname === '/mitre' && 'MITRE ATT&CK Analysis'}
            </h1>
          </div>

          <div className="flex items-center space-x-4">
            <div className="hidden sm:flex items-center space-x-2 text-sm text-text-secondary">
              <div className="w-2 h-2 rounded-full bg-neon-green animate-pulse" />
              <span>System Online</span>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="p-4 lg:p-6">
          <Outlet />
        </main>
      </div>

      {/* Session Timeout Warning */}
      <SessionTimeoutWarning />
    </div>
  );
}

