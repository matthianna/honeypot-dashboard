import { useState, useEffect, useRef } from 'react';
import { Navigate } from 'react-router-dom';
import { Shield, Eye, EyeOff, AlertCircle, Lock, Fingerprint, Activity } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

// Matrix rain effect
function MatrixRain() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener('resize', resize);
    
    const chars = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF';
    const fontSize = 14;
    const columns = Math.floor(canvas.width / fontSize);
    const drops: number[] = Array(columns).fill(1);
    
    const draw = () => {
      ctx.fillStyle = 'rgba(13, 13, 18, 0.05)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      
      ctx.fillStyle = '#39ff14';
      ctx.font = `${fontSize}px monospace`;
      
      for (let i = 0; i < drops.length; i++) {
        const char = chars[Math.floor(Math.random() * chars.length)];
        const x = i * fontSize;
        const y = drops[i] * fontSize;
        
        // Vary the opacity for depth effect
        ctx.fillStyle = `rgba(57, 255, 20, ${0.1 + Math.random() * 0.4})`;
        ctx.fillText(char, x, y);
        
        if (y > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i]++;
      }
    };
    
    const interval = setInterval(draw, 50);
    
    return () => {
      clearInterval(interval);
      window.removeEventListener('resize', resize);
    };
  }, []);
  
  return <canvas ref={canvasRef} className="fixed inset-0 pointer-events-none opacity-30" />;
}

// Animated grid background
function CyberGrid() {
  return (
    <div className="fixed inset-0 pointer-events-none overflow-hidden">
      {/* Perspective grid */}
      <div 
        className="absolute inset-0 opacity-20"
        style={{
          background: `
            linear-gradient(90deg, rgba(57, 255, 20, 0.1) 1px, transparent 1px),
            linear-gradient(rgba(57, 255, 20, 0.1) 1px, transparent 1px)
          `,
          backgroundSize: '50px 50px',
          transform: 'perspective(500px) rotateX(60deg) translateY(-50%)',
          transformOrigin: 'center top',
        }}
      />
      
      {/* Horizontal scan line */}
      <div 
        className="absolute left-0 right-0 h-px bg-gradient-to-r from-transparent via-neon-green to-transparent animate-scan"
        style={{ top: '50%' }}
      />
    </div>
  );
}

// Glowing orb
function GlowOrb({ color, size, x, y, delay }: { color: string; size: number; x: string; y: string; delay: number }) {
  return (
    <div 
      className="absolute rounded-full blur-3xl animate-pulse-slow"
      style={{
        backgroundColor: color,
        width: size,
        height: size,
        left: x,
        top: y,
        animationDelay: `${delay}s`,
        opacity: 0.15,
      }}
    />
  );
}

export default function Login() {
  const { isAuthenticated, login, isLoading } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [mounted, setMounted] = useState(false);
  const [focusedField, setFocusedField] = useState<string | null>(null);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await login({ username, password });
    } catch (err) {
      setError('Invalid credentials. Access denied.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-bg-primary flex items-center justify-center">
        <div className="relative">
          <div className="w-20 h-20 border-2 border-neon-green/30 rounded-full" />
          <div className="w-20 h-20 border-2 border-neon-green border-t-transparent rounded-full animate-spin absolute inset-0" />
          <Shield className="w-8 h-8 text-neon-green absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-bg-primary overflow-hidden flex relative">
      {/* Matrix rain effect */}
      <MatrixRain />
      
      {/* Cyber grid */}
      <CyberGrid />
      
      {/* Glow orbs */}
      <GlowOrb color="#39ff14" size={400} x="-10%" y="20%" delay={0} />
      <GlowOrb color="#00d4ff" size={350} x="70%" y="60%" delay={2} />
      <GlowOrb color="#bf00ff" size={300} x="30%" y="80%" delay={4} />
      
      {/* Left side - Branding */}
      <div className="hidden lg:flex flex-1 flex-col justify-center items-center p-12 relative">
        <div className={`text-center transition-all duration-1000 ${mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}`}>
          {/* Animated logo */}
          <div className="relative mb-8 inline-block">
            <div className="w-32 h-32 relative">
              {/* Outer ring */}
              <div className="absolute inset-0 border-2 border-neon-green/30 rounded-full animate-spin-slow" />
              {/* Middle ring */}
              <div className="absolute inset-4 border-2 border-neon-blue/30 rounded-full animate-spin-slow" style={{ animationDirection: 'reverse', animationDuration: '8s' }} />
              {/* Inner circle */}
              <div className="absolute inset-8 bg-gradient-to-br from-neon-green/20 to-neon-blue/20 rounded-full flex items-center justify-center">
                <Shield className="w-10 h-10 text-neon-green" />
              </div>
              {/* Glow effect */}
              <div className="absolute inset-0 bg-neon-green/20 rounded-full blur-2xl animate-pulse" />
            </div>
          </div>
          
          <h1 className="font-display text-5xl font-black mb-4">
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-neon-green via-neon-blue to-neon-purple animate-gradient">
              HONEYPOT
            </span>
          </h1>
          <p className="text-xl text-text-secondary mb-2">Security Intelligence Platform</p>
          <p className="text-sm text-text-muted max-w-md">
            Real-time threat monitoring and analysis across distributed honeypot sensors
          </p>
        </div>
      </div>
      
      {/* Right side - Login form */}
      <div className="flex-1 flex items-center justify-center p-8 relative">
        {/* Scanlines overlay */}
        <div 
          className="absolute inset-0 pointer-events-none opacity-[0.02]"
          style={{
            background: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,255,255,0.03) 2px, rgba(255,255,255,0.03) 4px)',
          }}
        />
        
        <div className={`w-full max-w-md transition-all duration-700 ${mounted ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-8'}`}>
          {/* Mobile logo */}
          <div className="lg:hidden text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-neon-green to-neon-blue mb-4">
              <Shield className="w-8 h-8 text-bg-primary" />
            </div>
            <h1 className="font-display text-3xl font-bold text-neon-green">HONEYPOT</h1>
          </div>
          
          {/* Login card */}
          <div className="relative">
            {/* Card glow */}
            <div className="absolute -inset-1 bg-gradient-to-r from-neon-green/20 via-neon-blue/20 to-neon-purple/20 rounded-2xl blur-xl opacity-50" />
            
            <div className="relative bg-bg-card/90 backdrop-blur-xl rounded-2xl border border-bg-hover overflow-hidden">
              {/* Header accent */}
              <div className="h-1 bg-gradient-to-r from-neon-green via-neon-blue to-neon-purple" />
              
              <div className="p-8">
                <div className="mb-6">
                  <h2 className="text-2xl font-display font-bold text-white mb-1">Secure Access</h2>
                  <p className="text-sm text-text-muted">Enter your credentials to access the dashboard</p>
                </div>
                
                <form onSubmit={handleSubmit} className="space-y-5">
                  {error && (
                    <div className="flex items-center gap-3 p-4 bg-neon-red/10 border border-neon-red/30 rounded-xl text-neon-red animate-shake">
                      <AlertCircle className="w-5 h-5 flex-shrink-0" />
                      <div>
                        <div className="text-sm font-medium">{error}</div>
                        <div className="text-xs opacity-70">Please try again</div>
                      </div>
                    </div>
                  )}

                  <div className="space-y-2">
                    <label htmlFor="username" className="block text-sm font-medium text-text-secondary">
                      Username
                    </label>
                    <div className={`relative rounded-xl transition-all duration-300 ${focusedField === 'username' ? 'ring-2 ring-neon-green/50' : ''}`}>
                      <div className="absolute left-4 top-1/2 -translate-y-1/2">
                        <Fingerprint className={`w-5 h-5 transition-colors ${focusedField === 'username' ? 'text-neon-green' : 'text-text-muted'}`} />
                      </div>
                      <input
                        id="username"
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        onFocus={() => setFocusedField('username')}
                        onBlur={() => setFocusedField(null)}
                        className="w-full pl-12 pr-4 py-3.5 bg-bg-secondary border border-bg-hover rounded-xl text-text-primary placeholder-text-muted focus:outline-none focus:border-neon-green transition-colors"
                        placeholder="Enter your username"
                        required
                        autoComplete="username"
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label htmlFor="password" className="block text-sm font-medium text-text-secondary">
                      Password
                    </label>
                    <div className={`relative rounded-xl transition-all duration-300 ${focusedField === 'password' ? 'ring-2 ring-neon-green/50' : ''}`}>
                      <div className="absolute left-4 top-1/2 -translate-y-1/2">
                        <Lock className={`w-5 h-5 transition-colors ${focusedField === 'password' ? 'text-neon-green' : 'text-text-muted'}`} />
                      </div>
                      <input
                        id="password"
                        type={showPassword ? 'text' : 'password'}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        onFocus={() => setFocusedField('password')}
                        onBlur={() => setFocusedField(null)}
                        className="w-full pl-12 pr-12 py-3.5 bg-bg-secondary border border-bg-hover rounded-xl text-text-primary placeholder-text-muted focus:outline-none focus:border-neon-green transition-colors"
                        placeholder="Enter your password"
                        required
                        autoComplete="current-password"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-4 top-1/2 -translate-y-1/2 text-text-muted hover:text-neon-green transition-colors"
                      >
                        {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                      </button>
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full py-4 px-6 bg-gradient-to-r from-neon-green to-neon-blue text-bg-primary font-bold rounded-xl hover:shadow-lg hover:shadow-neon-green/25 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-3 group relative overflow-hidden"
                  >
                    {/* Button shine effect */}
                    <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700" />
                    
                    {loading ? (
                      <>
                        <div className="w-5 h-5 border-2 border-bg-primary border-t-transparent rounded-full animate-spin" />
                        <span>Authenticating...</span>
                      </>
                    ) : (
                      <>
                        <Shield className="w-5 h-5" />
                        <span>Access Dashboard</span>
                      </>
                    )}
                  </button>
                </form>
              </div>
              
              {/* Footer */}
              <div className="px-8 py-4 bg-bg-secondary/50 border-t border-bg-hover">
                <div className="flex items-center justify-between text-xs text-text-muted">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 bg-neon-green rounded-full animate-pulse" />
                    <span>System Online</span>
                  </div>
                  <span>Secure Connection</span>
                </div>
              </div>
            </div>
          </div>
          
          {/* Security badges */}
          <div className="mt-6 flex items-center justify-center gap-6 text-xs text-text-muted">
            <div className="flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5" />
              <span>256-bit SSL</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5" />
              <span>JWT Auth</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5" />
              <span>Session Monitored</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
