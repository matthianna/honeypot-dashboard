import { useEffect, useState } from 'react';
import { Clock, LogOut, RefreshCw } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function SessionTimeoutWarning() {
  const { timeRemaining, extendSession, logout, isAuthenticated } = useAuth();
  const [isVisible, setIsVisible] = useState(false);

  // Show warning when under 60 seconds
  useEffect(() => {
    if (isAuthenticated && timeRemaining !== null && timeRemaining <= 60) {
      setIsVisible(true);
    } else {
      setIsVisible(false);
    }
  }, [timeRemaining, isAuthenticated]);

  if (!isVisible || timeRemaining === null) {
    return null;
  }

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    if (mins > 0) {
      return `${mins}:${secs.toString().padStart(2, '0')}`;
    }
    return `${secs}s`;
  };

  const urgencyColor = timeRemaining <= 10 
    ? 'from-red-600/95 to-red-800/95 border-red-500' 
    : timeRemaining <= 30 
      ? 'from-orange-600/95 to-orange-800/95 border-orange-500'
      : 'from-yellow-600/95 to-yellow-800/95 border-yellow-500';

  const pulseClass = timeRemaining <= 10 ? 'animate-pulse' : '';

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      
      {/* Modal */}
      <div className={`relative bg-gradient-to-b ${urgencyColor} rounded-2xl border-2 shadow-2xl max-w-md w-full overflow-hidden ${pulseClass}`}>
        {/* Animated background effect */}
        <div className="absolute inset-0 opacity-20">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(255,255,255,0.1),transparent_70%)]" />
        </div>
        
        <div className="relative p-6">
          {/* Icon and Title */}
          <div className="flex items-center justify-center mb-4">
            <div className="w-16 h-16 rounded-full bg-white/20 flex items-center justify-center">
              <Clock className={`w-8 h-8 text-white ${timeRemaining <= 10 ? 'animate-spin' : ''}`} 
                     style={{ animationDuration: '2s' }} />
            </div>
          </div>
          
          <h2 className="text-xl font-display font-bold text-white text-center mb-2">
            Session Expiring Soon
          </h2>
          
          <p className="text-white/80 text-center text-sm mb-4">
            Your session will expire due to inactivity
          </p>
          
          {/* Countdown Timer */}
          <div className="bg-black/30 rounded-xl p-4 mb-6">
            <div className="text-center">
              <div className={`text-5xl font-display font-bold text-white mb-1 ${timeRemaining <= 10 ? 'text-red-200' : ''}`}>
                {formatTime(timeRemaining)}
              </div>
              <div className="text-white/60 text-xs uppercase tracking-wider">
                Time Remaining
              </div>
            </div>
            
            {/* Progress bar */}
            <div className="mt-4 h-2 bg-black/30 rounded-full overflow-hidden">
              <div 
                className="h-full bg-white/80 rounded-full transition-all duration-1000 ease-linear"
                style={{ width: `${(timeRemaining / 60) * 100}%` }}
              />
            </div>
          </div>
          
          {/* Actions */}
          <div className="flex gap-3">
            <button
              onClick={extendSession}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-3 bg-white text-gray-900 rounded-xl font-semibold hover:bg-gray-100 transition-colors"
            >
              <RefreshCw className="w-4 h-4" />
              Stay Logged In
            </button>
            <button
              onClick={logout}
              className="flex items-center justify-center gap-2 px-4 py-3 bg-white/20 text-white rounded-xl font-semibold hover:bg-white/30 transition-colors"
            >
              <LogOut className="w-4 h-4" />
              Logout
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}




