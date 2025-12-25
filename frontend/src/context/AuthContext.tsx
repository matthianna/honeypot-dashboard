import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import type { User, LoginRequest } from '../types';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginRequest) => Promise<void>;
  logout: () => Promise<void>;
  resetInactivityTimer: () => void;
  timeRemaining: number | null;
  extendSession: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const INACTIVITY_TIMEOUT = 5 * 60 * 1000; // 5 minutes in milliseconds
const INACTIVITY_TIMEOUT_SECONDS = 5 * 60; // 5 minutes in seconds

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [timeRemaining, setTimeRemaining] = useState<number | null>(null);
  const navigate = useNavigate();
  const inactivityTimerRef = useRef<number | null>(null);
  const countdownIntervalRef = useRef<number | null>(null);
  const lastActivityRef = useRef<number>(Date.now());

  const clearInactivityTimer = useCallback(() => {
    if (inactivityTimerRef.current) {
      window.clearTimeout(inactivityTimerRef.current);
      inactivityTimerRef.current = null;
    }
    if (countdownIntervalRef.current) {
      window.clearInterval(countdownIntervalRef.current);
      countdownIntervalRef.current = null;
    }
  }, []);

  const handleLogout = useCallback(async () => {
    clearInactivityTimer();
    try {
      await api.logout();
    } catch {
      // Ignore logout errors
    }
    setUser(null);
    navigate('/login');
  }, [clearInactivityTimer, navigate]);

  const resetInactivityTimer = useCallback(() => {
    lastActivityRef.current = Date.now();
    clearInactivityTimer();
    setTimeRemaining(INACTIVITY_TIMEOUT_SECONDS);
    
    if (user) {
      // Set up logout timer
      inactivityTimerRef.current = window.setTimeout(() => {
        console.log('Session expired due to inactivity');
        handleLogout();
      }, INACTIVITY_TIMEOUT);
      
      // Set up countdown interval (update every second)
      countdownIntervalRef.current = window.setInterval(() => {
        const elapsed = Date.now() - lastActivityRef.current;
        const remaining = Math.max(0, Math.ceil((INACTIVITY_TIMEOUT - elapsed) / 1000));
        setTimeRemaining(remaining);
      }, 1000);
    }
  }, [user, clearInactivityTimer, handleLogout]);

  const extendSession = useCallback(() => {
    resetInactivityTimer();
  }, [resetInactivityTimer]);

  // Check for existing session on mount
  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem('access_token');
      if (token) {
        try {
          // Verify token is still valid by making a simple request
          await api.getDashboardOverview('1h');
          // Token is valid, set user
          setUser({ username: 'admin' }); // We don't store username, so use default
        } catch {
          // Token is invalid, clear it
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
        }
      }
      setIsLoading(false);
    };

    checkAuth();
  }, []);

  // Set up activity listeners
  useEffect(() => {
    if (!user) return;

    const activityEvents = ['mousedown', 'keydown', 'scroll', 'touchstart', 'mousemove'];
    
    const handleActivity = () => {
      const now = Date.now();
      // Only reset timer if more than 1 second has passed (debounce)
      if (now - lastActivityRef.current > 1000) {
        resetInactivityTimer();
      }
    };

    activityEvents.forEach(event => {
      window.addEventListener(event, handleActivity, { passive: true });
    });

    // Start initial timer
    resetInactivityTimer();

    return () => {
      activityEvents.forEach(event => {
        window.removeEventListener(event, handleActivity);
      });
      clearInactivityTimer();
    };
  }, [user, resetInactivityTimer, clearInactivityTimer]);

  const login = async (credentials: LoginRequest) => {
    const response = await api.login(credentials);
    if (response.access_token) {
      setUser({ username: credentials.username });
      navigate('/');
    }
  };

  const logout = async () => {
    await handleLogout();
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout,
        resetInactivityTimer,
        timeRemaining,
        extendSession,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

