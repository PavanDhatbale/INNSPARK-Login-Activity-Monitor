import React, { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(() => localStorage.getItem('session_token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadUser() {
      const savedToken = localStorage.getItem('session_token');
      if (savedToken) {
        try {
          const profile = await api.getCurrentUser();
          setUser(profile);
        } catch (err) {
          console.error('Failed to restore session:', err);
          localStorage.removeItem('session_token');
          setToken(null);
          setUser(null);
        }
      }
      setLoading(false);
    }
    loadUser();
  }, []);

  const saveAuth = (sessionToken, userInfo) => {
    localStorage.setItem('session_token', sessionToken);
    setToken(sessionToken);
    setUser(userInfo);
  };

  const logout = async () => {
    try {
      await api.logout();
    } catch (e) {
      // Ignore network errors on logout
    }
    localStorage.removeItem('session_token');
    setToken(null);
    setUser(null);
  };

  const isAdmin = user && (user.role === 'ADMIN' || user.role === 'SUPERADMIN');

  return (
    <AuthContext.Provider value={{ user, token, loading, saveAuth, logout, isAdmin, setUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
