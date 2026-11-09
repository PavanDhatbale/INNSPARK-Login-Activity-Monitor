import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="loading-screen">
        <div className="spinner"></div>
        <p>Verifying session security...</p>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return children;
}

export function AdminRoute({ children }) {
  const { user, loading, isAdmin } = useAuth();

  if (loading) {
    return (
      <div className="loading-screen">
        <div className="spinner"></div>
        <p>Verifying administrative privileges...</p>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (!isAdmin) {
    return (
      <div className="forbidden-card container">
        <h2>Access Denied (HTTP 403)</h2>
        <p>You do not have administrative permissions to view this dashboard.</p>
        <p>Required role: <strong>ADMIN</strong> or <strong>SUPERADMIN</strong>. Your current role: <strong>{user.role}</strong>.</p>
        <a href="/dashboard" className="btn btn-primary">Return to My Dashboard</a>
      </div>
    );
  }

  return children;
}
