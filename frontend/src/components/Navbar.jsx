import React from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Navbar() {
  const { user, logout, isAdmin } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  if (!user) {
    return null;
  }

  const roleBadgeClass = user.role === 'SUPERADMIN' 
    ? 'badge-superadmin' 
    : user.role === 'ADMIN' 
      ? 'badge-admin' 
      : 'badge-user';

  return (
    <header className="navbar">
      <div className="navbar-container">
        <div className="navbar-brand">
          <Link to="/dashboard" className="brand-logo">
            <span className="logo-icon">🛡️</span>
            <span className="brand-name">INNSPARK</span>
            <span className="brand-sub">Security Monitor</span>
          </Link>
        </div>

        <nav className="navbar-links">
          <Link 
            to="/dashboard" 
            className={`nav-link ${location.pathname === '/dashboard' ? 'active' : ''}`}
          >
            My Dashboard
          </Link>

          {isAdmin && (
            <Link 
              to="/admin/dashboard" 
              className={`nav-link ${location.pathname === '/admin/dashboard' ? 'active' : ''}`}
            >
              Admin Dashboard
            </Link>
          )}
        </nav>

        <div className="navbar-user">
          <div className="user-info">
            <span className="username">{user.username}</span>
            <span className={`role-badge ${roleBadgeClass}`}>{user.role}</span>
          </div>
          <button onClick={handleLogout} className="btn-logout" title="Sign out of active session">
            Sign Out
          </button>
        </div>
      </div>
    </header>
  );
}
