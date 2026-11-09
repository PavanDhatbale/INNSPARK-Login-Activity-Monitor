import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import { useAuth } from '../context/AuthContext';
import Navbar from '../components/Navbar';

export default function UserDashboardPage() {
  const { user } = useAuth();

  // Metrics state
  const [stats, setStats] = useState(null);
  const [statsLoading, setStatsLoading] = useState(true);

  // Login history state
  const [history, setHistory] = useState([]);
  const [historyPage, setHistoryPage] = useState(0);
  const [historyTotalPages, setHistoryTotalPages] = useState(0);
  const [historyTotalElements, setHistoryTotalElements] = useState(0);
  const [statusFilter, setStatusFilter] = useState('');
  const [historyLoading, setHistoryLoading] = useState(true);

  // Suspicious activities state
  const [suspiciousList, setSuspiciousList] = useState([]);
  const [suspiciousPage, setSuspiciousPage] = useState(0);
  const [suspiciousTotalPages, setSuspiciousTotalPages] = useState(0);
  const [suspiciousLoading, setSuspiciousLoading] = useState(true);

  // Global error
  const [error, setError] = useState('');

  // Fetch stats
  const fetchStats = useCallback(async () => {
    try {
      setStatsLoading(true);
      const data = await api.getUserStats();
      setStats(data);
    } catch (err) {
      console.error('Failed to load user stats:', err);
      setError('Could not load overview statistics.');
    } finally {
      setStatsLoading(false);
    }
  }, []);

  // Fetch login history
  const fetchHistory = useCallback(async (page = 0, status = '') => {
    try {
      setHistoryLoading(true);
      const filter = status || null;
      const data = await api.getUserLoginHistory(filter, page, 8);
      setHistory(data.content || []);
      setHistoryPage(data.page || 0);
      setHistoryTotalPages(data.totalPages || 0);
      setHistoryTotalElements(data.totalElements || 0);
    } catch (err) {
      console.error('Failed to load login history:', err);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  // Fetch suspicious activities
  const fetchSuspicious = useCallback(async (page = 0) => {
    try {
      setSuspiciousLoading(true);
      const data = await api.getUserSuspiciousActivities(page, 5);
      setSuspiciousList(data.content || []);
      setSuspiciousPage(data.page || 0);
      setSuspiciousTotalPages(data.totalPages || 0);
    } catch (err) {
      console.error('Failed to load suspicious activities:', err);
    } finally {
      setSuspiciousLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStats();
    fetchHistory(0, statusFilter);
    fetchSuspicious(0);
  }, [fetchStats, fetchHistory, fetchSuspicious, statusFilter]);

  const handleFilterChange = (e) => {
    const newStatus = e.target.value;
    setStatusFilter(newStatus);
    setHistoryPage(0);
    fetchHistory(0, newStatus);
  };

  const formatDateTime = (isoString) => {
    if (!isoString) return 'Never';
    const date = new Date(isoString);
    return date.toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'medium',
    });
  };

  return (
    <div className="dashboard-layout">
      <Navbar />

      <main className="dashboard-content container">
        {/* Welcome Banner */}
        <section className="welcome-banner">
          <div>
            <h1>Security Activity Dashboard</h1>
            <p className="subtitle">
              Real-time monitoring and authentication telemetry for <strong>{user?.username}</strong> ({user?.email})
            </p>
          </div>
          <button onClick={() => { fetchStats(); fetchHistory(historyPage, statusFilter); fetchSuspicious(suspiciousPage); }} className="btn btn-secondary btn-sm">
            🔄 Refresh Metrics
          </button>
        </section>

        {error && (
          <div className="alert alert-danger" role="alert">
            <span>{error}</span>
          </div>
        )}

        {/* 1. Overview Cards */}
        <section className="stats-grid">
          <div className="stat-card">
            <div className="stat-icon-wrapper blue">📊</div>
            <div className="stat-info">
              <span className="stat-label">Total Login Attempts</span>
              <span className="stat-value">
                {statsLoading ? '...' : (stats?.totalLoginAttempts ?? 0)}
              </span>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon-wrapper green">✅</div>
            <div className="stat-info">
              <span className="stat-label">Successful Logins</span>
              <span className="stat-value text-success">
                {statsLoading ? '...' : (stats?.successfulLogins ?? 0)}
              </span>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon-wrapper red">❌</div>
            <div className="stat-info">
              <span className="stat-label">Failed Logins</span>
              <span className="stat-value text-danger">
                {statsLoading ? '...' : (stats?.failedLogins ?? 0)}
              </span>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon-wrapper orange">⚠️</div>
            <div className="stat-info">
              <span className="stat-label">Suspicious Incidents</span>
              <span className="stat-value text-warning">
                {statsLoading ? '...' : (stats?.suspiciousActivities ?? 0)}
              </span>
            </div>
          </div>
        </section>

        {/* Timestamp telemetry bar */}
        <div className="telemetry-bar">
          <div className="telemetry-item">
            <span className="telemetry-label">Latest Login Attempt:</span>
            <span className="telemetry-val">{formatDateTime(stats?.lastLogin)}</span>
          </div>
          <div className="telemetry-item">
            <span className="telemetry-label">Latest Successful Login:</span>
            <span className="telemetry-val text-success">{formatDateTime(stats?.lastSuccessfulLogin)}</span>
          </div>
        </div>

        {/* Main Content Grid: Login History + Suspicious Activity */}
        <div className="dashboard-grid">
          {/* Left Column: Login History Table */}
          <section className="card dashboard-section">
            <div className="section-header">
              <div>
                <h2>Login Attempt History</h2>
                <span className="section-subtitle">
                  Showing {history.length} of {historyTotalElements} recorded attempts
                </span>
              </div>

              {/* Status Filter Dropdown */}
              <div className="filter-group">
                <label htmlFor="status-filter">Filter:</label>
                <select
                  id="status-filter"
                  className="form-select"
                  value={statusFilter}
                  onChange={handleFilterChange}
                >
                  <option value="">All Statuses</option>
                  <option value="SUCCESS">Success Only</option>
                  <option value="FAILURE">Failures Only</option>
                </select>
              </div>
            </div>

            {historyLoading ? (
              <div className="table-loading">
                <div className="spinner-small"></div>
                <span>Loading authentication history...</span>
              </div>
            ) : history.length === 0 ? (
              <div className="empty-state">
                <p>No login attempts recorded matching the current filter.</p>
              </div>
            ) : (
              <div className="table-responsive">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>IP Address</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((item) => (
                      <tr key={item.id}>
                        <td>{formatDateTime(item.timestamp)}</td>
                        <td>
                          <code className="ip-badge">{item.ipAddress || '127.0.0.1'}</code>
                        </td>
                        <td>
                          <span
                            className={`status-pill ${
                              item.status === 'SUCCESS' ? 'pill-success' : 'pill-failure'
                            }`}
                          >
                            {item.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Pagination Controls */}
            {historyTotalPages > 1 && (
              <div className="pagination">
                <button
                  onClick={() => fetchHistory(historyPage - 1, statusFilter)}
                  disabled={historyPage === 0 || historyLoading}
                  className="btn btn-sm btn-secondary"
                >
                  Previous
                </button>
                <span className="page-indicator">
                  Page {historyPage + 1} of {historyTotalPages}
                </span>
                <button
                  onClick={() => fetchHistory(historyPage + 1, statusFilter)}
                  disabled={historyPage >= historyTotalPages - 1 || historyLoading}
                  className="btn btn-sm btn-secondary"
                >
                  Next
                </button>
              </div>
            )}
          </section>

          {/* Right Column: Suspicious Activity Timeline */}
          <section className="card dashboard-section">
            <div className="section-header">
              <div>
                <h2>Suspicious Activity Timeline</h2>
                <span className="section-subtitle">Real-time incident detection telemetry</span>
              </div>
            </div>

            {suspiciousLoading ? (
              <div className="table-loading">
                <div className="spinner-small"></div>
                <span>Loading incident telemetry...</span>
              </div>
            ) : suspiciousList.length === 0 ? (
              <div className="empty-state safe-state">
                <span className="safe-icon">🛡️</span>
                <h3>No Anomalies Detected</h3>
                <p>All authentication activity for this account complies with security baselines.</p>
              </div>
            ) : (
              <div className="timeline-container">
                {suspiciousList.map((incident) => (
                  <div key={incident.id} className="timeline-card">
                    <div className="timeline-card-header">
                      <span className={`severity-badge ${incident.severity ? incident.severity.toLowerCase() : 'medium'}`}>
                        {incident.severity || 'MEDIUM'}
                      </span>
                      <span className="timeline-date">
                        {formatDateTime(incident.timestamp)}
                      </span>
                    </div>
                    <p className="timeline-reason">{incident.reason}</p>
                    <div className="timeline-meta">
                      <span>Source IP:</span>
                      <code>{incident.ipAddress}</code>
                    </div>
                  </div>
                ))}

                {suspiciousTotalPages > 1 && (
                  <div className="pagination">
                    <button
                      onClick={() => fetchSuspicious(suspiciousPage - 1)}
                      disabled={suspiciousPage === 0 || suspiciousLoading}
                      className="btn btn-sm btn-secondary"
                    >
                      Previous
                    </button>
                    <span className="page-indicator">
                      Page {suspiciousPage + 1} of {suspiciousTotalPages}
                    </span>
                    <button
                      onClick={() => fetchSuspicious(suspiciousPage + 1)}
                      disabled={suspiciousPage >= suspiciousTotalPages - 1 || suspiciousLoading}
                      className="btn btn-sm btn-secondary"
                    >
                      Next
                    </button>
                  </div>
                )}
              </div>
            )}
          </section>
        </div>
      </main>
    </div>
  );
}
