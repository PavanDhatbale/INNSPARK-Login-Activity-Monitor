import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import { useAuth } from '../context/AuthContext';
import Navbar from '../components/Navbar';

export default function AdminDashboardPage() {
  const { user } = useAuth();

  const [adminStats, setAdminStats] = useState(null);
  const [statsLoading, setStatsLoading] = useState(true);

  // Tab: 'suspicious' or 'users'
  const [activeTab, setActiveTab] = useState('suspicious');

  // Suspicious list
  const [allSuspicious, setAllSuspicious] = useState([]);
  const [suspiciousLoading, setSuspiciousLoading] = useState(true);

  // Registered users list
  const [usersList, setUsersList] = useState([]);
  const [usersPage, setUsersPage] = useState(0);
  const [usersTotalPages, setUsersTotalPages] = useState(0);
  const [usersTotalElements, setUsersTotalElements] = useState(0);
  const [usersLoading, setUsersLoading] = useState(true);

  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [actionLoadingId, setActionLoadingId] = useState(null);

  const [selectedUserSessions, setSelectedUserSessions] = useState([]);
  const [sessionsModalOpen, setSessionsModalOpen] = useState(false);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [selectedUserForSessions, setSelectedUserForSessions] = useState(null);
  const [sessionActionLoading, setSessionActionLoading] = useState(null);
  const [drawerError, setDrawerError] = useState('');
  const [drawerSuccess, setDrawerSuccess] = useState('');

  const fetchAdminStats = useCallback(async () => {
    try {
      setStatsLoading(true);
      const data = await api.getAdminStats();
      setAdminStats(data);
    } catch (err) {
      console.error('Failed to load admin statistics:', err);
      setError('Could not retrieve administrative telemetry.');
    } finally {
      setStatsLoading(false);
    }
  }, []);

  const fetchSuspicious = useCallback(async () => {
    try {
      setSuspiciousLoading(true);
      const data = await api.getAllSuspicious();
      setAllSuspicious(data || []);
    } catch (err) {
      console.error('Failed to load system-wide suspicious activities:', err);
    } finally {
      setSuspiciousLoading(false);
    }
  }, []);

  const fetchUsers = useCallback(async (page = 0) => {
    try {
      setUsersLoading(true);
      const data = await api.getAdminUsers(page, 10);
      setUsersList(data.content || []);
      setUsersPage(data.page || 0);
      setUsersTotalPages(data.totalPages || 0);
      setUsersTotalElements(data.totalElements || 0);
    } catch (err) {
      console.error('Failed to load user accounts:', err);
    } finally {
      setUsersLoading(false);
    }
  }, []);

  const handleRoleChange = async (userId, newRole, targetUsername) => {
    try {
      setActionLoadingId(userId);
      setError('');
      setSuccessMessage('');
      const updatedUser = await api.updateUserRole(userId, newRole);
      setSuccessMessage(`Role for user "${targetUsername}" successfully updated to ${updatedUser.role}.`);
      setUsersList((prev) =>
        prev.map((u) => (u.id === userId ? { ...u, role: updatedUser.role } : u))
      );
    } catch (err) {
      console.error('Failed to update role:', err);
      setError(err.message || 'Failed to update user role.');
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleStatusToggle = async (userId, newStatus, targetUsername) => {
    try {
      setActionLoadingId(userId);
      setError('');
      setSuccessMessage('');
      const updatedUser = await api.updateUserStatus(userId, newStatus);
      setSuccessMessage(
        `Account for "${targetUsername}" has been ${updatedUser.enabled ? 'activated' : 'disabled'}.`
      );
      setUsersList((prev) =>
        prev.map((u) => (u.id === userId ? { ...u, enabled: updatedUser.enabled } : u))
      );
    } catch (err) {
      console.error('Failed to update status:', err);
      setError(err.message || 'Failed to update account status.');
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleViewSessions = async (targetAccount) => {
    setSelectedUserForSessions(targetAccount);
    setSessionsModalOpen(true);
    setSessionsLoading(true);
    setDrawerError('');
    setDrawerSuccess('');
    try {
      const data = await api.getUserSessions(targetAccount.id);
      setSelectedUserSessions(data || []);
    } catch (err) {
      console.error('Failed to load user sessions:', err);
      const errMsg = err.message || 'Failed to fetch user sessions.';
      setDrawerError(errMsg);
      setError(errMsg);
    } finally {
      setSessionsLoading(false);
    }
  };

  const handleRevokeSession = async (sessionId, targetUserId) => {
    const userId = targetUserId || selectedUserForSessions?.id;
    if (!sessionId) return;
    if (sessionActionLoading !== null) return; // Prevent duplicate submissions

    const confirmed = window.confirm(
      `Terminate session #${sessionId} for user "${selectedUserForSessions?.username || 'user'}"?\n\nThe user will be immediately logged out of this session.`
    );
    if (!confirmed) return;

    try {
      setSessionActionLoading(sessionId);
      setDrawerError('');
      setDrawerSuccess('');
      setError('');
      setSuccessMessage('');

      await api.revokeUserSession(userId, sessionId);

      const successText = `Session #${sessionId} was terminated successfully.`;
      setDrawerSuccess(successText);
      setSuccessMessage(successText);

      // Immediately remove the revoked session from the local list
      setSelectedUserSessions((prev) => prev.filter((s) => s.id !== sessionId));

      // Refresh from server to ensure complete consistency
      if (userId) {
        const updated = await api.getUserSessions(userId);
        setSelectedUserSessions(updated || []);
      }
    } catch (err) {
      console.error('Failed to revoke session:', err);
      const errMsg = err.message || 'Failed to terminate session.';
      setDrawerError(errMsg);
      setError(errMsg);
    } finally {
      setSessionActionLoading(null);
    }
  };

  const handleRevokeAllSessions = async () => {
    if (!selectedUserForSessions) return;
    if (sessionActionLoading !== null) return; // Prevent duplicate submissions

    const confirmed = window.confirm(
      `Terminate ALL active sessions for user "${selectedUserForSessions.username}"?\n\nAll active devices will be disconnected immediately.`
    );
    if (!confirmed) return;

    try {
      setSessionActionLoading('all');
      setDrawerError('');
      setDrawerSuccess('');
      setError('');
      setSuccessMessage('');

      const res = await api.revokeAllUserSessions(selectedUserForSessions.id);
      const msg = res?.message || `All active sessions for "${selectedUserForSessions.username}" have been terminated.`;
      setDrawerSuccess(msg);
      setSuccessMessage(msg);

      // Immediately clear active sessions
      setSelectedUserSessions([]);

      // Refresh from server
      const updated = await api.getUserSessions(selectedUserForSessions.id);
      setSelectedUserSessions(updated || []);
    } catch (err) {
      console.error('Failed to revoke all sessions:', err);
      const errMsg = err.message || 'Failed to terminate user sessions.';
      setDrawerError(errMsg);
      setError(errMsg);
    } finally {
      setSessionActionLoading(null);
    }
  };

  useEffect(() => {
    fetchAdminStats();
    if (activeTab === 'suspicious') {
      fetchSuspicious();
    } else if (activeTab === 'users') {
      fetchUsers(0);
    }
  }, [fetchAdminStats, fetchSuspicious, fetchUsers, activeTab]);

  const formatDateTime = (isoString) => {
    if (!isoString) return 'N/A';
    return new Date(isoString).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'medium',
    });
  };

  return (
    <div className="dashboard-layout">
      <Navbar />

      <main className="dashboard-content container">
        <section className="welcome-banner admin-banner">
          <div>
            <div className="admin-badge-header">
              <span className="shield-icon">🛡️</span>
              <span className="admin-pill">ADMINISTRATIVE TELEMETRY</span>
            </div>
            <h1>System Security Control Center</h1>
            <p className="subtitle">
              Global overview and audit logs for privileged operator: <strong>{user?.username}</strong> ({user?.role})
            </p>
          </div>
          <button
            onClick={() => {
              fetchAdminStats();
              if (activeTab === 'suspicious') fetchSuspicious();
              else fetchUsers(usersPage);
            }}
            className="btn btn-secondary btn-sm"
          >
            🔄 Refresh System Stats
          </button>
        </section>

        {error && (
          <div className="alert alert-danger" role="alert">
            <span>{error}</span>
          </div>
        )}

        {/* Admin Metric Cards Grid */}
        <section className="stats-grid admin-stats-grid">
          <div className="stat-card">
            <div className="stat-icon-wrapper purple">👥</div>
            <div className="stat-info">
              <span className="stat-label">Total Users</span>
              <span className="stat-value">
                {statsLoading ? '...' : (adminStats?.totalUsers ?? 0)}
              </span>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon-wrapper blue">📊</div>
            <div className="stat-info">
              <span className="stat-label">Total Login Attempts</span>
              <span className="stat-value">
                {statsLoading ? '...' : (adminStats?.totalLoginAttempts ?? 0)}
              </span>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon-wrapper green">✅</div>
            <div className="stat-info">
              <span className="stat-label">Successful Logins</span>
              <span className="stat-value text-success">
                {statsLoading ? '...' : (adminStats?.totalSuccessfulLogins ?? 0)}
              </span>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon-wrapper red">❌</div>
            <div className="stat-info">
              <span className="stat-label">Failed Logins</span>
              <span className="stat-value text-danger">
                {statsLoading ? '...' : (adminStats?.totalFailedLogins ?? 0)}
              </span>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon-wrapper orange">⚠️</div>
            <div className="stat-info">
              <span className="stat-label">Total Suspicious Incidents</span>
              <span className="stat-value text-warning">
                {statsLoading ? '...' : (adminStats?.totalSuspiciousActivities ?? 0)}
              </span>
            </div>
          </div>

          <div className="stat-card highlight-card">
            <div className="stat-icon-wrapper alert-red">🚨</div>
            <div className="stat-info">
              <span className="stat-label">Recent Suspicious (24h)</span>
              <span className="stat-value text-danger">
                {statsLoading ? '...' : (adminStats?.recentSuspiciousActivities ?? 0)}
              </span>
            </div>
          </div>
        </section>

        {/* Navigation Tabs */}
        <div className="admin-tabs">
          <button
            onClick={() => setActiveTab('suspicious')}
            className={`tab-btn ${activeTab === 'suspicious' ? 'active' : ''}`}
          >
            🚨 System-Wide Suspicious Activity Log ({allSuspicious.length})
          </button>
          <button
            onClick={() => setActiveTab('users')}
            className={`tab-btn ${activeTab === 'users' ? 'active' : ''}`}
          >
            👥 User Account Directory ({usersTotalElements})
          </button>
        </div>

        {/* Tab 1: System-Wide Suspicious Activity Log */}
        {activeTab === 'suspicious' && (
          <section className="card dashboard-section">
            <div className="section-header">
              <div>
                <h2>Detected Anomaly Incidents</h2>
                <span className="section-subtitle">Real-time alerts triggered by detection rules</span>
              </div>
            </div>

            {suspiciousLoading ? (
              <div className="table-loading">
                <div className="spinner-small"></div>
                <span>Querying system anomalies...</span>
              </div>
            ) : allSuspicious.length === 0 ? (
              <div className="empty-state safe-state">
                <span className="safe-icon">🛡️</span>
                <h3>No System-Wide Anomalies</h3>
                <p>No suspicious activities have been detected across any accounts.</p>
              </div>
            ) : (
              <div className="table-responsive">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Incident ID</th>
                      <th>Timestamp</th>
                      <th>Target Username</th>
                      <th>Source IP</th>
                      <th>Detection Reason</th>
                      <th>Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {allSuspicious.map((item) => (
                      <tr key={item.id}>
                        <td>#{item.id}</td>
                        <td>{formatDateTime(item.timestamp)}</td>
                        <td>
                          <strong>{item.username || 'IP Attack'}</strong>
                        </td>
                        <td>
                          <code className="ip-badge">{item.ipAddress}</code>
                        </td>
                        <td>{item.reason}</td>
                        <td>
                          <span className={`severity-badge ${item.severity ? item.severity.toLowerCase() : 'medium'}`}>
                            {item.severity || 'MEDIUM'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}

        {/* Tab 2: User Accounts Directory */}
        {activeTab === 'users' && (
          <section className="card dashboard-section">
            <div className="section-header">
              <div>
                <h2>Registered User Directory</h2>
                <span className="section-subtitle">
                  RBAC accounts registered in MySQL — Manage user roles and account statuses
                </span>
              </div>
              <button
                onClick={() => fetchUsers(usersPage)}
                disabled={usersLoading}
                className="btn btn-secondary btn-sm"
              >
                🔄 Refresh Directory
              </button>
            </div>

            {successMessage && (
              <div className="alert alert-success" role="alert" style={{ display: 'flex', alignItems: 'center' }}>
                <span>✅ {successMessage}</span>
                <button
                  type="button"
                  onClick={() => setSuccessMessage('')}
                  className="alert-dismiss-btn"
                  title="Dismiss"
                >
                  ✕
                </button>
              </div>
            )}

            {usersLoading ? (
              <div className="table-loading">
                <div className="spinner-small"></div>
                <span>Loading registered users...</span>
              </div>
            ) : usersList.length === 0 ? (
              <div className="empty-state">
                <p>No user accounts found.</p>
              </div>
            ) : (
              <div className="table-responsive">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>User ID</th>
                      <th>Username</th>
                      <th>Email</th>
                      <th>Role</th>
                      <th>Account Status</th>
                      <th>Created At</th>
                      <th>Role Management</th>
                      <th>Account Controls</th>
                      <th>Active Sessions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {usersList.map((account) => {
                      const isSelf = account.username === user?.username;
                      const isTargetSuperadmin = account.role === 'SUPERADMIN';
                      const isActorSuperadmin = user?.role === 'SUPERADMIN';
                      const isActorAdmin = user?.role === 'ADMIN';

                      return (
                        <tr key={account.id}>
                          <td>#{account.id}</td>
                          <td>
                            <strong>{account.username}</strong>
                            {isSelf && <span className="self-tag" style={{ marginLeft: '6px' }}>(You)</span>}
                          </td>
                          <td>{account.email}</td>
                          <td>
                            <span
                              className={`role-badge ${
                                account.role === 'SUPERADMIN'
                                  ? 'badge-superadmin'
                                  : account.role === 'ADMIN'
                                  ? 'badge-admin'
                                  : 'badge-user'
                              }`}
                            >
                              {account.role}
                            </span>
                          </td>
                          <td>
                            <span className={`status-pill ${account.enabled ? 'pill-success' : 'pill-failure'}`}>
                              {account.enabled ? 'ACTIVE' : 'DISABLED'}
                            </span>
                          </td>
                          <td>{formatDateTime(account.createdAt)}</td>
                          <td>
                            {isSelf ? (
                              <span className="self-tag">Cannot edit own role</span>
                            ) : isActorSuperadmin ? (
                              <div className="role-manage-wrapper">
                                <select
                                  value={account.role}
                                  disabled={actionLoadingId === account.id}
                                  onChange={(e) => handleRoleChange(account.id, e.target.value, account.username)}
                                  className="role-select"
                                  aria-label={`Change role for ${account.username}`}
                                >
                                  <option value="USER">USER</option>
                                  <option value="ADMIN">ADMIN</option>
                                  <option value="SUPERADMIN">SUPERADMIN</option>
                                </select>
                                {actionLoadingId === account.id && <span className="spinner-small"></span>}
                              </div>
                            ) : isActorAdmin ? (
                              isTargetSuperadmin ? (
                                <span className="self-tag">Protected (SUPERADMIN)</span>
                              ) : (
                                <div className="role-manage-wrapper">
                                  <select
                                    value={account.role}
                                    disabled={actionLoadingId === account.id}
                                    onChange={(e) => handleRoleChange(account.id, e.target.value, account.username)}
                                    className="role-select"
                                    aria-label={`Change role for ${account.username}`}
                                  >
                                    <option value="USER">USER</option>
                                    <option value="ADMIN">ADMIN</option>
                                  </select>
                                  {actionLoadingId === account.id && <span className="spinner-small"></span>}
                                </div>
                              )
                            ) : (
                              <span className="self-tag">Read-only</span>
                            )}
                          </td>
                          <td>
                            {isSelf ? (
                              <span className="self-tag">—</span>
                            ) : isActorAdmin && isTargetSuperadmin ? (
                              <span className="self-tag">—</span>
                            ) : (
                              <button
                                onClick={() => handleStatusToggle(account.id, !account.enabled, account.username)}
                                disabled={actionLoadingId === account.id}
                                className={`btn-xs ${account.enabled ? 'btn-outline-danger' : 'btn-outline-success'}`}
                                title={account.enabled ? 'Deactivate this user account' : 'Activate this user account'}
                              >
                                {actionLoadingId === account.id
                                  ? 'Saving...'
                                  : account.enabled
                                  ? '🚫 Disable'
                                  : '✅ Enable'}
                              </button>
                            )}
                          </td>
                          <td>
                            <button
                              onClick={() => handleViewSessions(account)}
                              className="btn-xs btn-outline-primary"
                              title="View active sessions for this account"
                            >
                              👁️ Sessions
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {usersTotalPages > 1 && (
              <div className="pagination">
                <button
                  onClick={() => fetchUsers(usersPage - 1)}
                  disabled={usersPage === 0 || usersLoading}
                  className="btn btn-sm btn-secondary"
                >
                  Previous
                </button>
                <span className="page-indicator">
                  Page {usersPage + 1} of {usersTotalPages}
                </span>
                <button
                  onClick={() => fetchUsers(usersPage + 1)}
                  disabled={usersPage >= usersTotalPages - 1 || usersLoading}
                  className="btn btn-sm btn-secondary"
                >
                  Next
                </button>
              </div>
            )}

            {/* Active Sessions Inspection Drawer/Modal */}
            {sessionsModalOpen && (
              <div
                className="card sessions-drawer"
                style={{
                  marginTop: '24px',
                  padding: '20px 24px',
                  backgroundColor: '#0f172a',
                  border: '1px solid var(--border-color)',
                  borderLeft: '4px solid #3b82f6',
                  borderRadius: 'var(--radius)',
                  boxShadow: '0 8px 24px -4px rgba(0, 0, 0, 0.45)',
                }}
              >
                <div className="section-header" style={{ marginBottom: '16px', alignItems: 'center' }}>
                  <div>
                    <h3 style={{ margin: 0, fontSize: '1.15rem', color: '#f8fafc', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span>🔑</span>
                      <span>
                        Active Sessions for: <strong style={{ color: '#60a5fa' }}>{selectedUserForSessions?.username}</strong> (#{selectedUserForSessions?.id})
                      </span>
                    </h3>
                    <span className="section-subtitle" style={{ color: '#94a3b8', fontSize: '13px', marginTop: '4px', display: 'block' }}>
                      Sessions automatically expire after 15 minutes of sliding inactivity. Terminating an active session disconnects that client immediately.
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                    {selectedUserSessions.length > 0 && (
                      <button
                        onClick={handleRevokeAllSessions}
                        className="btn btn-xs btn-outline-danger"
                        disabled={sessionActionLoading !== null}
                        title="Revoke all active sessions for this user"
                      >
                        {sessionActionLoading === 'all' ? 'Terminating All...' : '🚫 Revoke All Sessions'}
                      </button>
                    )}
                    <button
                      onClick={() => {
                        setSessionsModalOpen(false);
                        setSelectedUserForSessions(null);
                        setSelectedUserSessions([]);
                        setDrawerError('');
                        setDrawerSuccess('');
                      }}
                      className="btn btn-secondary btn-sm"
                      style={{
                        padding: '6px 14px',
                        fontSize: '13px',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        cursor: 'pointer',
                      }}
                      title="Close Active Sessions inspection"
                    >
                      ✕ Close
                    </button>
                  </div>
                </div>

                {drawerError && (
                  <div className="alert alert-danger" style={{ marginBottom: '14px', fontSize: '13px', display: 'flex', alignItems: 'center' }}>
                    <span>⚠️ {drawerError}</span>
                    <button type="button" onClick={() => setDrawerError('')} className="alert-dismiss-btn" title="Dismiss">✕</button>
                  </div>
                )}

                {drawerSuccess && (
                  <div className="alert alert-success" style={{ marginBottom: '14px', fontSize: '13px', display: 'flex', alignItems: 'center' }}>
                    <span>✅ {drawerSuccess}</span>
                    <button type="button" onClick={() => setDrawerSuccess('')} className="alert-dismiss-btn" title="Dismiss">✕</button>
                  </div>
                )}

                {sessionsLoading ? (
                  <div className="table-loading" style={{ color: 'var(--text-muted)' }}>
                    <div className="spinner-small"></div>
                    <span>Checking active sessions...</span>
                  </div>
                ) : selectedUserSessions.length === 0 ? (
                  <div className="empty-state" style={{ padding: '24px 0', color: 'var(--text-muted)' }}>
                    <p style={{ margin: 0 }}>No active unexpired sessions found for this user.</p>
                  </div>
                ) : (
                  <div className="table-responsive">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Session ID</th>
                          <th>Created At</th>
                          <th>Last Activity (Sliding Window)</th>
                          <th>Inactivity Expiry</th>
                          <th>Status</th>
                          <th style={{ textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selectedUserSessions.map((s) => (
                          <tr key={s.id}>
                            <td>
                              <code
                                style={{
                                  color: '#38bdf8',
                                  background: 'rgba(56, 189, 248, 0.1)',
                                  padding: '2px 8px',
                                  borderRadius: '4px',
                                  border: '1px solid rgba(56, 189, 248, 0.2)',
                                  fontFamily: 'monospace',
                                  fontSize: '12px',
                                }}
                              >
                                #{s.id}
                              </code>
                            </td>
                            <td style={{ color: 'var(--text-main)' }}>{formatDateTime(s.createdAt)}</td>
                            <td>
                              <strong style={{ color: '#38bdf8' }}>{formatDateTime(s.lastActivityAt)}</strong>
                            </td>
                            <td style={{ color: 'var(--text-muted)' }}>{formatDateTime(s.expiresAt)}</td>
                            <td>
                              <span className={`status-pill ${s.active ? 'pill-success' : 'pill-failure'}`}>
                                {s.active ? 'ACTIVE' : 'REVOKED'}
                              </span>
                            </td>
                            <td style={{ textAlign: 'right' }}>
                              <button
                                onClick={() => handleRevokeSession(s.id, s.userId || selectedUserForSessions?.id)}
                                className="btn btn-xs btn-outline-danger"
                                disabled={sessionActionLoading !== null}
                                title={`Terminate session #${s.id}`}
                              >
                                {sessionActionLoading === s.id ? 'Revoking...' : 'Terminate'}
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </section>
        )}
      </main>
    </div>
  );
}
