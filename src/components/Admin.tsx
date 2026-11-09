import { useEffect, useState } from 'react';
import { AdminUser, RiskAlert, SupportTicket, api } from '../api';
import { ErrorBox } from './ErrorBox';

type Tab = 'users' | 'alerts' | 'support';

export function Admin() {
  const [tab, setTab] = useState<Tab>('users');
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [alerts, setAlerts] = useState<RiskAlert[]>([]);
  const [tickets, setTickets] = useState<SupportTicket[]>([]);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    setError(null);
    const load = async () => {
      if (tab === 'users') setUsers(await api<AdminUser[]>('/admin/users'));
      if (tab === 'alerts') setAlerts(await api<RiskAlert[]>('/admin/alerts'));
      if (tab === 'support') setTickets(await api<SupportTicket[]>('/admin/support'));
    };
    load().catch(setError);
  }, [tab]);

  return (
    <section className="card">
      <h2>Admin console</h2>
      <div className="tabs" role="tablist">
        {(['users', 'alerts', 'support'] as Tab[]).map((name) => (
          <button
            key={name}
            type="button"
            role="tab"
            aria-selected={tab === name}
            className={tab === name ? 'active' : ''}
            onClick={() => setTab(name)}
          >
            {name === 'users' ? 'Users' : name === 'alerts' ? 'Risk alerts' : 'Support tickets'}
          </button>
        ))}
      </div>
      <ErrorBox error={error} />

      {tab === 'users' && (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Username</th>
              <th>Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Password hash</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td>{user.id}</td>
                <td>{user.username}</td>
                <td>{user.full_name}</td>
                <td>{user.email}</td>
                <td>{user.role}</td>
                <td className="mono">{user.password}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {tab === 'alerts' && (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Date</th>
              <th>Account</th>
              <th>Severity</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr key={alert.id}>
                <td>{alert.id}</td>
                <td>{alert.created_at}</td>
                <td>{alert.account_id}</td>
                <td>
                  <span className={`severity severity-${alert.severity}`}>{alert.severity}</span>
                </td>
                <td>{alert.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {tab === 'support' && (
        <ul className="tickets">
          {tickets.map((ticket) => (
            <li key={ticket.id}>
              <strong>{ticket.subject}</strong>
              <span className="muted">
                {' '}
                from {ticket.username} · {ticket.created_at}
              </span>
              {/* FLAW: ticket messages are rendered as raw HTML (stored XSS in the admin console). */}
              <div dangerouslySetInnerHTML={{ __html: ticket.message }} />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
