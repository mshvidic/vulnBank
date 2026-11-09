import { useEffect, useState } from 'react';
import { Account, User, api } from './api';
import { Admin } from './components/Admin';
import { AccountDetail } from './components/AccountDetail';
import { Dashboard } from './components/Dashboard';
import { LoginPage } from './components/LoginPage';
import { Profile } from './components/Profile';
import { Statements } from './components/Statements';
import { Support } from './components/Support';
import { TransferForm } from './components/TransferForm';
import { WarningBanner } from './components/WarningBanner';

type View = 'dashboard' | 'account' | 'transfer' | 'statements' | 'profile' | 'support' | 'admin';

const NAV: Array<{ view: View; label: string; adminOnly?: boolean }> = [
  { view: 'dashboard', label: 'Accounts' },
  { view: 'transfer', label: 'Transfer' },
  { view: 'statements', label: 'Statements' },
  { view: 'profile', label: 'Profile' },
  { view: 'support', label: 'Support' },
  // The Admin tab is hidden for customers in the UI only. The API behind it is not protected.
  { view: 'admin', label: 'Admin', adminOnly: true },
];

export function App() {
  const [me, setMe] = useState<User | null>(null);
  const [checking, setChecking] = useState(true);
  const [view, setView] = useState<View>('dashboard');
  const [accountId, setAccountId] = useState<number | null>(null);
  const [accounts, setAccounts] = useState<Account[]>([]);

  // Restore the session from the cookie, if there is one.
  useEffect(() => {
    api<User>('/me')
      .then(setMe)
      .catch(() => setMe(null))
      .finally(() => setChecking(false));
  }, []);

  // Own accounts are needed by the transfer form.
  useEffect(() => {
    if (me) api<Account[]>('/accounts').then(setAccounts).catch(() => setAccounts([]));
  }, [me, view]);

  const logout = async () => {
    await api('/logout', { method: 'POST' });
    setMe(null);
    setView('dashboard');
  };

  const openAccount = (id: number) => {
    setAccountId(id);
    setView('account');
  };

  return (
    <div className="app">
      <WarningBanner />
      <header className="app-header">
        <h1>VulnBank</h1>
        {me && (
          <nav aria-label="Main">
            {NAV.filter((item) => !item.adminOnly || me.role === 'admin').map((item) => (
              <button
                key={item.view}
                type="button"
                className={view === item.view ? 'active' : ''}
                onClick={() => setView(item.view)}
              >
                {item.label}
              </button>
            ))}
          </nav>
        )}
        {me && (
          <div className="session">
            <span>
              {me.full_name || me.username} ({me.role})
            </span>
            <button type="button" onClick={logout}>
              Log out
            </button>
          </div>
        )}
      </header>

      <main>
        {checking ? (
          <p className="muted">Loading…</p>
        ) : !me ? (
          <LoginPage onLoggedIn={setMe} />
        ) : (
          <>
            {view === 'dashboard' && <Dashboard onOpenAccount={openAccount} />}
            {view === 'account' && accountId !== null && (
              <AccountDetail accountId={accountId} onBack={() => setView('dashboard')} />
            )}
            {view === 'transfer' && <TransferForm key={accounts.map((a) => a.id).join('-')} accounts={accounts} />}
            {view === 'statements' && <Statements />}
            {view === 'profile' && <Profile me={me} onUpdated={setMe} />}
            {view === 'support' && <Support />}
            {view === 'admin' && <Admin />}
          </>
        )}
      </main>
    </div>
  );
}
