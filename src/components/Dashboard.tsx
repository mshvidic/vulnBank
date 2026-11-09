import { FormEvent, useEffect, useState } from 'react';
import { Account, api, money } from '../api';
import { ErrorBox } from './ErrorBox';

interface DashboardProps {
  onOpenAccount: (id: number) => void;
}

export function Dashboard({ onOpenAccount }: DashboardProps) {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [lookupId, setLookupId] = useState('');

  useEffect(() => {
    api<Account[]>('/accounts').then(setAccounts).catch(setError);
  }, []);

  const total = accounts.reduce((sum, account) => sum + account.balance, 0);

  const lookup = (event: FormEvent) => {
    event.preventDefault();
    if (lookupId.trim()) onOpenAccount(Number(lookupId));
  };

  return (
    <>
      <section className="card">
        <h2>My accounts</h2>
        <ErrorBox error={error} />
        <p className="total">
          Total balance: <strong>{money(total)}</strong>
        </p>
        <ul className="account-list">
          {accounts.map((account) => (
            <li key={account.id}>
              <div>
                <strong>{account.number}</strong>
                <span className="muted"> {account.type} · id {account.id}</span>
              </div>
              <div className="balance">{money(account.balance)}</div>
              <button type="button" onClick={() => onOpenAccount(account.id)} aria-label={`View ${account.number}`}>
                View
              </button>
            </li>
          ))}
        </ul>
      </section>

      <section className="card">
        <h2>Open an account by ID</h2>
        <form onSubmit={lookup} className="inline" aria-label="Account lookup">
          <label>
            Account ID
            <input value={lookupId} onChange={(e) => setLookupId(e.target.value)} inputMode="numeric" />
          </label>
          <button type="submit">Open</button>
        </form>
      </section>
    </>
  );
}
