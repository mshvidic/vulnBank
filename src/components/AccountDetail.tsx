import { FormEvent, useCallback, useEffect, useState } from 'react';
import { Account, Transaction, api, money } from '../api';
import { ErrorBox } from './ErrorBox';

export function AccountDetail({ accountId, onBack }: { accountId: number; onBack: () => void }) {
  const [account, setAccount] = useState<Account | null>(null);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [search, setSearch] = useState('');
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(
    async (q: string) => {
      setError(null);
      try {
        setAccount(await api<Account>(`/accounts/${accountId}`));
        setTransactions(await api<Transaction[]>(`/accounts/${accountId}/transactions?q=${encodeURIComponent(q)}`));
      } catch (e) {
        setError(e);
      }
    },
    [accountId],
  );

  useEffect(() => {
    void load('');
  }, [load]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void load(search);
  };

  return (
    <section className="card">
      <button type="button" className="link" onClick={onBack}>
        ← Back
      </button>
      <h2>Account {accountId}</h2>

      {account && (
        <dl className="details">
          <dt>Number</dt>
          <dd>{account.number}</dd>
          <dt>Type</dt>
          <dd>{account.type}</dd>
          <dt>Balance</dt>
          <dd>{money(account.balance)}</dd>
          {account.owner_name && (
            <>
              <dt>Owner</dt>
              <dd>
                {account.owner_name} ({account.owner_email})
              </dd>
            </>
          )}
        </dl>
      )}

      <form onSubmit={submit} className="inline" aria-label="Search transactions">
        <label>
          Search memo
          <input value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>
        <button type="submit">Search</button>
      </form>

      <ErrorBox error={error} />

      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Date</th>
            <th>From</th>
            <th>To</th>
            <th>Amount</th>
            <th>Memo</th>
          </tr>
        </thead>
        <tbody>
          {transactions.map((tx) => (
            <tr key={tx.id}>
              <td>{tx.id}</td>
              <td>{tx.created_at}</td>
              <td>{tx.from_account}</td>
              <td>{tx.to_account}</td>
              <td>{money(Number(tx.amount))}</td>
              {/* FLAW: the memo is rendered as raw HTML (stored XSS). */}
              <td dangerouslySetInnerHTML={{ __html: tx.memo ?? '' }} />
            </tr>
          ))}
        </tbody>
      </table>
      {transactions.length === 0 && !error && <p className="muted">No transactions found.</p>}
    </section>
  );
}
