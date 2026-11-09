import { FormEvent, useState } from 'react';
import { Account, api } from '../api';
import { ErrorBox } from './ErrorBox';

export function TransferForm({ accounts }: { accounts: Account[] }) {
  const [fromAccount, setFromAccount] = useState(accounts[0] ? String(accounts[0].id) : '');
  const [toAccount, setToAccount] = useState('');
  const [amount, setAmount] = useState('');
  const [memo, setMemo] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState('');

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setResult('');
    try {
      const tx = await api<{ id: number }>('/transfer', {
        method: 'POST',
        body: { fromAccount: Number(fromAccount), toAccount: Number(toAccount), amount: Number(amount), memo },
      });
      setResult(`Transfer completed. Reference #${tx.id}`);
      setAmount('');
      setMemo('');
    } catch (e) {
      setError(e);
    }
  };

  return (
    <section className="card narrow">
      <h2>Transfer money</h2>
      <form onSubmit={submit} aria-label="Transfer">
        <label>
          From account ID
          <input value={fromAccount} onChange={(e) => setFromAccount(e.target.value)} inputMode="numeric" />
        </label>
        <label>
          To account ID
          <input value={toAccount} onChange={(e) => setToAccount(e.target.value)} inputMode="numeric" />
        </label>
        <label>
          Amount
          <input value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" />
        </label>
        <label>
          Memo
          <input value={memo} onChange={(e) => setMemo(e.target.value)} />
        </label>
        <button type="submit">Send</button>
      </form>
      {result && <p className="success">{result}</p>}
      <ErrorBox error={error} />
      {accounts.length > 0 && (
        <p className="muted">Your account IDs: {accounts.map((a) => `${a.id} (${a.number})`).join(', ')}</p>
      )}
    </section>
  );
}
