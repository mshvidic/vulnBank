import { FormEvent, useState } from 'react';
import { User, api } from '../api';
import { ErrorBox } from './ErrorBox';

export function Profile({ me, onUpdated }: { me: User; onUpdated: (user: User) => void }) {
  const [fullName, setFullName] = useState(me.full_name);
  const [email, setEmail] = useState(me.email);
  const [error, setError] = useState<unknown>(null);
  const [saved, setSaved] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setSaved(false);
    try {
      onUpdated(await api<User>('/profile', { method: 'PUT', body: { full_name: fullName, email } }));
      setSaved(true);
    } catch (e) {
      setError(e);
    }
  };

  return (
    <section className="card narrow">
      <h2>My profile</h2>
      <p className="muted">
        Signed in as <strong>{me.username}</strong> · role: {me.role}
      </p>
      <form onSubmit={submit} aria-label="Profile">
        <label>
          Full name
          <input value={fullName} onChange={(e) => setFullName(e.target.value)} />
        </label>
        <label>
          Email
          <input value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <button type="submit">Save</button>
      </form>
      {saved && <p className="success">Profile saved.</p>}
      <ErrorBox error={error} />
    </section>
  );
}
