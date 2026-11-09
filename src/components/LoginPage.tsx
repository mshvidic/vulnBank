import { FormEvent, useState } from 'react';
import { User, api } from '../api';
import { ErrorBox } from './ErrorBox';

export function LoginPage({ onLoggedIn }: { onLoggedIn: (user: User) => void }) {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [message, setMessage] = useState('');

  const login = async () => {
    const result = await api<{ user: User }>('/login', { method: 'POST', body: { username, password } });
    onLoggedIn(result.user);
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setMessage('');
    try {
      if (mode === 'register') {
        await api('/register', { method: 'POST', body: { username, password, fullName, email } });
        setMessage('Account created. You can log in now.');
        setMode('login');
      } else {
        await login();
      }
    } catch (e) {
      setError(e);
    }
  };

  return (
    <section className="card narrow">
      <h2>{mode === 'login' ? 'Log in' : 'Open an account'}</h2>
      <form onSubmit={submit} aria-label={mode === 'login' ? 'Log in' : 'Register'}>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
          />
        </label>
        {mode === 'register' && (
          <>
            <label>
              Full name
              <input value={fullName} onChange={(e) => setFullName(e.target.value)} />
            </label>
            <label>
              Email
              <input value={email} onChange={(e) => setEmail(e.target.value)} />
            </label>
          </>
        )}
        <button type="submit">{mode === 'login' ? 'Log in' : 'Create account'}</button>
      </form>

      {message && <p className="success">{message}</p>}
      <ErrorBox error={error} />

      <p className="muted">
        {mode === 'login' ? (
          <>
            New customer?{' '}
            <button type="button" className="link" onClick={() => setMode('register')}>
              Open an account
            </button>
          </>
        ) : (
          <>
            Already a customer?{' '}
            <button type="button" className="link" onClick={() => setMode('login')}>
              Log in
            </button>
          </>
        )}
      </p>
      <p className="muted">Demo users are listed in the README (for example alice / password1).</p>
    </section>
  );
}
