import { FormEvent, useState } from 'react';
import { api } from '../api';
import { ErrorBox } from './ErrorBox';

export function Support() {
  const [subject, setSubject] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [sent, setSent] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setSent(false);
    try {
      await api('/support', { method: 'POST', body: { subject, message } });
      setSent(true);
      setSubject('');
      setMessage('');
    } catch (e) {
      setError(e);
    }
  };

  return (
    <section className="card narrow">
      <h2>Contact support</h2>
      <form onSubmit={submit} aria-label="Support request">
        <label>
          Subject
          <input value={subject} onChange={(e) => setSubject(e.target.value)} />
        </label>
        <label>
          Message
          <textarea value={message} onChange={(e) => setMessage(e.target.value)} rows={5} />
        </label>
        <button type="submit">Send</button>
      </form>
      {sent && <p className="success">Thanks, our team will review your message.</p>}
      <ErrorBox error={error} />
    </section>
  );
}
