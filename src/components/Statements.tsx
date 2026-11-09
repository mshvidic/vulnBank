import { FormEvent, useEffect, useState } from 'react';
import { api } from '../api';
import { ErrorBox } from './ErrorBox';

export function Statements() {
  const [files, setFiles] = useState<string[]>([]);
  const [fileName, setFileName] = useState('');
  const [content, setContent] = useState('');
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    api<string[]>('/statements').then(setFiles).catch(setError);
  }, []);

  const open = async (name: string) => {
    setError(null);
    setContent('');
    try {
      setContent(await api<string>(`/statements/download?file=${encodeURIComponent(name)}`));
    } catch (e) {
      setError(e);
    }
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void open(fileName);
  };

  return (
    <section className="card">
      <h2>Statements</h2>
      <ul className="plain">
        {files.map((name) => (
          <li key={name}>
            <button type="button" className="link" onClick={() => open(name)}>
              {name}
            </button>
          </li>
        ))}
      </ul>

      <form onSubmit={submit} className="inline" aria-label="Open statement by name">
        <label>
          Open by file name
          <input value={fileName} onChange={(e) => setFileName(e.target.value)} placeholder="alice-2025-09.txt" />
        </label>
        <button type="submit">Open</button>
      </form>

      <ErrorBox error={error} />
      {content && <pre className="document">{content}</pre>}
    </section>
  );
}
