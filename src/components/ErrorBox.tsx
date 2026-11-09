import { ApiError } from '../api';

/** Shows an error exactly as the server reported it, including the SQL and stack trace if sent. */
export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  const message = error instanceof Error ? error.message : String(error);
  const details = error instanceof ApiError ? error.details : undefined;

  return (
    <div className="error-box" role="alert">
      <strong>{message}</strong>
      {details?.query && <pre>{details.query}</pre>}
      {details?.stack && <pre>{details.stack}</pre>}
    </div>
  );
}
