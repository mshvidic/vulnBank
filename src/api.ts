export interface User {
  id: number;
  username: string;
  full_name: string;
  email: string;
  role: string;
}

export interface Account {
  id: number;
  user_id: number;
  number: string;
  type: string;
  balance: number;
  owner_name?: string;
  owner_email?: string;
}

export interface Transaction {
  id: number;
  from_account: number;
  to_account: number;
  amount: number;
  memo: string | null;
  created_at: string;
}

export interface AdminUser extends User {
  password: string;
  created_at: string;
}

export interface RiskAlert {
  id: number;
  account_id: number | null;
  reason: string;
  severity: string;
  created_at: string;
}

export interface SupportTicket {
  id: number;
  username: string;
  subject: string;
  message: string;
  created_at: string;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    /** The server sends the failing SQL and a stack trace with errors (an intentional flaw). */
    readonly details?: { query?: string; stack?: string },
  ) {
    super(message);
  }
}

export async function api<T>(path: string, options: { method?: string; body?: unknown } = {}): Promise<T> {
  const response = await fetch(`/api${path}`, {
    method: options.method ?? 'GET',
    headers: options.body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
    credentials: 'same-origin',
  });
  const text = await response.text();
  let data: unknown = text;
  try {
    data = JSON.parse(text);
  } catch {
    /* plain text response */
  }
  if (!response.ok) {
    const body = (typeof data === 'object' && data !== null ? data : {}) as {
      error?: string;
      query?: string;
      stack?: string;
    };
    throw new ApiError(body.error ?? `HTTP ${response.status}`, response.status, {
      query: body.query,
      stack: body.stack,
    });
  }
  return data as T;
}

export const money = (amount: number) =>
  new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount);
