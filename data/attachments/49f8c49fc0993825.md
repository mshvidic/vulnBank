# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: injection-and-data-exposure.spec.ts >> #18 Stored XSS in support tickets >> a script-like support message must not be stored or returned as live HTML
- Location: tests/security/injection-and-data-exposure.spec.ts:119:3

# Error details

```
Error: expect(received).not.toContain(expected) // indexOf

Expected substring: not "<img"
Received string:        "<img src=x onerror=\"window.__adminxss=1\">"
```

# Test source

```ts
  38  | 
  39  |     const admin = await loginToken(request, 'admin', 'admin123');
  40  |     const response = await request.get('/api/admin/users', asUser(admin));
  41  |     const users = await response.json();
  42  |     expect(users.every((u: Record<string, unknown>) => u.password === undefined)).toBe(true);
  43  |   });
  44  | });
  45  | 
  46  | test.describe('#15 SQL injection in memo search', () => {
  47  |   test('a stray quote in the search box must not cause a server error', async ({ request }) => {
  48  |     const alice = await loginToken(request, 'alice', 'password1');
  49  | 
  50  |     const response = await request.get("/api/accounts/2/transactions?q='", asUser(alice));
  51  | 
  52  |     expect(response.status()).toBeLessThan(500);
  53  |   });
  54  | 
  55  |   test('a UNION-based payload must not be able to dump other tables\' data', async ({ request }) => {
  56  |     const alice = await loginToken(request, 'alice', 'password1');
  57  | 
  58  |     // If this still reaches a raw SQL string, it asks the database to return every
  59  |     // username/password pair from the users table, disguised as transaction memos.
  60  |     const payload = "zzz%' UNION SELECT id, id, id, 0, username || ':' || password, role FROM users --";
  61  |     const response = await request.get(`/api/accounts/2/transactions?q=${encodeURIComponent(payload)}`, asUser(alice));
  62  | 
  63  |     expect(response.status()).toBeLessThan(500);
  64  |     const body = await response.json();
  65  |     const text = JSON.stringify(body);
  66  |     expect(text).not.toMatch(/admin:[0-9a-f]{32}/); // a dumped username:hash pair
  67  |   });
  68  | });
  69  | 
  70  | test.describe('#16 Verbose errors', () => {
  71  |   test('a server error must not include the underlying query or a stack trace', async ({ request }) => {
  72  |     const alice = await loginToken(request, 'alice', 'password1');
  73  | 
  74  |     const response = await request.get("/api/accounts/2/transactions?q='", asUser(alice));
  75  | 
  76  |     if (response.status() >= 500) {
  77  |       const body = await response.json();
  78  |       expect(body.query).toBeUndefined();
  79  |       expect(body.stack).toBeUndefined();
  80  |     }
  81  |     // If the request above no longer errors at all (because #15 is already fixed), there's
  82  |     // nothing for this particular probe to leak — that's fine, see the file header comment.
  83  |   });
  84  | });
  85  | 
  86  | test.describe('#17 Stored XSS in transfer memos', () => {
  87  |   test('a script-like memo must not be stored or returned as live HTML', async ({ request }) => {
  88  |     const senderUsername = `xss_sender_${Date.now()}`;
  89  |     const receiverUsername = `xss_receiver_${Date.now()}`;
  90  |     await request.post('/api/register', { data: { username: senderUsername, password: 'whatever123' } });
  91  |     await request.post('/api/register', { data: { username: receiverUsername, password: 'whatever123' } });
  92  |     const sender = await loginToken(request, senderUsername, 'whatever123');
  93  |     const receiver = await loginToken(request, receiverUsername, 'whatever123');
  94  |     const [{ id: senderAccountId }] = await (await request.get('/api/accounts', asUser(sender))).json();
  95  |     const [{ id: receiverAccountId }] = await (await request.get('/api/accounts', asUser(receiver))).json();
  96  | 
  97  |     const payload = '<img src=x onerror="window.__xss=1">';
  98  |     const transfer = await request.post('/api/transfer', {
  99  |       ...asUser(sender),
  100 |       data: { fromAccount: senderAccountId, toAccount: receiverAccountId, amount: 1, memo: payload },
  101 |     });
  102 |     // The transfer itself must still go through — a fix that just makes this endpoint error
  103 |     // out on any input would otherwise make the check below pass for the wrong reason.
  104 |     expect(transfer.status()).toBe(201);
  105 |     const { id: transferId } = await transfer.json();
  106 | 
  107 |     const transactions = await (
  108 |       await request.get(`/api/accounts/${senderAccountId}/transactions`, asUser(sender))
  109 |     ).json();
  110 |     const stored = transactions.find((t: { id: number }) => t.id === transferId);
  111 | 
  112 |     // A secure API either rejects this input outright, or returns it HTML-escaped
  113 |     // (&lt;img ...&gt;) — either way, the raw, executable tag must not come back as-is.
  114 |     expect(stored?.memo ?? '').not.toContain('<img');
  115 |   });
  116 | });
  117 | 
  118 | test.describe('#18 Stored XSS in support tickets', () => {
  119 |   test('a script-like support message must not be stored or returned as live HTML', async ({ request }) => {
  120 |     const username = `xss_ticket_${Date.now()}`;
  121 |     await request.post('/api/register', { data: { username, password: 'whatever123' } });
  122 |     const customer = await loginToken(request, username, 'whatever123');
  123 |     const admin = await loginToken(request, 'admin', 'admin123');
  124 | 
  125 |     const payload = '<img src=x onerror="window.__adminxss=1">';
  126 |     const submission = await request.post('/api/support', {
  127 |       ...asUser(customer),
  128 |       data: { subject: `ticket from ${username}`, message: payload },
  129 |     });
  130 |     // The ticket itself must still be accepted — a fix that just makes this endpoint error
  131 |     // out on any input would otherwise make the check below pass for the wrong reason.
  132 |     expect(submission.status()).toBe(201);
  133 | 
  134 |     const tickets = await (await request.get('/api/admin/support', asUser(admin))).json();
  135 |     const ticket = tickets.find((t: { username: string }) => t.username === username);
  136 | 
  137 |     expect(ticket).toBeDefined();
> 138 |     expect(ticket?.message ?? '').not.toContain('<img');
      |                                       ^ Error: expect(received).not.toContain(expected) // indexOf
  139 |   });
  140 | });
  141 | 
  142 | test.describe('#19 Path traversal on statement downloads', () => {
  143 |   test('a file name must not be able to escape the statements folder', async ({ request }) => {
  144 |     const alice = await loginToken(request, 'alice', 'password1');
  145 | 
  146 |     const response = await request.get('/api/statements/download?file=../secrets/config.env', asUser(alice));
  147 | 
  148 |     expect([403, 404]).toContain(response.status());
  149 |   });
  150 | });
  151 | 
```