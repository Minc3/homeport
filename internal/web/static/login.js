// Kept in its own file rather than inline in login.html: the portal's
// Content-Security-Policy is default-src 'self' with no 'unsafe-inline' for
// scripts, so an inline handler is silently blocked. The form then falls back
// to a native GET submit, which puts the password in the URL bar and bounces
// straight back to the login page.
document.getElementById('login').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const err = document.getElementById('error');
  err.textContent = '';
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: form.get('username'), password: form.get('password')}),
  });
  if (res.ok) {
    location.href = '/';
    return;
  }
  const body = await res.json().catch(() => ({}));
  err.textContent = body.error || 'Sign in failed';
});
