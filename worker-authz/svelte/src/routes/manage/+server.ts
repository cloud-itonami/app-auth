import type { RequestHandler } from './$types';

// Manage UI lives on auth.etzhayyim.com (static asset); redirect there until
// the full manage page is ported to accounts.etzhayyim.com.
export const GET: RequestHandler = () =>
  Response.redirect('https://auth.etzhayyim.com/manage', 302);
