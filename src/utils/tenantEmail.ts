// ponytail: mock-tenant restriction for this demo — a real multi-tenant app
// would enforce this in Supabase (e.g. a domain check on user_directory),
// not just here. Swap/remove when real tenant boundaries are defined.
const TENANT_EMAIL_PATTERN = /@oddball\.io$/i;

export function isAllowedTenantEmail(email: string): boolean {
  return TENANT_EMAIL_PATTERN.test(email.trim());
}
