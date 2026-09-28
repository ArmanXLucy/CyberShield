const unique = values => [...new Set(
  values
    .map(v => String(v || '').trim())
    .filter(Boolean)
)]

export function normalizeProfile(input = {}) {
  const rawAliases = Array.isArray(input.aliases)
    ? input.aliases.join('\n')
    : String(input.aliases || '')

  const profile = {
    email: String(input.email || '').trim().toLowerCase(),
    primary_username: String(input.primary_username || '').trim(),
    full_name: String(input.full_name || '').trim(),
    aliases: unique(rawAliases.split(/[\n,]+/)),
    github_username: String(input.github_username || '').trim(),
    instagram_username: String(input.instagram_username || '').trim(),
    reddit_username: String(input.reddit_username || '').trim(),
    x_username: String(input.x_username || '').trim(),
    phone: String(input.phone || '').replace(/\s+/g, '').trim(),
    website: String(input.website || '').trim(),
    self_audit_confirmed: Boolean(input.self_audit_confirmed),
  }

  profile.aliases = profile.aliases.slice(0, 20)

  profile.identifiers = unique([
    profile.primary_username,
    profile.github_username,
    profile.instagram_username,
    profile.reddit_username,
    profile.x_username,
    ...profile.aliases,
  ]).slice(0, 30)

  return profile
}

export function maskEmail(email) {
  if (!email || !email.includes('@')) return '—'
  const [local, domain] = email.split('@')
  const prefix = local.slice(0, 1)
  return `${prefix || '*'}***@${domain}`
}

export function maskPhone(phone) {
  if (!phone) return '—'
  const digits = phone.replace(/\D/g, '')
  return digits.length < 4 ? '***' : `+${digits.slice(0, 2)}******${digits.slice(-4)}`
}
