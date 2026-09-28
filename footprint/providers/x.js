import { FootprintProvider, fetchWithRetry } from './base.js'

export class XProvider extends FootprintProvider {
  constructor() {
    super('x', 'X')
    this.bearer = process.env.X_BEARER_TOKEN || ''
  }

  isConfigured() {
    return Boolean(this.bearer)
  }

  async search(profile, { signal } = {}) {
    const usernames = [...new Set([
      profile.x_username,
      profile.primary_username,
      ...profile.aliases,
    ].filter(Boolean))].slice(0, 5)

    if (!this.isConfigured()) {
      return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'X_BEARER_TOKEN is not configured.', findings: [] }
    }
    if (!usernames.length) {
      return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'No X-compatible username was supplied.', findings: [] }
    }

    const findings = []
    for (const username of usernames) {
      try {
        const url = `https://api.x.com/2/users/by/username/${encodeURIComponent(username)}?user.fields=created_at,description,entities,location,name,profile_image_url,protected,public_metrics,url,verified,verified_type`
        const response = await fetchWithRetry(url, {
          headers: { Authorization: `Bearer ${this.bearer}` },
          signal,
        })
        if (response.status === 404) continue
        if ([401, 403, 429].includes(response.status)) {
          return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: `X API access returned ${response.status}; permissions or plan may not allow this lookup.`, findings }
        }
        if (!response.ok) return { provider: this.name, source_display_name: this.displayName, status: 'error', reason: `X API returned ${response.status}.`, findings }

        const body = await response.json()
        const user = body?.data
        if (!user) continue
        findings.push({
          source: 'x',
          source_display_name: 'X',
          status: 'found',
          match_type: 'confirmed',
          confidence: 'high',
          profile_url: `https://x.com/${encodeURIComponent(user.username || username)}`,
          matched_identifier: username,
          information: {
            username: user.username || username,
            display_name: user.name || null,
            bio: user.description || null,
            location: user.location || null,
            website: user.url || null,
            protected: Boolean(user.protected),
            verified: Boolean(user.verified),
            created_at: user.created_at || null,
          },
          evidence: [`X API returned a public profile whose username matches "${username}".`],
          collected_at: new Date().toISOString(),
        })
      } catch (error) {
        if (error.name === 'AbortError') throw error
        return { provider: this.name, source_display_name: this.displayName, status: 'error', reason: 'X API request failed.', findings }
      }
    }
    return { provider: this.name, source_display_name: this.displayName, status: findings.length ? 'found' : 'not_found', reason: findings.length ? null : 'No matching public X profile was returned.', findings }
  }
}

