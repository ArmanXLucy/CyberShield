import { FootprintProvider, fetchWithRetry } from './base.js'

export class InstagramProvider extends FootprintProvider {
  constructor() {
    super('instagram', 'Instagram')
    this.token = process.env.INSTAGRAM_ACCESS_TOKEN || ''
  }

  isConfigured() {
    return Boolean(this.token)
  }

  async search(profile, { signal } = {}) {
    if (!this.isConfigured()) {
      return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'Instagram official API credentials are not configured.', findings: [] }
    }

    const username = profile.instagram_username
    if (!username) {
      return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'No Instagram username was supplied.', findings: [] }
    }

    // Official API access is permissions-dependent and does not provide a generic
    // server-side arbitrary public-username directory lookup. When a token is
    // configured, we can safely inspect the connected account and confirm a match.
    try {
      const url = 'https://graph.instagram.com/me?fields=id,username,name,biography,website'
      const response = await fetchWithRetry(url, {
        headers: { Authorization: `Bearer ${this.token}` },
        signal,
      })
      if (!response.ok) {
        return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'The configured Instagram API permissions do not allow this lookup.', findings: [] }
      }
      const user = await response.json()
      if (!user.username || user.username.toLowerCase() !== username.toLowerCase()) {
        return { provider: this.name, source_display_name: this.displayName, status: 'not_found', reason: 'The connected Instagram account does not match the supplied username.', findings: [] }
      }
      return {
        provider: this.name,
        source_display_name: this.displayName,
        status: 'found',
        reason: null,
        findings: [{
          source: 'instagram',
          source_display_name: 'Instagram',
          status: 'found',
          match_type: 'confirmed',
          confidence: 'high',
          profile_url: `https://www.instagram.com/${encodeURIComponent(user.username)}/`,
          matched_identifier: username,
          information: {
            username: user.username,
            display_name: user.name || null,
            bio: user.biography || null,
            website: user.website || null,
          },
          evidence: ['The configured official Instagram API returned an account whose username matches the supplied username.'],
          collected_at: new Date().toISOString(),
        }],
      }
    } catch (error) {
      if (error.name === 'AbortError') throw error
      return { provider: this.name, source_display_name: this.displayName, status: 'error', reason: 'Instagram API request failed.', findings: [] }
    }
  }
}

