import { FootprintProvider, fetchWithRetry } from './base.js'

export class RedditProvider extends FootprintProvider {
  constructor() {
    super('reddit', 'Reddit')
    this.clientId = process.env.REDDIT_CLIENT_ID || ''
    this.clientSecret = process.env.REDDIT_CLIENT_SECRET || ''
    this.userAgent = process.env.REDDIT_USER_AGENT || 'CyberShield/1.0'
  }

  isConfigured() {
    return Boolean(this.clientId && this.clientSecret)
  }

  async getToken(signal) {
    const auth = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')
    const response = await fetch('https://www.reddit.com/api/v1/access_token', {
      method: 'POST',
      headers: {
        Authorization: `Basic ${auth}`,
        'User-Agent': this.userAgent,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'grant_type=client_credentials',
      signal,
    })
    if (!response.ok) throw new Error(`Reddit token ${response.status}`)
    const data = await response.json()
    return data.access_token
  }

  async search(profile, { signal } = {}) {
    const usernames = [...new Set([
      profile.reddit_username,
      profile.primary_username,
      ...profile.aliases,
    ].filter(Boolean))].slice(0, 5)

    if (!this.isConfigured()) {
      return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'Reddit client credentials are not configured.', findings: [] }
    }
    if (!usernames.length) {
      return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'No Reddit-compatible username was supplied.', findings: [] }
    }

    try {
      const token = await this.getToken(signal)
      const findings = []
      for (const username of usernames) {
        const response = await fetchWithRetry(`https://oauth.reddit.com/user/${encodeURIComponent(username)}/about`, {
          headers: { Authorization: `Bearer ${token}`, 'User-Agent': this.userAgent },
          signal,
        })
        if (response.status === 404) continue
        if (response.status === 401 || response.status === 403 || response.status === 429) {
          return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: `Reddit API access returned ${response.status}.`, findings }
        }
        if (!response.ok) return { provider: this.name, source_display_name: this.displayName, status: 'error', reason: `Reddit API returned ${response.status}.`, findings }

        const wrapper = await response.json()
        const user = wrapper?.data || {}
        findings.push({
          source: 'reddit',
          source_display_name: 'Reddit',
          status: 'found',
          match_type: 'confirmed',
          confidence: 'high',
          profile_url: user.subreddit?.display_name_prefixed
            ? `https://www.reddit.com/user/${encodeURIComponent(username)}`
            : `https://www.reddit.com/user/${encodeURIComponent(username)}`,
          matched_identifier: username,
          information: {
            username: user.name || username,
            created_at: user.created_utc ? new Date(user.created_utc * 1000).toISOString() : null,
            link_karma: Number.isFinite(user.link_karma) ? user.link_karma : null,
            comment_karma: Number.isFinite(user.comment_karma) ? user.comment_karma : null,
            profile_description: user.subreddit?.public_description || null,
            is_gold: Boolean(user.is_gold),
            is_mod: Boolean(user.is_mod),
          },
          evidence: [`Reddit returned a public user profile matching "${username}".`],
          collected_at: new Date().toISOString(),
        })
      }
      return { provider: this.name, source_display_name: this.displayName, status: findings.length ? 'found' : 'not_found', reason: findings.length ? null : 'No matching public Reddit profile was returned.', findings }
    } catch (error) {
      if (error.name === 'AbortError') throw error
      return { provider: this.name, source_display_name: this.displayName, status: 'error', reason: 'Reddit request failed.', findings: [] }
    }
  }
}

