import { FootprintProvider, fetchWithRetry } from './base.js'

export class WebSearchProvider extends FootprintProvider {
  constructor() {
    super('web_search', 'Public Web Discovery')
    this.endpoint = process.env.WEB_SEARCH_API_URL || ''
    this.key = process.env.WEB_SEARCH_API_KEY || ''
  }

  isConfigured() {
    return Boolean(this.endpoint && this.key)
  }

  async search(profile, { signal } = {}) {
    if (!this.isConfigured()) {
      return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'No officially supported/configured web-search provider is configured.', findings: [] }
    }
    const queries = [
      profile.email && `"${profile.email}"`,
      profile.primary_username && `"${profile.primary_username}"`,
      profile.full_name && profile.primary_username && `"${profile.full_name}" "${profile.primary_username}"`,
    ].filter(Boolean).slice(0, 3)

    const findings = []
    for (const q of queries) {
      const url = new URL(this.endpoint)
      url.searchParams.set('q', q)
      try {
        const response = await fetchWithRetry(url, {
          headers: {
            Authorization: `Bearer ${this.key}`,
            'User-Agent': 'CyberShield/1.0',
          },
          signal,
        })
        if (!response.ok) return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: `Configured search provider returned ${response.status}.`, findings }
        const body = await response.json()
        const results = Array.isArray(body?.results) ? body.results.slice(0, 10) : []
        for (const item of results) {
          if (!item?.url) continue
          findings.push({
            source: 'web_search',
            source_display_name: 'Public Web Discovery',
            status: 'found',
            match_type: 'possible',
            confidence: 'low',
            profile_url: String(item.url),
            matched_identifier: q,
            information: {
              title: item.title || null,
              snippet: item.snippet || null,
            },
            evidence: ['Returned by the configured public web-search provider for a user-supplied self-audit identifier.'],
            collected_at: new Date().toISOString(),
          })
        }
      } catch (error) {
        if (error.name === 'AbortError') throw error
        return { provider: this.name, source_display_name: this.displayName, status: 'error', reason: 'Configured web-search provider request failed.', findings }
      }
    }
    return { provider: this.name, source_display_name: this.displayName, status: findings.length ? 'found' : 'not_found', reason: findings.length ? null : 'No public web results were returned by the configured provider.', findings }
  }
}

