import { FootprintProvider, fetchWithRetry } from './base.js'
import { maskEmail } from '../normalizer.js'

export class HIBPProvider extends FootprintProvider {
  constructor() {
    super('hibp', 'Have I Been Pwned')
    this.apiKey = process.env.HIBP_API_KEY || ''
    this.userAgent = process.env.HIBP_USER_AGENT || 'CyberShield/1.0'
  }

  isConfigured() {
    return Boolean(this.apiKey)
  }

  async search(profile, { signal } = {}) {
    if (!profile.email) {
      return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'No email supplied.', findings: [] }
    }
    if (!this.apiKey) {
      return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'HIBP_API_KEY is not configured.', findings: [] }
    }

    const url = `https://haveibeenpwned.com/api/v3/breachedAccount/${encodeURIComponent(profile.email)}?truncateResponse=false&includeUnverified=true`
    try {
      const response = await fetchWithRetry(url, {
        headers: {
          'hibp-api-key': this.apiKey,
          'user-agent': this.userAgent,
          'Accept': 'application/json',
        },
        signal,
      })
      if (response.status === 404) {
        return { provider: this.name, source_display_name: this.displayName, status: 'not_found', reason: 'No breaches were returned for this email address.', findings: [] }
      }
      if (response.status === 401) {
        return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'HIBP rejected the API key.', findings: [] }
      }
      if (response.status === 403) {
        return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'HIBP access was denied by the current API permissions.', findings: [] }
      }
      if (response.status === 429) {
        return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'HIBP rate limit reached.', findings: [] }
      }
      if (!response.ok) {
        return { provider: this.name, source_display_name: this.displayName, status: 'error', reason: `HIBP returned ${response.status}.`, findings: [] }
      }

      const breaches = await response.json()
      return {
        provider: this.name,
        source_display_name: this.displayName,
        status: 'found',
        reason: null,
        findings: [{
          source: 'hibp',
          source_display_name: 'Have I Been Pwned',
          status: 'found',
          match_type: 'confirmed',
          confidence: 'high',
          profile_url: 'https://haveibeenpwned.com/',
          matched_identifier: maskEmail(profile.email),
          breach_count: Array.isArray(breaches) ? breaches.length : 0,
          breaches: Array.isArray(breaches) ? breaches.slice(0, 50).map(b => ({
            name: b.Name,
            title: b.Title,
            domain: b.Domain,
            breach_date: b.BreachDate,
            added_date: b.AddedDate,
            modified_date: b.ModifiedDate,
            data_classes: Array.isArray(b.DataClasses) ? b.DataClasses : [],
            verified: Boolean(b.IsVerified),
            unverified: !b.IsVerified,
            sensitive: Boolean(b.IsSensitive),
          })) : [],
          evidence: [`HIBP returned ${Array.isArray(breaches) ? breaches.length : 0} breach record(s) for the supplied email.`],
          collected_at: new Date().toISOString(),
        }],
      }
    } catch (error) {
      if (error.name === 'AbortError') throw error
      return { provider: this.name, source_display_name: this.displayName, status: 'error', reason: 'HIBP request failed.', findings: [] }
    }
  }
}

