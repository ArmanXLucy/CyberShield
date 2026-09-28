import dns from 'node:dns/promises'
import net from 'node:net'
import { FootprintProvider, fetchWithRetry } from './base.js'

function isPrivateIp(ip) {
  if (net.isIP(ip) === 4) {
    const [a,b,c] = ip.split('.').map(Number)
    return a === 10 || a === 127 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || a === 0
  }
  if (net.isIP(ip) === 6) {
    const lower = ip.toLowerCase()
    return lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80:')
  }
  return true
}

async function validateHost(hostname) {
  const addresses = await dns.lookup(hostname, { all: true })
  if (!addresses.length || addresses.some(x => isPrivateIp(x.address))) {
    throw new Error('private-or-unresolvable-host')
  }
}

async function fetchSafe(url, signal) {
  let current = url
  for (let i = 0; i < 4; i += 1) {
    const parsed = new URL(current)
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('unsupported-protocol')
    await validateHost(parsed.hostname)

    const controller = new AbortController()
    const onAbort = () => controller.abort()
    if (signal) signal.addEventListener('abort', onAbort, { once: true })
    const timeout = setTimeout(() => controller.abort(), 8000)
    try {
      const response = await fetchWithRetry(current, {
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'User-Agent': 'CyberShield/1.0' },
      })
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location')
        if (!location) return response
        current = new URL(location, current).toString()
        continue
      }
      return response
    } finally {
      clearTimeout(timeout)
      if (signal) signal.removeEventListener('abort', onAbort)
    }
  }
  throw new Error('redirect-limit')
}

export class WebsiteProvider extends FootprintProvider {
  constructor() {
    super('website', 'Website / Domain')
  }

  isConfigured() {
    return true
  }

  async search(profile, { signal } = {}) {
    if (!profile.website) {
      return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'No personal website or domain was supplied.', findings: [] }
    }

    let website = profile.website
    try {
      if (!/^https?:\/\//i.test(website)) website = `https://${website}`
      const parsed = new URL(website)
      if (!parsed.hostname) throw new Error('invalid-url')
      const response = await fetchSafe(parsed.toString(), signal)

      const contentType = response.headers.get('content-type') || ''
      const text = contentType.includes('text/html') ? (await response.text()).slice(0, 500_000) : ''
      const title = text.match(/<title[^>]*>([^<]{1,200})<\/title>/i)?.[1]?.trim() || null
      const emails = [...new Set(text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || [])].slice(0, 10)
      const socials = [...new Set((text.match(/https?:\/\/(?:www\.)?(?:github\.com|instagram\.com|reddit\.com|x\.com|twitter\.com)\/[^\s"'<>]+/gi) || []))].slice(0, 20)

      const findings = [{
        source: 'website',
        source_display_name: 'Website / Domain',
        status: 'found',
        match_type: 'confirmed',
        confidence: 'high',
        profile_url: parsed.toString(),
        matched_identifier: parsed.hostname,
        information: {
          final_url: response.url || parsed.toString(),
          http_status: response.status,
          page_title: title,
          public_contact_emails: emails,
          public_social_links: socials,
          headers: {
            strict_transport_security: response.headers.get('strict-transport-security'),
            content_security_policy: response.headers.get('content-security-policy'),
            x_content_type_options: response.headers.get('x-content-type-options'),
          },
        },
        evidence: [
          `The supplied website responded with HTTP ${response.status}.`,
          emails.length ? `Found ${emails.length} public email-like address(es) in the first 500 KB of HTML.` : null,
          socials.length ? `Found ${socials.length} public social profile link(s).` : null,
        ].filter(Boolean),
        collected_at: new Date().toISOString(),
      }]

      return {
        provider: this.name,
        source_display_name: this.displayName,
        status: 'found',
        reason: null,
        findings,
      }
    } catch (error) {
      return {
        provider: this.name,
        source_display_name: this.displayName,
        status: 'unavailable',
        reason: 'Website analysis could not be completed safely for the supplied address.',
        findings: [],
      }
    }
  }
}

