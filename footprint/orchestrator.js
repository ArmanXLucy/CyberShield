import { GitHubProvider } from './providers/github.js'
import { HIBPProvider } from './providers/hibp.js'
import { RedditProvider } from './providers/reddit.js'
import { InstagramProvider } from './providers/instagram.js'
import { XProvider } from './providers/x.js'
import { WebsiteProvider } from './providers/website.js'
import { WebSearchProvider } from './providers/web_search.js'
import { normalizeProfile, maskEmail, maskPhone } from './normalizer.js'
import { analyzeRisk } from './risk_engine.js'
import { buildCorrelations } from './correlation.js'
import { mockProviderResult } from './mock.js'

export const providerFactories = [
  () => new GitHubProvider(),
  () => new RedditProvider(),
  () => new InstagramProvider(),
  () => new XProvider(),
  () => new HIBPProvider(),
  () => new WebsiteProvider(),
  () => new WebSearchProvider(),
]

function providerStatus(provider) {
  return {
    provider: provider.name,
    display_name: provider.displayName,
    status: provider.isConfigured() ? 'pending' : 'unavailable',
    reason: provider.isConfigured() ? null : 'Provider is not configured.',
  }
}

export function createFootprintScan(input) {
  const profile = normalizeProfile(input)
  if (!profile.email || !profile.primary_username) {
    const error = new Error('Email and primary username are required.')
    error.statusCode = 400
    throw error
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(profile.email) || profile.email.length > 320) {
    const error = new Error('Please provide a valid email address.')
    error.statusCode = 400
    throw error
  }
  if (profile.primary_username.length > 100 || profile.aliases.some(value => value.length > 100)) {
    const error = new Error('Username and alias values must be 100 characters or fewer.')
    error.statusCode = 400
    throw error
  }
  if (profile.full_name.length > 160 || profile.phone.length > 32 || profile.website.length > 2048) {
    const error = new Error('One or more optional identifier fields are too long.')
    error.statusCode = 400
    throw error
  }
  if (!profile.self_audit_confirmed) {
    const error = new Error('Self-audit confirmation is required.')
    error.statusCode = 400
    throw error
  }
  return profile
}

export async function runFootprintScan(profile, onProviderStart = () => {}, onProviderFinish = () => {}, signal) {
  const results = []
  const statuses = []
  const providers = providerFactories.map(factory => factory())

  // Run independently but cap concurrency to keep provider load controlled.
  const queue = [...providers]
  const workers = Array.from({ length: 3 }, async () => {
    while (queue.length) {
      const provider = queue.shift()
      if (!provider) return
      statuses.push(providerStatus(provider))
      onProviderStart(provider)
      try {
        const result = process.env.CYBERSHIELD_MOCK_EXTERNAL_APIS === 'true'
          ? mockProviderResult(provider, profile)
          : await provider.search(profile, { signal })
        results.push(result)
        onProviderFinish(provider, result)
      } catch (error) {
        const result = {
          provider: provider.name,
          source_display_name: provider.displayName,
          status: error.name === 'AbortError' ? 'unavailable' : 'error',
          reason: error.name === 'AbortError' ? 'Provider timed out.' : 'Provider request failed.',
          findings: [],
        }
        results.push(result)
        onProviderFinish(provider, result)
      }
    }
  })

  await Promise.all(workers)

  const correlations = buildCorrelations(results)
  if (correlations.length) {
    results.push({
      provider: 'correlation',
      source_display_name: 'CyberShield correlation',
      status: 'found',
      reason: null,
      findings: correlations,
    })
  }

  const risk = analyzeRisk(results)
  const foundSources = results.filter(r => r.status === 'found' && r.provider !== 'correlation').length
  const checkedSources = results.filter(r => ['found', 'not_found', 'unavailable', 'error'].includes(r.status) && r.provider !== 'correlation').length

  return {
    version: 1,
    scan_type: 'footprint',
    profile: {
      email: maskEmail(profile.email),
      primary_username: profile.primary_username,
      full_name: profile.full_name || null,
      aliases: profile.aliases,
      phone: maskPhone(profile.phone),
      website: profile.website || null,
    },
    providers: results.map(r => ({
      provider: r.provider,
      display_name: r.source_display_name,
      status: r.status,
      reason: r.reason || null,
      finding_count: (r.findings || []).length,
    })),
    findings: results.flatMap(r => r.findings || []),
    summary: {
      checked_sources: checkedSources,
      found_sources: foundSources,
      breach_count: risk.breach_count,
      overall_risk: risk.overall_risk,
      exposures: risk.exposures,
      correlations: correlations.length,
    },
    recommendations: risk.recommendations,
    attribution: {
      hibp: results.some(r => r.provider === 'hibp')
        ? 'Breach information provided by Have I Been Pwned.'
        : null,
    },
    collected_at: new Date().toISOString(),
  }
}

