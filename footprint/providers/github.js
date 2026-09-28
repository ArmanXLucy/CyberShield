import { FootprintProvider, fetchWithRetry } from './base.js'

const API = 'https://api.github.com'
const API_VERSION = '2026-03-10'
const CACHE_TTL_MS = 60_000
const cache = new Map()

function cacheKey(username, tokenPresent) {
  return `${tokenPresent ? 'auth' : 'public'}:${username.toLowerCase()}`
}

async function githubFetch(path, token, signal) {
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': API_VERSION,
    'User-Agent': 'CyberShield/1.0',
  }
  if (token) headers.Authorization = `Bearer ${token}`
  return fetchWithRetry(`${API}${path}`, { headers, signal })
}

export class GitHubProvider extends FootprintProvider {
  constructor() {
    super('github', 'GitHub')
    this.token = process.env.GITHUB_TOKEN || ''
  }

  isConfigured() {
    return Boolean(this.token) || process.env.GITHUB_ALLOW_UNAUTHENTICATED !== 'false'
  }

  async search(profile, { signal } = {}) {
    const usernames = [...new Set([
      profile.github_username,
      profile.primary_username,
      ...profile.aliases,
    ].filter(Boolean))].slice(0, 8)

    if (!usernames.length) {
      return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'No GitHub-compatible username was supplied.', findings: [] }
    }

    const findings = []
    let anyFound = false

    for (const username of usernames) {
      const key = cacheKey(username, Boolean(this.token))
      const cached = cache.get(key)
      let user = null

      if (cached && Date.now() - cached.createdAt < CACHE_TTL_MS) {
        user = cached.user
      } else {
        try {
          const response = await githubFetch(`/users/${encodeURIComponent(username)}`, this.token, signal)
          if (response.status === 404) continue
          if (response.status === 403 || response.status === 429) {
            return { provider: this.name, source_display_name: this.displayName, status: 'unavailable', reason: 'GitHub API rate limit or access restriction.', findings }
          }
          if (!response.ok) {
            return { provider: this.name, source_display_name: this.displayName, status: 'error', reason: `GitHub API returned ${response.status}.`, findings }
          }
          user = await response.json()
          cache.set(key, { createdAt: Date.now(), user })
          if (cache.size > 200) cache.delete(cache.keys().next().value)
        } catch (error) {
          if (error.name === 'AbortError') throw error
          return { provider: this.name, source_display_name: this.displayName, status: 'error', reason: 'GitHub request failed.', findings }
        }
      }

      anyFound = true
      let repositories = []
      try {
        const repoResponse = await githubFetch(
          `/users/${encodeURIComponent(user.login || username)}/repos?per_page=10&sort=updated`,
          this.token,
          signal,
        )
        if (repoResponse.ok) {
          const payload = await repoResponse.json()
          repositories = Array.isArray(payload)
            ? payload.slice(0, 10).map(repo => ({
                name: repo.name || null,
                url: repo.html_url || null,
                description: repo.description || null,
              }))
            : []
        }
      } catch (error) {
        if (error.name === 'AbortError') throw error
        // Profile lookup remains useful if the optional repository listing fails.
      }

      const information = {
        username: user.login || username,
        display_name: user.name || null,
        bio: user.bio || null,
        location: user.location || null,
        website: user.blog || null,
        public_repositories: Number.isFinite(user.public_repos) ? user.public_repos : null,
        public_repository_references: repositories,
        public_email: user.email || null,
        profile_url: user.html_url || `https://github.com/${encodeURIComponent(username)}`,
      }

      findings.push({
        source: 'github',
        source_display_name: 'GitHub',
        status: 'found',
        match_type: user.login?.toLowerCase() === username.toLowerCase() ? 'confirmed' : 'possible',
        confidence: 'high',
        profile_url: information.profile_url,
        matched_identifier: username,
        information,
        evidence: [
          `GitHub returned a public profile whose username matches "${username}".`,
          information.website ? 'A public website is listed on the profile.' : null,
          information.public_email ? 'A public email is exposed by the profile.' : null,
        ].filter(Boolean),
        collected_at: new Date().toISOString(),
      })
    }

    return {
      provider: this.name,
      source_display_name: this.displayName,
      status: anyFound ? 'found' : 'not_found',
      reason: anyFound ? null : 'No matching public GitHub profile was returned.',
      findings,
    }
  }
}
