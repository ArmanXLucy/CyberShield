export class FootprintProvider {
  constructor(name, displayName) {
    this.name = name
    this.displayName = displayName
  }

  isConfigured() {
    return false
  }

  async search(_profile, _helpers = {}) {
    return {
      provider: this.name,
      source_display_name: this.displayName,
      status: 'unavailable',
      reason: 'Provider is not configured.',
      findings: [],
    }
  }
}

/**
 * Safe retry wrapper for idempotent provider GET/metadata requests.
 * POST/token requests may also opt in explicitly with retryableMethods.
 * Never retries caller cancellation.
 */
export async function fetchWithRetry(url, options = {}, config = {}) {
  const retries = Number.isInteger(config.retries) ? config.retries : 2
  const baseDelay = Number.isFinite(config.baseDelay) ? config.baseDelay : 300
  const retryStatuses = new Set(config.retryStatuses || [408, 425, 429, 500, 502, 503, 504])
  const retryableMethods = new Set(config.retryableMethods || ['GET', 'HEAD'])
  const method = String(options.method || 'GET').toUpperCase()
  const canRetry = retryableMethods.has(method)
  let lastError

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    if (options.signal?.aborted) {
      const error = new Error('Request aborted.')
      error.name = 'AbortError'
      throw error
    }

    try {
      const response = await fetch(url, options)
      if (!canRetry || !retryStatuses.has(response.status) || attempt === retries) {
        return response
      }

      const retryAfter = Number(response.headers.get('retry-after'))
      const delay = Number.isFinite(retryAfter)
        ? Math.min(Math.max(retryAfter * 1000, baseDelay), 5000)
        : Math.min(baseDelay * (2 ** attempt), 2000)
      await new Promise(resolve => setTimeout(resolve, delay))
    } catch (error) {
      if (error?.name === 'AbortError') throw error
      lastError = error
      if (!canRetry || attempt === retries) throw error

      const delay = Math.min(baseDelay * (2 ** attempt), 2000)
      await new Promise(resolve => setTimeout(resolve, delay))
    }
  }

  throw lastError || new Error('Provider request failed.')
}
