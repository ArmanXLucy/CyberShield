import dns from 'node:dns/promises'
import net from 'node:net'
import tls from 'node:tls'
import http from 'node:http'
import https from 'node:https'
import crypto from 'node:crypto'
import { URL } from 'node:url'

const DEFAULT_TIMEOUT_MS = Number(process.env.URL_SCAN_TIMEOUT_MS || 12000)
const MAX_REDIRECTS = Number(process.env.URL_MAX_REDIRECTS || 8)
const MAX_HTML_BYTES = Number(process.env.URL_MAX_HTML_BYTES || 512 * 1024)
const MAX_RESPONSE_BYTES = Number(process.env.URL_MAX_RESPONSE_BYTES || 1024 * 1024)
const MAX_DNS_RECORDS = 20
const MAX_CNAME_CHAIN = 5
let urlscanActive = 0
const MAX_URLSCAN_CONCURRENCY = Number(
  process.env.URLSCAN_MAX_CONCURRENCY || 2
)

const SENSITIVE_QUERY_KEYS = new Set([
  'token',
  'access_token',
  'auth',
  'authorization',
  'api_key',
  'apikey',
  'key',
  'secret',
  'password',
  'passwd',
  'pwd',
  'session',
  'sessionid',
  'sid',
  'code',
  'otp',
  'reset',
  'reset_token',
  'verification',
  'verify_token',
  'email',
  'phone',
  'document',
  'signature',
])

const REDIRECT_KEYS = new Set([
  'redirect',
  'url',
  'next',
  'return',
  'continue',
  'target',
  'dest',
  'destination',
])

const SUSPICIOUS_KEYWORDS = new Set([
  'login',
  'verify',
  'verification',
  'secure',
  'account',
  'password',
  'update',
  'signin',
  'bank',
  'wallet',
  'payment',
  'confirm',
])

const BRANDS = {
  google: ['google.com', 'googleusercontent.com'],
  microsoft: [
    'microsoft.com',
    'live.com',
    'office.com',
    'microsoftonline.com',
  ],
  apple: ['apple.com', 'icloud.com'],
  amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk'],
  paypal: ['paypal.com'],
  facebook: ['facebook.com', 'fb.com'],
  instagram: ['instagram.com'],
  github: ['github.com'],
  'microsoft 365': [
    'microsoft.com',
    'office.com',
    'microsoftonline.com',
  ],
  netflix: ['netflix.com'],
}

const SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'is.gd',
  'ow.ly',
  'buff.ly',
  'cutt.ly',
  'shorturl.at',
])

const COMMON_SECOND_LEVEL_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'me.uk',
  'ac.uk',
  'gov.uk',
  'com.au',
  'net.au',
  'org.au',
  'edu.au',
  'co.in',
  'firm.in',
  'net.in',
  'org.in',
  'gen.in',
  'ind.in',
  'co.jp',
  'ne.jp',
  'or.jp',
  'com.br',
  'com.cn',
  'com.mx',
  'com.sg',
  'com.hk',
  'com.tr',
  'com.tw',
  'co.nz',
  'co.za',
])

function finding(
  severity,
  category,
  title,
  description,
  evidence,
  source = 'local_analysis',
  recommendation = ''
) {
  return {
    severity,
    category,
    title,
    description,
    evidence,
    source,
    ...(recommendation ? { recommendation } : {}),
  }
}

function unique(list) {
  return [...new Set(list)]
}

function isPrivateIp(ip) {
  const version = net.isIP(ip)

  if (version === 4) {
    const n = ip
      .split('.')
      .reduce((a, oct) => (a << 8) + Number(oct), 0) >>> 0

    const ranges = [
      [0x00000000, 0x00ffffff],
      [0x0a000000, 0x0affffff],
      [0x64400000, 0x647fffff],
      [0x7f000000, 0x7fffffff],
      [0xa9fe0000, 0xa9feffff],
      [0xac100000, 0xac1fffff],
      [0xc0a80000, 0xc0a8ffff],
      [0xe0000000, 0xffffffff],
    ]

    return ranges.some(([a, b]) => n >= a && n <= b)
  }

  const normalized = ip.toLowerCase()

  return (
    normalized === '::1' ||
    normalized === '::' ||
    normalized.startsWith('fc') ||
    normalized.startsWith('fd') ||
    normalized.startsWith('fe8') ||
    normalized.startsWith('fe9') ||
    normalized.startsWith('fea') ||
    normalized.startsWith('feb') ||
    normalized.startsWith('::ffff:127.') ||
    normalized.startsWith('::ffff:10.') ||
    normalized.startsWith('::ffff:192.168.') ||
    normalized.startsWith('::ffff:172.16.')
  )
}

function ipFromNumericHost(host) {
  const raw = String(host || '')
    .replace(/^\[|\]$/g, '')
    .toLowerCase()

  if (net.isIP(raw)) {
    return raw
  }

  if (/^0x[0-9a-f]+$/.test(raw)) {
    const n = Number.parseInt(raw, 16)

    if (
      Number.isSafeInteger(n) &&
      n >= 0 &&
      n <= 0xffffffff
    ) {
      return [
        n >>> 24,
        (n >>> 16) & 255,
        (n >>> 8) & 255,
        n & 255,
      ].join('.')
    }
  }

  if (/^\d+$/.test(raw)) {
    const n = Number(raw)

    if (
      Number.isSafeInteger(n) &&
      n >= 0 &&
      n <= 0xffffffff
    ) {
      return [
        n >>> 24,
        (n >>> 16) & 255,
        (n >>> 8) & 255,
        n & 255,
      ].join('.')
    }
  }

  if (raw.includes('.')) {
    const parts = raw.split('.')

    if (
      parts.length >= 2 &&
      parts.length <= 4 &&
      parts.every(
        (p) => /^(?:0x[0-9a-f]+|0[0-7]+|\d+)$/.test(p)
      )
    ) {
      try {
        const nums = parts.map((p) =>
          p.startsWith('0x')
            ? Number.parseInt(p, 16)
            : p.length > 1 && p.startsWith('0')
              ? Number.parseInt(p, 8)
              : Number(p)
        )

        const max = [0xff, 0xff, 0xff, 0xffffffff]

        if (
          nums.every(
            (n, i) =>
              Number.isSafeInteger(n) &&
              n >= 0 &&
              n <= max[i]
          )
        ) {
          let n

          if (nums.length === 2) {
            n = nums[0] * 0x1000000 + nums[1]
          } else if (nums.length === 3) {
            n =
              nums[0] * 0x1000000 +
              nums[1] * 0x10000 +
              nums[2]
          } else {
            n =
              nums[0] * 0x1000000 +
              nums[1] * 0x10000 +
              nums[2] * 0x100 +
              nums[3]
          }

          if (n >= 0 && n <= 0xffffffff) {
            return [
              Math.floor(n / 0x1000000) & 255,
              Math.floor(n / 0x10000) & 255,
              Math.floor(n / 0x100) & 255,
              n & 255,
            ].join('.')
          }
        }
      } catch {}
    }
  }

  return null
}

function assertSafeHost(hostname) {
  const host = String(hostname || '')
    .toLowerCase()
    .replace(/\.$/, '')

  if (!host) {
    throw Object.assign(
      new Error('Hostname is required.'),
      { code: 'invalid_hostname' }
    )
  }

  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host === 'metadata.google.internal' ||
    host === 'metadata.google'
  ) {
    throw Object.assign(
      new Error(
        'Private or local network destinations are not allowed.'
      ),
      { code: 'private_destination' }
    )
  }

  const trickIp = ipFromNumericHost(host)

  if (trickIp && isPrivateIp(trickIp)) {
    throw Object.assign(
      new Error(
        'Private or local network destinations are not allowed.'
      ),
      { code: 'private_destination' }
    )
  }
}

function normalizeUrl(input) {
  const raw = String(input || '').trim()

  if (!raw) {
    throw Object.assign(
      new Error('A URL is required.'),
      { code: 'url_required' }
    )
  }

  if (raw.length > 8192) {
    throw Object.assign(
      new Error('URL is too long.'),
      { code: 'url_too_long' }
    )
  }

  const candidate =
    /^[a-z][a-z\d+.-]*:\/\//i.test(raw)
      ? raw
      : `https://${raw}`

  let parsed

  try {
    parsed = new URL(candidate)
  } catch {
    throw Object.assign(
      new Error('Malformed URL.'),
      { code: 'invalid_url' }
    )
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw Object.assign(
      new Error(
        'Only HTTP and HTTPS URLs are supported.'
      ),
      { code: 'unsupported_scheme' }
    )
  }

  if (parsed.username || parsed.password) {
    throw Object.assign(
      new Error(
        'URLs containing embedded usernames or passwords are not allowed.'
      ),
      { code: 'url_credentials' }
    )
  }

  if (
    !parsed.hostname ||
    parsed.hostname.length > 253
  ) {
    throw Object.assign(
      new Error('Invalid hostname.'),
      { code: 'invalid_hostname' }
    )
  }

  assertSafeHost(parsed.hostname)

  if (
    parsed.port &&
    (
      !/^\d+$/.test(parsed.port) ||
      Number(parsed.port) < 1 ||
      Number(parsed.port) > 65535
    )
  ) {
    throw Object.assign(
      new Error('URL port is invalid.'),
      { code: 'invalid_port' }
    )
  }

  return parsed
}

function safeUrlForDisplay(url) {
  const u = new URL(url)

  for (const key of [...u.searchParams.keys()]) {
    if (
      SENSITIVE_QUERY_KEYS.has(
        key.toLowerCase()
      )
    ) {
      u.searchParams.set(key, 'REDACTED')
    }
  }

  return u.toString()
}

function registeredDomain(hostname) {
  const host = String(hostname || '')
    .toLowerCase()
    .replace(/^www\./, '')
    .replace(/\.$/, '')

  const labels = host
    .split('.')
    .filter(Boolean)

  if (labels.length <= 2) {
    return labels.join('.')
  }

  const last2 = labels
    .slice(-2)
    .join('.')

  if (
    COMMON_SECOND_LEVEL_SUFFIXES.has(last2) &&
    labels.length >= 3
  ) {
    return labels.slice(-3).join('.')
  }

  return last2
}

function structuralAnalysis(u) {
  const host = u.hostname.toLowerCase()
  const reg = registeredDomain(host)

  const subdomain =
    host === reg
      ? ''
      : host.slice(0, -(reg.length + 1))

  const queryKeys = [
    ...u.searchParams.keys(),
  ]

  const encodedMatches =
    u.href.match(/%[0-9a-f]{2}/gi) || []

  const suspiciousEncoding =
    encodedMatches.filter((x) =>
      [
        '%2f',
        '%3d',
        '%40',
        '%00',
        '%25',
        '%5c',
      ].includes(x.toLowerCase())
    )

  const doubleEncoding =
    /%25(?:2f|3d|40|00|5c)/i.test(u.href)

  const keywordHits = unique(
    `${u.pathname} ${u.search}`
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter(Boolean)
      .filter((x) =>
        SUSPICIOUS_KEYWORDS.has(x)
      )
  )

  const redirectKeys =
    queryKeys.filter((k) =>
      REDIRECT_KEYS.has(k.toLowerCase())
    )

  const isIp = Boolean(
    net.isIP(host) ||
      ipFromNumericHost(host)
  )

  const flags = {
    excessive_subdomains: subdomain
      ? subdomain.split('.').length >= 3
      : false,

    ip_based: isIp,

    suspicious_port: [
      8080,
      8000,
      4444,
      8443,
      8888,
    ].includes(
      Number(
        u.port ||
          (
            u.protocol === 'https:'
              ? 443
              : 80
          )
      )
    ),

    long_url:
      u.href.length > 1800,

    many_query_parameters:
      queryKeys.length > 12,

    encoded_characters:
      encodedMatches.length > 0,

    suspicious_encoded_characters:
      suspiciousEncoding.length > 0,

    double_encoding:
      doubleEncoding,

    redirect_parameters:
      redirectKeys.length > 0,

    suspicious_keywords:
      keywordHits.length > 0,
  }

  return {
    scheme:
      u.protocol.slice(0, -1),

    hostname:
      host,

    registered_domain:
      reg,

    subdomain,

    port:
      Number(
        u.port ||
          (
            u.protocol === 'https:'
              ? 443
              : 80
          )
      ),

    path:
      u.pathname || '/',

    query:
      u.search
        ? '[redacted in report]'
        : '',

    fragment_present:
      Boolean(u.hash),

    username_present:
      Boolean(u.username),

    password_present:
      Boolean(u.password),

    length:
      u.href.length,

    query_parameter_count:
      queryKeys.length,

    flags,

    keyword_hits:
      keywordHits,

    redirect_parameter_keys:
      redirectKeys,

    encoded_count:
      encodedMatches.length,

    suspicious_encoded_count:
      suspiciousEncoding.length,

    punycode:
      host.includes('xn--'),

    unicode_host:
      /[^\x00-\x7f]/.test(host),
  }
}

async function resolveHost(hostname) {
  assertSafeHost(hostname)

  const addresses =
    await dns.lookup(
      hostname,
      {
        all: true,
        verbatim: true,
      }
    )

  if (!addresses.length) {
    throw Object.assign(
      new Error(
        'Hostname did not resolve.'
      ),
      { code: 'dns_no_records' }
    )
  }

  const uniqueAddresses = unique(
    addresses.map(
      (a) => a.address
    )
  ).slice(
    0,
    MAX_DNS_RECORDS
  )

  for (const ip of uniqueAddresses) {
    if (isPrivateIp(ip)) {
      throw Object.assign(
        new Error(
          'Hostname resolves to a private or local network address.'
        ),
        { code: 'private_destination' }
      )
    }
  }

  return uniqueAddresses
}

async function cnameChain(hostname) {
  const chain = []
  let current = hostname

  for (
    let i = 0;
    i < MAX_CNAME_CHAIN;
    i++
  ) {
    try {
      const next =
        await dns.resolveCname(
          current
        )

      if (!next?.length) {
        break
      }

      const target =
        String(next[0])
          .replace(/\.$/, '')

      if (
        !target ||
        chain.includes(target) ||
        target === current
      ) {
        break
      }

      chain.push(target)
      current = target
    } catch {
      break
    }
  }

  return chain
}

async function dnsAnalysis(hostname) {
  const result = {
    status: 'pass',
    records: {},
    cname_chain: [],
    observations: [],
  }

  try {
    const [
      addresses,
      mx,
      ns,
      txt,
      cname,
    ] = await Promise.allSettled([
      resolveHost(hostname),
      dns.resolveMx(hostname),
      dns.resolveNs(hostname),
      dns.resolveTxt(hostname),
      cnameChain(hostname),
    ])

    if (
      addresses.status === 'rejected'
    ) {
      throw addresses.reason
    }

    result.records.A_AAAA =
      addresses.value

    if (
      mx.status === 'fulfilled'
    ) {
      result.records.MX =
        mx.value.slice(
          0,
          MAX_DNS_RECORDS
        )
    }

    if (
      ns.status === 'fulfilled'
    ) {
      result.records.NS =
        ns.value.slice(
          0,
          MAX_DNS_RECORDS
        )
    }

    if (
      txt.status === 'fulfilled'
    ) {
      result.records.TXT =
        txt.value
          .slice(
            0,
            MAX_DNS_RECORDS
          )
          .map((v) =>
            Array.isArray(v)
              ? v.join('')
              : v
          )
    }

    if (
      cname.status === 'fulfilled'
    ) {
      result.records.CNAME =
        cname.value.slice(
          0,
          MAX_DNS_RECORDS
        )

      if (
        cname.value.length >=
        MAX_CNAME_CHAIN
      ) {
        result.observations.push(
          'CNAME chain reached the configured inspection limit.'
        )
      }
    }
  } catch (error) {
    result.status =
      'unavailable'

    result.error =
      error.message
  }

  return result
}

function tlsDetailsFromSocket(
  socket,
  hostname
) {
  const cert =
    socket.getPeerCertificate(true)

  const protocol =
    socket.getProtocol?.() || null

  const authorized =
    socket.authorized

  const authorizationError =
    socket.authorizationError || null

  const validTo =
    cert.valid_to
      ? new Date(cert.valid_to)
      : null

  const validFrom =
    cert.valid_from
      ? new Date(cert.valid_from)
      : null

  const san =
    typeof cert.subjectaltname === 'string'
      ? cert.subjectaltname
          .split(/,\s*/)
          .map((x) =>
            x.replace(/^DNS:/, '')
          )
          .filter(Boolean)
      : []

  return {
    valid: Boolean(
      authorized &&
        (!validTo ||
          validTo > new Date()) &&
        (!validFrom ||
          validFrom <= new Date())
    ),

    authorized,

    authorization_error:
      authorizationError,

    issuer:
      cert.issuer?.O ||
      cert.issuer?.CN ||
      null,

    subject:
      cert.subject?.CN ||
      null,

    san:
      san.slice(0, 50),

    valid_from:
      cert.valid_from ||
      null,

    valid_to:
      cert.valid_to ||
      null,

    protocol,

    fingerprint256:
      cert.fingerprint256 ||
      null,

    hostname,

    hostname_match:
      !authorizationError ||
      !/hostname/i.test(
        String(authorizationError)
      ),
  }
}

function requestOnce(
  urlString,
  {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxBytes = MAX_RESPONSE_BYTES,
  } = {}
) {
  const target =
    new URL(urlString)

  assertSafeHost(
    target.hostname
  )

  const transport =
    target.protocol === 'https:'
      ? https
      : http

  return new Promise(
    (resolve, reject) => {
      let settled = false
      let bytes = 0
      const chunks = []
      let tlsInfo = null

      const finish = (
        err,
        value
      ) => {
        if (settled) {
          return
        }

        settled = true
        clearTimeout(timer)

        if (err) {
          reject(err)
        } else {
          resolve(value)
        }
      }

      const options = {
        protocol:
          target.protocol,

        hostname:
          target.hostname,

        port:
          target.port || undefined,

        path:
          `${target.pathname || '/'}${
            target.search || ''
          }`,

        method:
          'GET',

        headers: {
          'User-Agent':
            'CyberShield URL Security Scanner/1.0',

          Accept:
            'text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5',

          'Accept-Encoding':
            'identity',

          Connection:
            'close',
        },

        maxHeaderSize:
          32 * 1024,

        timeout:
          timeoutMs,

        lookup: (
          hostname,
          opts,
          callback
        ) => {
          dns.lookup(
            hostname,
            {
              all: true,
              verbatim: true,
            }
          )
            .then((results) => {
              const safe =
                results
                  .map(
                    (r) => r.address
                  )
                  .filter(
                    (ip) =>
                      !isPrivateIp(ip)
                  )

              if (!safe.length) {
                return callback(
                  Object.assign(
                    new Error(
                      'Destination resolves to a private or local address.'
                    ),
                    {
                      code:
                        'private_destination',
                    }
                  )
                )
              }

              callback(
                null,
                safe[0],
                net.isIP(safe[0])
              )
            })
            .catch(callback)
        },

        ...(target.protocol === 'https:'
          ? {
              servername:
                target.hostname,

              rejectUnauthorized:
                false,

              minVersion:
                'TLSv1.2',
            }
          : {}),
      }

      const req =
        transport.request(
          options,
          (res) => {
            res.on(
              'data',
              (chunk) => {
                bytes +=
                  chunk.length

                if (
                  bytes <= maxBytes
                ) {
                  chunks.push(chunk)
                }

                if (
                  bytes > maxBytes
                ) {
                  req.destroy(
                    Object.assign(
                      new Error(
                        'Response exceeded the scanner limit.'
                      ),
                      {
                        code:
                          'response_too_large',
                      }
                    )
                  )
                }
              }
            )

            res.on(
              'end',
              () => {
                const body =
                  Buffer.concat(
                    chunks
                  ).toString(
                    'utf8'
                  )

                resolve({
                  status_code:
                    res.statusCode ||
                    0,

                  headers:
                    Object.fromEntries(
                      Object.entries(
                        res.headers
                      ).map(
                        ([k, v]) => [
                          k.toLowerCase(),
                          Array.isArray(v)
                            ? v.join(', ')
                            : String(
                                v ?? ''
                              ),
                        ]
                      )
                    ),

                  body,

                  bytes,

                  tls:
                    tlsInfo,
                })
              }
            )

            res.on(
              'error',
              finish
            )
          }
        )

      req.on(
        'socket',
        (socket) => {
          if (
            target.protocol ===
            'https:'
          ) {
            socket.once(
              'secureConnect',
              () => {
                try {
                  tlsInfo =
                    tlsDetailsFromSocket(
                      socket,
                      target.hostname
                    )
                } catch {}
              }
            )
          }
        }
      )

      req.on(
        'timeout',
        () =>
          req.destroy(
            Object.assign(
              new Error(
                'HTTP request timed out.'
              ),
              {
                code:
                  'timeout',
              }
            )
          )
      )

      req.on(
        'error',
        finish
      )

      req.end()

      const timer =
        setTimeout(
          () =>
            req.destroy(
              Object.assign(
                new Error(
                  'HTTP request timed out.'
                ),
                {
                  code:
                    'timeout',
                }
              )
            ),
          timeoutMs
        )
    }
  )
}

async function fetchSafe(
  urlString,
  maxRedirects = MAX_REDIRECTS
) {
  const chain = []
  let current = urlString
  let response = null
  const visited = new Set()

  for (
    let i = 0;
    i <= maxRedirects;
    i++
  ) {
    const normalized =
      safeUrlForDisplay(
        current
      )

    if (
      visited.has(normalized)
    ) {
      return {
        chain,
        final_url: current,
        response,
        loop: true,
      }
    }

    visited.add(
      normalized
    )

    const u =
      normalizeUrl(current)

    await resolveHost(
      u.hostname
    )

    response =
      await requestOnce(
        u.toString(),
        {
          maxBytes:
            MAX_RESPONSE_BYTES,
        }
      )

    chain.push({
      url:
        safeUrlForDisplay(
          u.toString()
        ),

      status_code:
        response.status_code,

      location:
        response.headers.location
          ? safeUrlForDisplay(
              new URL(
                response.headers.location,
                u
              ).toString()
            )
          : null,
    })

    if (
      ![
        301,
        302,
        303,
        307,
        308,
      ].includes(
        response.status_code
      ) ||
      !response.headers.location
    ) {
      return {
        chain,
        final_url: u.toString(),
        response,
        loop: false,
      }
    }

    if (
      i === maxRedirects
    ) {
      return {
        chain,
        final_url:
          u.toString(),
        response,
        max_redirects:
          true,
      }
    }

    const next =
      new URL(
        response.headers.location,
        u
      )

    assertSafeHost(
      next.hostname
    )

    current =
      next.toString()
  }

  return {
    chain,
    final_url: current,
    response,
  }
}

function pageAnalysis(
  html,
  baseUrl
) {
  const sample =
    String(html || '')
      .slice(
        0,
        MAX_HTML_BYTES
      )

  const title =
    (
      sample.match(
        /<title[^>]*>([\s\S]*?)<\/title>/i
      )?.[1] || ''
    )
      .replace(
        /\s+/g,
        ' '
      )
      .trim()
      .slice(
        0,
        300
      )

  const forms =
    [
      ...sample.matchAll(
        /<form\b([^>]*)>/gi
      ),
    ]
      .slice(
        0,
        20
      )
      .map(
        (m) => m[1]
      )

  const passwordFields =
    (
      sample.match(
        /<input\b[^>]*(?:type\s*=\s*["']?password|name\s*=\s*["']?pass)/gi
      ) || []
    ).length

  const externalFormActions = []

  for (
    const attrs of forms
  ) {
    const action =
      attrs.match(
        /action\s*=\s*["']([^"']+)/i
      )?.[1]

    if (action) {
      try {
        const absolute =
          new URL(
            action,
            baseUrl
          )

        if (
          absolute.origin !==
          new URL(
            baseUrl
          ).origin
        ) {
          externalFormActions.push(
            safeUrlForDisplay(
              absolute.toString()
            )
          )
        }
      } catch {}
    }
  }

  const iframes =
    [
      ...sample.matchAll(
        /<iframe\b[^>]*src\s*=\s*["']([^"']+)/gi
      ),
    ]
      .slice(
        0,
        20
      )
      .map(
        (m) => m[1]
      )

  const scripts =
    [
      ...sample.matchAll(
        /<script\b[^>]*src\s*=\s*["']([^"']+)/gi
      ),
    ]
      .slice(
        0,
        20
      )
      .map(
        (m) => m[1]
      )

  const jsPatterns = [
    'eval\\s*\\(',
    'document\\.location',
    'window\\.location',
    'atob\\s*\\(',
    'fromCharCode\\s*\\(',
  ]

  const jsHits =
    jsPatterns.filter(
      (p) =>
        new RegExp(
          p,
          'i'
        ).test(sample)
    )

  return {
    title:
      title || null,

    login_form_detected:
      passwordFields > 0 ||
      /\b(?:login|sign[ -]?in)\b/i.test(
        title
      ),

    password_field_count:
      passwordFields,

    external_form_actions:
      externalFormActions,

    iframe_sources:
      iframes,

    external_script_sources:
      scripts,

    javascript_static_indicators:
      jsHits,

    html_bytes_analyzed:
      Buffer.byteLength(
        sample
      ),
  }
}

function localReputation(
  structure
) {
  const configured =
    String(
      process.env.CYBERSHIELD_BLOCKLIST_DOMAINS ||
        ''
    )
      .split(',')
      .map(
        (x) =>
          x
            .trim()
            .toLowerCase()
            .replace(
              /^\.+|\.+$/g,
              ''
            )
      )
      .filter(Boolean)

  const defaults =
    String(
      process.env.CYBERSHIELD_KNOWN_BAD_DOMAINS ||
        ''
    )
      .split(',')
      .map(
        (x) =>
          x
            .trim()
            .toLowerCase()
            .replace(
              /^\.+|\.+$/g,
              ''
            )
      )
      .filter(Boolean)

  const blocked =
    unique([
      ...configured,
      ...defaults,
    ])

  const matched =
    blocked.find(
      (domain) =>
        structure.registered_domain ===
          domain ||
        structure.registered_domain.endsWith(
          `.${domain}`
        )
    )

  return matched
    ? finding(
        'critical',
        'reputation',
        'Known malicious indicator matched',
        'The registered domain matches a locally configured known-bad domain rule.',
        `Registered domain: ${structure.registered_domain}; matched rule: ${matched}`,
        'local_reputation',
        'Avoid visiting the site and do not download files from it.'
      )
    : null
}

function analyzePhishing({
  structure,
  page,
  redirects,
  domain,
  tlsInfo,
}) {
  const signals = []

  const reg =
    structure.registered_domain

  const host =
    structure.hostname

  const brandHits = []

  const combinedText =
    `${host} ${structure.path} ${
      page?.title || ''
    }`.toLowerCase()

  for (
    const [brand, domains] of
      Object.entries(BRANDS)
  ) {
    if (
      !combinedText.includes(
        brand.split(' ')[0]
      )
    ) {
      continue
    }

    if (
      !domains.some(
        (d) =>
          reg === d ||
          reg.endsWith(
            `.${d}`
          )
      )
    ) {
      brandHits.push(
        brand
      )
    }
  }

  if (brandHits.length) {
    signals.push(
      finding(
        'high',
        'phishing',
        'Possible brand impersonation',
        `Brand references (${brandHits.join(', ')}) appear outside their known registered domains.`,
        `Registered domain: ${reg}; brand references: ${brandHits.join(', ')}`,
        'brand_heuristic',
        'Verify the registered domain before entering credentials.'
      )
    )
  }

  if (
    structure.punycode ||
    structure.unicode_host
  ) {
    signals.push(
      finding(
        'medium',
        'phishing',
        'Internationalized domain detected',
        'The hostname uses Unicode or punycode representation and may contain visually confusable characters.',
        `Hostname: ${host}`,
        'local_analysis',
        'Verify the normalized domain carefully.'
      )
    )
  }

  if (
    page?.password_field_count > 0 &&
    brandHits.length
  ) {
    signals.push(
      finding(
        'high',
        'phishing',
        'Credential collection on unrelated domain',
        'A password field was detected on a page whose hostname does not match the referenced brand domain.',
        `Password fields: ${page.password_field_count}; registered domain: ${reg}`,
        'page_analysis',
        'Do not enter credentials until the site is independently verified.'
      )
    )
  }

  if (
    redirects?.length > 1
  ) {
    const domains =
      unique(
        redirects
          .map(
            (r) => {
              try {
                return registeredDomain(
                  new URL(
                    r.url
                  ).hostname
                )
              } catch {
                return ''
              }
            }
          )
          .filter(Boolean)
      )

    if (
      domains.length > 1
    ) {
      signals.push(
        finding(
          'medium',
          'redirect',
          'Cross-domain redirect chain',
          'The URL redirected across multiple registered domains before reaching the final response.',
          `Registered domains: ${domains.join(' → ')}`,
          'redirect_analysis',
          'Review the final destination before interacting with it.'
        )
      )
    }

    if (
      redirects.some(
        (r, i) =>
          i > 0 &&
          /^https:/i.test(
            redirects[i - 1].url
          ) &&
          /^http:/i.test(
            r.url
          )
      )
    ) {
      signals.push(
        finding(
          'medium',
          'redirect',
          'HTTPS to HTTP downgrade',
          'The redirect chain moves from HTTPS to HTTP.',
          'A redirect destination used HTTP after HTTPS.',
          'redirect_analysis',
          'Avoid entering sensitive information over a downgraded connection.'
        )
      )
    }
  }

  if (
    page?.external_form_actions?.length
  ) {
    signals.push(
      finding(
        'medium',
        'phishing',
        'External form submission detected',
        'A form submits data to a different origin than the scanned page.',
        page.external_form_actions.join(
          ', '
        ),
        'page_analysis',
        'Verify the destination before submitting information.'
      )
    )
  }

  if (
    structure.flags.redirect_parameters
  ) {
    signals.push(
      finding(
        'low',
        'redirect',
        'Redirect parameter detected',
        'The URL contains a parameter commonly used to select another destination.',
        structure.redirect_parameter_keys.join(
          ', '
        ),
        'local_analysis',
        'Inspect the final destination before following it.'
      )
    )
  }

  if (
    tlsInfo &&
    tlsInfo.valid === false
  ) {
    signals.push(
      finding(
        'high',
        'tls',
        'TLS certificate validation failed',
        'The HTTPS connection did not present a certificate that the scanner could validate for this host.',
        tlsInfo.authorization_error ||
          'Certificate validation failed.',
        'tls_analysis',
        'Do not enter sensitive information until the certificate problem is resolved.'
      )
    )
  }

  return signals
}

function localSignals(
  structure,
  dnsInfo,
  httpInfo,
  pageInfo,
  shortener
) {
  const s = []
  const f =
    structure.flags

  if (
    f.ip_based
  ) {
    s.push(
      finding(
        'medium',
        'url_structure',
        'IP-based URL',
        'The URL uses an IP address instead of a domain name.',
        structure.hostname,
        'local_analysis',
        'Verify why the site uses a direct IP before continuing.'
      )
    )
  }

  if (
    f.excessive_subdomains
  ) {
    s.push(
      finding(
        'low',
        'url_structure',
        'Many subdomains',
        'The hostname contains several subdomain levels. This is unusual in some phishing URLs but is not conclusive.',
        structure.hostname,
        'local_analysis'
      )
    )
  }

  if (
    f.suspicious_port
  ) {
    s.push(
      finding(
        'low',
        'url_structure',
        'Non-standard web port',
        'The URL uses a port that is less common for normal public web traffic.',
        String(
          structure.port
        ),
        'local_analysis'
      )
    )
  }

  if (
    f.long_url
  ) {
    s.push(
      finding(
        'low',
        'url_structure',
        'Long URL',
        'The submitted URL is unusually long.',
        `${structure.length} characters`,
        'local_analysis'
      )
    )
  }

  if (
    f.many_query_parameters
  ) {
    s.push(
      finding(
        'low',
        'url_structure',
        'Many query parameters',
        'The URL contains an unusually large number of query parameters.',
        `${structure.query_parameter_count} parameters`,
        'local_analysis'
      )
    )
  }

  if (
    f.suspicious_encoded_characters ||
    f.double_encoding
  ) {
    s.push(
      finding(
        'low',
        'url_structure',
        'Encoded URL characters',
        'The URL contains encoded or double-encoded separators that can obscure its meaning.',
        `${structure.suspicious_encoded_count} suspicious encoded characters`,
        'local_analysis'
      )
    )
  }

  if (
    f.suspicious_keywords
  ) {
    s.push(
      finding(
        'low',
        'url_structure',
        'Credential-related keywords',
        'The path or query contains words commonly associated with account or payment workflows.',
        structure.keyword_hits.join(
          ', '
        ),
        'local_analysis'
      )
    )
  }

  if (shortener) {
    s.push(
      finding(
        'low',
        'redirect',
        'URL shortening service detected',
        'The submitted hostname belongs to a common URL-shortening service, so the final destination is more important than the short link itself.',
        structure.registered_domain,
        'local_analysis',
        'Review the resolved destination before interacting.'
      )
    )
  }

  if (
    dnsInfo.status ===
    'unavailable'
  ) {
    s.push(
      finding(
        'informational',
        'dns',
        'DNS analysis unavailable',
        'DNS information could not be completed for this host.',
        dnsInfo.error ||
          'No DNS result.',
        'dns_analysis'
      )
    )
  }

  if (
    httpInfo?.status_code >=
    400
  ) {
    s.push(
      finding(
        'low',
        'http',
        'HTTP error response',
        'The destination returned an HTTP error status during passive analysis.',
        String(
          httpInfo.status_code
        ),
        'http_analysis'
      )
    )
  }

  return s
}

function riskEngine(
  signals,
  providerStatuses
) {
  const weights = {
    critical: 40,
    high: 28,
    medium: 12,
    low: 4,
    informational: 0,
  }

  const score =
    Math.min(
      100,
      signals.reduce(
        (sum, signal) =>
          sum +
          (weights[
            signal.severity
          ] || 0),
        0
      )
    )

  // Only authoritative reputation evidence can produce MALICIOUS.
  const hasAuthoritative =
    signals.some(
      (signal) =>
        signal.category ===
          'reputation' &&
        [
          'critical',
          'high',
        ].includes(
          signal.severity
        )
    )

  // Optional provider failures should not automatically make a normally
  // analyzable URL UNKNOWN.
  const meaningfulProviders =
    providerStatuses.filter(
      (provider) =>
        provider.name !==
        'urlscan.io'
    )

  let label =
    'SAFE / LOW RISK'

  if (
    hasAuthoritative
  ) {
    label =
      'MALICIOUS'
  } else if (
    score >= 45
  ) {
    label =
      'HIGH RISK'
  } else if (
    score >= 16
  ) {
    label =
      'SUSPICIOUS'
  } else {
    // UNKNOWN is reserved for cases where every meaningful local check
    // failed and there is effectively no evidence to assess the URL.
    const allMeaningfulUnavailable =
      meaningfulProviders.length >
        0 &&
      meaningfulProviders.every(
        (provider) =>
          [
            'unavailable',
            'error',
            'timeout',
            'blocked',
          ].includes(
            provider.status
          )
      )

    if (
      score === 0 &&
      allMeaningfulUnavailable
    ) {
      label =
        'UNKNOWN'
    }
  }

  const confidence =
    label === 'UNKNOWN'
      ? 'low'
      : score >= 45
        ? 'high'
        : score >= 16
          ? 'medium'
          : 'medium'

  return {
    label,

    status:
      label
        .toLowerCase()
        .replaceAll(
          ' / ',
          '_'
        )
        .replaceAll(
          ' ',
          '_'
        ),

    score,

    confidence,

    heuristic:
      true,
  }
}

async function urlscanProvider(
  url
) {
  if (
    String(
      process.env
        .CYBERSHIELD_MOCK_EXTERNAL_APIS
    ).toLowerCase() ===
    'true'
  ) {
    return {
      name:
        'urlscan.io',

      status:
        'completed',

      visibility:
        'mock',

      result: {
        verdicts: {
          overall: {
            malicious:
              false,
          },
        },
      },
    }
  }

  const apiKey =
    String(
      process.env
        .URLSCAN_API_KEY ||
        ''
    ).trim()

  if (!apiKey) {
    return {
      name:
        'urlscan.io',

      status:
        'not_configured',
    }
  }

  const u =
    new URL(url)

  const sensitive =
    [
      ...u.searchParams.keys(),
    ].some(
      (k) =>
        SENSITIVE_QUERY_KEYS.has(
          k.toLowerCase()
        )
    )

  if (
    sensitive &&
    String(
      process.env
        .URLSCAN_ALLOW_SENSITIVE_SUBMISSION
    ).toLowerCase() !==
      'true'
  ) {
    return {
      name:
        'urlscan.io',

      status:
        'skipped_sensitive_url',

      message:
        'External submission skipped because sensitive query parameters were detected.',
    }
  }

  const visibility =
    String(
      process.env
        .URLSCAN_VISIBILITY ||
        'unlisted'
    ).toLowerCase()

  if (
    ![
      'public',
      'unlisted',
      'private',
    ].includes(
      visibility
    )
  ) {
    return {
      name:
        'urlscan.io',

      status:
        'configuration_error',

      message:
        'URLSCAN_VISIBILITY must be public, unlisted, or private.',
    }
  }

  if (
    urlscanActive >=
    MAX_URLSCAN_CONCURRENCY
  ) {
    return {
      name:
        'urlscan.io',

      status:
        'busy',

      message:
        'Provider concurrency limit reached; local analysis continued.',
    }
  }

  urlscanActive += 1

  const headers = {
    'Content-Type':
      'application/json',

    'API-Key':
      apiKey,
  }

  const fetchJson =
    async (
      urlString,
      options = {}
    ) => {
      const controller =
        new AbortController()

      const timer =
        setTimeout(
          () =>
            controller.abort(),
          8000
        )

      try {
        const response =
          await fetch(
            urlString,
            {
              ...options,

              headers: {
                ...headers,
                ...(options.headers ||
                  {}),
              },

              signal:
                controller.signal,
            }
          )

        let body = null

        try {
          body =
            await response.json()
        } catch {}

        return {
          response,
          body,
        }
      } finally {
        clearTimeout(
          timer
        )
      }
    }

  try {
    const submitted =
      await fetchJson(
        'https://urlscan.io/api/v1/scan/',
        {
          method:
            'POST',

          body:
            JSON.stringify({
              url,
              visibility,
            }),
        }
      )

    const status =
      submitted.response
        .status

    if (
      !submitted.response.ok
    ) {
      return {
        name:
          'urlscan.io',

        status:
          status === 429
            ? 'rate_limited'
            : status === 401 ||
                status === 403
              ? 'unauthorized'
              : status >= 500
                ? 'provider_error'
                : 'error',

        http_status:
          status,
      }
    }

    const scanId =
      submitted.body?.uuid ||
      submitted.body?.scanId ||
      null

    const resultUrl =
      submitted.body?.result ||
      null

    if (!scanId) {
      return {
        name:
          'urlscan.io',

        status:
          'submitted',

        result_url:
          resultUrl,
      }
    }

    // The scan result can take a few seconds to become available.
    // Poll briefly using bounded retries and backoff.
    let result = null

    for (
      const delay of [
        750,
        1500,
        2500,
      ]
    ) {
      await new Promise(
        (resolve) =>
          setTimeout(
            resolve,
            delay
          )
      )

      const fetched =
        await fetchJson(
          `https://urlscan.io/api/v1/result/${encodeURIComponent(
            scanId
          )}/`,
          {
            method:
              'GET',
          }
        )

      if (
        fetched.response.ok
      ) {
        result =
          fetched.body

        break
      }

      if (
        ![
          404,
          429,
        ].includes(
          fetched.response
            .status
        )
      ) {
        break
      }
    }

    const malicious =
      result?.verdicts
        ?.overall
        ?.malicious === true

    return {
      name:
        'urlscan.io',

      status:
        result
          ? 'completed'
          : 'submitted',

      scan_id:
        scanId,

      result_url:
        resultUrl,

      visibility,

      verdict_malicious:
        malicious,

      result: result
        ? {
            verdicts:
              result.verdicts ||
              null,

            page:
              result.page ||
              null,
          }
        : null,
    }
  } catch (error) {
    return {
      name:
        'urlscan.io',

      status:
        error.name ===
        'AbortError'
          ? 'timeout'
          : 'unavailable',

      message:
        error.message,
    }
  } finally {
    urlscanActive =
      Math.max(
        0,
        urlscanActive - 1
      )
  }
}

function providerStatuses(
  dnsInfo,
  httpInfo,
  tlsInfo,
  urlscan,
  httpError = null
) {
  const providers = [
    {
      name:
        'Local analysis',

      status:
        'completed',
    },

    {
      name:
        'DNS',

      status:
        dnsInfo.status ===
        'pass'
          ? 'completed'
          : 'unavailable',
    },

    {
      name:
        'HTTP',

      status:
        httpInfo
          ? 'completed'
          : httpError?.status ||
            'unavailable',

      ...(httpError?.message
        ? {
            message:
              httpError.message,
          }
        : {}),
    },
  ]

  // TLS is only counted when TLS information actually exists.
  if (tlsInfo) {
    providers.push({
      name:
        'TLS',

      status:
        'completed',
    })
  }

  // urlscan.io is optional.
  // A missing API key must not make the whole scan UNKNOWN.
  if (urlscan) {
    providers.push(
      urlscan
    )
  }

  return providers
}

export async function scanUrl(
  input
) {
  const startedAt =
    Date.now()

  const initial =
    normalizeUrl(input)

  const scannedUrl =
    initial.toString()

  const structure =
    structuralAnalysis(
      initial
    )

  const dnsInfo =
    await dnsAnalysis(
      initial.hostname
    )

  const providers = []

  let fetchResult =
    null

  let httpInfo =
    null

  let pageInfo =
    null

  let finalUrl =
    scannedUrl

  let redirectLoop =
    false

  let maxRedirects =
    false

  let httpError =
    null

  try {
    fetchResult =
      await fetchSafe(
        scannedUrl
      )

    httpInfo =
      fetchResult.response

    finalUrl =
      fetchResult.final_url

    redirectLoop =
      Boolean(
        fetchResult.loop
      )

    maxRedirects =
      Boolean(
        fetchResult.max_redirects
      )

    if (
      httpInfo?.body &&
      /text\/html|application\/xhtml/i.test(
        httpInfo.headers[
          'content-type'
        ] || ''
      )
    ) {
      pageInfo =
        pageAnalysis(
          httpInfo.body,
          finalUrl
        )
    }
  } catch (error) {
    httpError = {
      status:
        error.code ===
        'private_destination'
          ? 'blocked'
          : 'unavailable',

      message:
        error.message,
    }
  }

  if (
    redirectLoop
  ) {
    providers.push({
      name:
        'Redirects',

      status:
        'loop_detected',
    })
  }

  if (
    maxRedirects
  ) {
    providers.push({
      name:
        'Redirects',

      status:
        'limit_reached',
    })
  }

  const redirects =
    fetchResult?.chain ||
    []

  const shortener =
    SHORTENERS.has(
      structure.registered_domain
    )

  const tlsInfo =
    httpInfo?.tls ||
    null

  const reputationFinding =
    localReputation(
      structure
    )

  const signals = [
    ...localSignals(
      structure,
      dnsInfo,
      httpInfo,
      pageInfo,
      shortener
    ),

    ...(reputationFinding
      ? [reputationFinding]
      : []),

    ...analyzePhishing({
      structure,
      page:
        pageInfo,
      redirects,
      domain:
        structure.registered_domain,
      tlsInfo,
    }),
  ]

  if (
    redirectLoop
  ) {
    signals.push(
      finding(
        'medium',
        'redirect',
        'Redirect loop detected',
        'The destination redirected back to a previously visited URL.',
        redirects
          .map(
            (r) => r.url
          )
          .join(' → '),
        'redirect_analysis',
        'Do not continue following the link.'
      )
    )
  }

  if (
    maxRedirects
  ) {
    signals.push(
      finding(
        'medium',
        'redirect',
        'Redirect limit reached',
        `The scanner stopped after ${MAX_REDIRECTS} redirects.`,
        String(
          MAX_REDIRECTS
        ),
        'redirect_analysis',
        'Review the redirect chain before continuing.'
      )
    )
  }

  if (
    initial.protocol ===
    'http:'
  ) {
    signals.push(
      finding(
        'low',
        'transport',
        'HTTPS not used',
        'The submitted URL uses unencrypted HTTP.',
        safeUrlForDisplay(
          scannedUrl
        ),
        'http_analysis',
        'Avoid entering sensitive information over an unencrypted connection.'
      )
    )
  }

  if (
    tlsInfo?.valid ===
    false
  ) {
    signals.push(
      finding(
        'high',
        'tls',
        'Certificate validation failed',
        'The HTTPS connection could not be validated by the scanner.',
        tlsInfo.authorization_error ||
          'TLS certificate validation failed.',
        'tls_analysis',
        'Do not enter sensitive information until the certificate issue is resolved.'
      )
    )
  }

  const urlscan =
    await urlscanProvider(
      scannedUrl
    )

  providers.push(
    ...providerStatuses(
      dnsInfo,
      httpInfo,
      tlsInfo,
      urlscan,
      httpError
    )
  )

  if (
    urlscan?.verdict_malicious ===
    true
  ) {
    signals.push(
      finding(
        'critical',
        'reputation',
        'External threat-intelligence match',
        'urlscan.io reported a malicious verdict for the submitted URL.',
        'urlscan.io verdicts.overall.malicious = true',
        'urlscan.io',
        'Avoid visiting the site and do not download files from it.'
      )
    )
  }

  const overall =
    riskEngine(
      signals,
      providers
    )

  const completed =
    providers.filter(
      (p) =>
        [
          'completed',
          'submitted',
        ].includes(
          p.status
        )
    ).length

  const unavailable =
    providers.filter(
      (p) =>
        ![
          'completed',
          'submitted',
        ].includes(
          p.status
        )
    ).length

  const report = {
    scan_id:
      crypto.randomUUID(),

    scan_type:
      'url',

    scanned_url:
      safeUrlForDisplay(
        scannedUrl
      ),

    final_url:
      safeUrlForDisplay(
        finalUrl
      ),

    hostname:
      structure.hostname,

    registered_domain:
      structure.registered_domain,

    overall,

    coverage: {
      completed_checks:
        completed,

      unavailable_checks:
        unavailable,

      total_checks:
        providers.length,

      percentage:
        providers.length
          ? Math.round(
              (completed /
                providers.length) *
                100
            )
          : 0,
    },

    duration_ms:
      Date.now() -
      startedAt,

    url_details:
      structure,

    dns:
      dnsInfo,

    http: httpInfo
      ? {
          status_code:
            httpInfo.status_code,

          content_type:
            httpInfo.headers[
              'content-type'
            ] || null,

          server:
            httpInfo.headers.server ||
            null,

          headers:
            Object.fromEntries(
              [
                'strict-transport-security',
                'content-security-policy',
                'x-content-type-options',
                'referrer-policy',
                'permissions-policy',
                'x-frame-options',
              ].map(
                (k) => [
                  k,
                  httpInfo.headers[
                    k
                  ] || null,
                ]
              )
            ),

          tls:
            tlsInfo,
        }
      : null,

    redirects,

    page_analysis:
      pageInfo,

    providers,

    signals,

    recommendations:
      recommendationsFor(
        signals,
        overall
      ),

    disclaimer:
      'CyberShield provides an automated security assessment based on available evidence. It cannot guarantee that a URL is completely safe or malicious.',
  }

  return report
}

function recommendationsFor(
  signals,
  overall
) {
  const out = []

  if (
    signals.some(
      (s) =>
        s.category ===
        'phishing'
    )
  ) {
    out.push(
      'Do not enter passwords or payment information until the domain is independently verified.'
    )
  }

  if (
    signals.some(
      (s) =>
        s.category ===
        'redirect'
    )
  ) {
    out.push(
      'Check the final destination before interacting with the page.'
    )
  }

  if (
    signals.some(
      (s) =>
        s.category ===
        'transport'
    )
  ) {
    out.push(
      'Avoid entering sensitive information over an unencrypted HTTP connection.'
    )
  }

  if (
    signals.some(
      (s) =>
        s.title.includes(
          'Internationalized'
        )
    )
  ) {
    out.push(
      'Verify the domain carefully because visually similar characters can be used in phishing.'
    )
  }

  if (
    overall.label ===
    'MALICIOUS'
  ) {
    out.push(
      'Avoid visiting the site and do not download files from it.'
    )
  }

  if (!out.length) {
    out.push(
      'No known malicious indicators were detected by the available checks; continue to use normal security precautions.'
    )
  }

  return unique(out)
}

export const _test = {
  isPrivateIp,
  ipFromNumericHost,
  normalizeUrl,
  registeredDomain,
  structuralAnalysis,
  riskEngine,
  safeUrlForDisplay,
}