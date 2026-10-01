'use strict'

const fs = require('node:fs')
const path = require('node:path')
const http = require('node:http')
const https = require('node:https')
const { createHash } = require('node:crypto')

// Only the one integrator-named launch file is opened. No profile/state discovery.
function readLaunch(file, expectedPid, origin) {
  if (!path.isAbsolute(file) || path.basename(file) !== 'launch-url.json'
    || !Number.isSafeInteger(expectedPid) || expectedPid < 1) throw new Error('PREVIEW_ACCESS_ARGUMENTS_INVALID')
  const parent = fs.lstatSync(path.dirname(file))
  const uid = process.getuid?.()
  if (uid === undefined || !parent.isDirectory() || parent.isSymbolicLink()
    || parent.uid !== uid || (parent.mode & 0o077)) throw new Error('PREVIEW_ACCESS_DIRECTORY_NOT_PRIVATE')
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
  let bytes
  try {
    const stat = fs.fstatSync(fd)
    if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== uid || (stat.mode & 0o077)
      || stat.size < 1 || stat.size > 16384) throw new Error('PREVIEW_ACCESS_FILE_NOT_PRIVATE')
    bytes = fs.readFileSync(fd)
    if (bytes.length > 16384) throw new Error('PREVIEW_ACCESS_FILE_TOO_LARGE')
    const data = JSON.parse(bytes.toString('utf8'))
    if (!data || Array.isArray(data) || Object.keys(data).sort().join(',') !== 'pid,url'
      || data.pid !== expectedPid || typeof data.url !== 'string') throw new Error('PREVIEW_ACCESS_PID_OR_FORMAT_MISMATCH')
    const launch = new URL(data.url)
    if (launch.origin !== origin.origin || launch.username || launch.password || launch.pathname !== '/'
      || launch.hash || [...launch.searchParams.keys()].join(',') !== 'token'
      || !launch.searchParams.get('token')) throw new Error('PREVIEW_ACCESS_URL_MISMATCH')
    return launch
  } finally { bytes?.fill(0); fs.closeSync(fd) }
}

function parseCookie(headers, origin) {
  const raw = headers['set-cookie']
  if (!Array.isArray(raw) || raw.length !== 1 || raw[0].length > 8192) throw new Error('PREVIEW_COOKIE_MISMATCH')
  const [pair, ...attrs] = raw[0].split(';').map(value => value.trim())
  const name = 'dsh-auth-' + createHash('sha256').update(origin.host).digest('base64url')
  const value = pair.slice(name.length + 1)
  if (!pair.startsWith(name + '=') || !/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)
    || !attrs.some(a => /^HttpOnly$/i.test(a)) || !attrs.some(a => /^SameSite=Strict$/i.test(a))
    || !attrs.some(a => /^Path=\/$/i.test(a)) || attrs.some(a => /^Domain=/i.test(a))
    || (origin.protocol === 'https:' && !attrs.some(a => /^Secure$/i.test(a)))) throw new Error('PREVIEW_COOKIE_SCOPE_MISMATCH')
  return { url: origin.href, name, value, path: '/', httpOnly: true,
    secure: origin.protocol === 'https:', sameSite: 'strict' }
}

function requestHeaders(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http
    const request = transport.request(url, { method: 'GET', headers, agent: false, maxHeaderSize: 16384 }, response => {
      resolve({ status: response.statusCode, headers: response.headers })
      response.destroy()
    })
    request.setTimeout(5000, () => request.destroy())
    request.on('error', () => reject(new Error('PREVIEW_ENDPOINT_UNAVAILABLE')))
    request.end()
  })
}

async function exchangeLaunch(file, expectedPid, origin) {
  let launch, cookie
  try {
    launch = readLaunch(file, expectedPid, origin)
    const response = await requestHeaders(launch)
    launch = undefined
    if (response.status !== 303 || response.headers.location !== '/') throw new Error('PREVIEW_HANDSHAKE_MISMATCH')
    cookie = parseCookie(response.headers, origin)
    const clean = await requestHeaders(origin, { Cookie: cookie.name + '=' + cookie.value })
    if (clean.status !== 200 || !clean.headers['content-type']?.includes('text/html')) throw new Error('PREVIEW_HTML_UNAVAILABLE')
    return cookie
  } finally { launch = undefined; cookie = undefined }
}

module.exports = { readLaunch, parseCookie, requestHeaders, exchangeLaunch }
