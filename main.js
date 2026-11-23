const { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');

fs.writeFileSync(path.join(__dirname, 'boot.log'), 'Booting main.js at ' + new Date().toISOString() + '\n');

process.on('uncaughtException', err => {
  try { fs.appendFileSync(path.join(__dirname, 'boot.log'), 'Uncaught: ' + (err.stack || err) + '\n'); } catch(e){}
});
process.on('unhandledRejection', err => {
  try { fs.appendFileSync(path.join(__dirname, 'boot.log'), 'Rejection: ' + (err.stack || err) + '\n'); } catch(e){}
});
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const os = require('os');
const net = require('net');
const { spawn, exec, execSync } = require('child_process');
const { URL } = require('url');

const DIR = __dirname;
let BIN_DIR = path.join(DIR, 'bin');

// Windows/Go non-ASCII path protection:
// When the project directory contains Cyrillic/non-ASCII characters,
// sing-box and node runtimes are mirrored to %ProgramData%\WouldApp\bin.
if (/[^\x00-\x7F]/.test(BIN_DIR)) {
  const safeBinDir = path.join(process.env.ProgramData || 'C:\\ProgramData', 'WouldApp', 'bin');
  try {
    fs.mkdirSync(safeBinDir, { recursive: true });
    const binFiles = ['sing-box.exe', 'wintun.dll', 'proxy_helper.exe', 'node.exe'];
    for (const f of binFiles) {
      const src = path.join(path.join(DIR, 'bin'), f);
      const dst = path.join(safeBinDir, f);
      if (fs.existsSync(src)) {
        if (!fs.existsSync(dst) || fs.statSync(src).size !== fs.statSync(dst).size) {
          fs.copyFileSync(src, dst);
        }
      }
    }
    BIN_DIR = safeBinDir;
  } catch (e) {}
}

const SINGBOX_EXE = path.join(BIN_DIR, 'sing-box.exe');
const CONFIG_PATH = path.join(BIN_DIR, 'active-config.json');

let singboxProcess = null;
let processStartTime = null;
let logsBuffer = [];
let activeMode = 'proxy'; // 'tun' or 'proxy'
let isTrafficBlocked = false; // true if Kill Switch triggered (§1)

// Persistent settings (API_CONTRACT §6)
let serverSettings = {
  dns: 'google',
  mode: 'proxy',
  killSwitch: false,
  autoConnect: false,
  autoStart: false,
  sound: true,
  minimizeToTray: true
};

let lastTrafficDown = 0;
let lastTrafficUp = 0;

async function fetchSingboxTraffic() {
  if (!singboxProcess) return { downBytes: 0, upBytes: 0, connections: 0 };
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port: 9090, path: '/traffic', timeout: 1500 }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; req.destroy(); });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data.trim().split('\n').pop());
          lastTrafficDown += parsed.down || 0;
          lastTrafficUp += parsed.up || 0;
          resolve({ downBytes: lastTrafficDown, upBytes: lastTrafficUp, connections: 0 });
        } catch (e) {
          resolve({ downBytes: lastTrafficDown, upBytes: lastTrafficUp, connections: 0 });
        }
      });
    });
    req.on('error', () => resolve({ downBytes: lastTrafficDown, upBytes: lastTrafficUp, connections: 0 }));
    req.on('timeout', () => { req.destroy(); resolve({ downBytes: lastTrafficDown, upBytes: lastTrafficUp, connections: 0 }); });
  });
}

function safeDecodeURIComponent(str) {
  if (!str) return '';
  try {
    return decodeURIComponent(str);
  } catch (e) {
    return str;
  }
}

function tcpPing(host, port, timeoutMs = 2000) {
  return new Promise((resolve) => {
    if (!host) return resolve(null);
    const start = Date.now();
    let resolved = false;
    let socket;
    const finish = (val) => {
      if (!resolved) {
        resolved = true;
        if (socket) {
          try { socket.destroy(); } catch (e) {}
        }
        resolve(val);
      }
    };
    try {
      socket = net.connect({ host, port: parseInt(port, 10) || 443 });
      socket.setTimeout(timeoutMs);
      socket.on('connect', () => finish(Date.now() - start));
      socket.on('error', () => finish(null));
      socket.on('timeout', () => finish(null));
    } catch (e) {
      finish(null);
    }
  });
}

function applyAutoStart(enabled) {
  try {
    app.setLoginItemSettings({
      openAtLogin: !!enabled,
      path: process.execPath
    });
  } catch (e) {}
}

const SETTINGS_PATH = path.join(DIR, 'settings.json');
function loadSettingsFromDisk() {
  try {
    if (fs.existsSync(SETTINGS_PATH)) {
      const data = JSON.parse(fs.readFileSync(SETTINGS_PATH, 'utf8'));
      Object.assign(serverSettings, data);
    }
  } catch (e) {}
  try {
    const loginSettings = app.getLoginItemSettings();
    serverSettings.autoStart = loginSettings.openAtLogin;
  } catch (e) {}
  if (serverSettings.mode) activeMode = serverSettings.mode;
}

function saveSettingsToDisk() {
  try {
    fs.writeFileSync(SETTINGS_PATH, JSON.stringify(serverSettings, null, 2), 'utf8');
  } catch (e) {}
}

function addLog(msg) {
  const line = `[${new Date().toTimeString().split(' ')[0]}] ${msg}`;
  logsBuffer.push(line);
  if (logsBuffer.length > 100) logsBuffer.shift();
  console.log(line);
}

const PROXY_HELPER_EXE = path.join(BIN_DIR, 'proxy_helper.exe');
const PROXY_BACKUP_FILE = path.join(BIN_DIR, 'proxy-backup.json');

function getSystemProxyState() {
  try {
    const out = execSync('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'ignore'],
      windowsHide: true
    });
    const parseVal = (name) => {
      const match = out.match(new RegExp(`${name}\\s+REG_[A-Z]+\\s+(.*)`));
      return match ? match[1].trim() : null;
    };
    const rawEnable = parseVal('ProxyEnable');
    return {
      ProxyEnable: rawEnable !== null ? (parseInt(rawEnable, 16) || parseInt(rawEnable, 10) || 0) : 0,
      ProxyServer: parseVal('ProxyServer') || '',
      ProxyOverride: parseVal('ProxyOverride') || '',
      AutoConfigURL: parseVal('AutoConfigURL') || ''
    };
  } catch (e) {
    return null;
  }
}

function restoreProxyStateSync(backup) {
  if (!backup) return;
  try {
    if (backup.ProxyEnable === 0) {
      if (fs.existsSync(PROXY_HELPER_EXE)) {
        execSync(`"${PROXY_HELPER_EXE}" disable`, { stdio: 'ignore', windowsHide: true });
      } else {
        execSync('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f', { stdio: 'ignore', windowsHide: true });
      }
    } else {
      execSync(`reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d ${backup.ProxyEnable} /f`, { stdio: 'ignore', windowsHide: true });
      if (backup.ProxyServer) {
        execSync(`reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyServer /t REG_SZ /d "${backup.ProxyServer}" /f`, { stdio: 'ignore', windowsHide: true });
      }
      if (backup.ProxyOverride) {
        execSync(`reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyOverride /t REG_SZ /d "${backup.ProxyOverride}" /f`, { stdio: 'ignore', windowsHide: true });
      }
      if (fs.existsSync(PROXY_HELPER_EXE)) {
        const port = (backup.ProxyServer && backup.ProxyServer.includes(':')) ? backup.ProxyServer.split(':').pop() : '2080';
        execSync(`"${PROXY_HELPER_EXE}" enable ${port}`, { stdio: 'ignore', windowsHide: true });
      }
    }
  } catch (e) {}
}

function restoreProxyOnStartup() {
  if (fs.existsSync(PROXY_BACKUP_FILE)) {
    try {
      const backup = JSON.parse(fs.readFileSync(PROXY_BACKUP_FILE, 'utf8'));
      restoreProxyStateSync(backup);
      fs.unlinkSync(PROXY_BACKUP_FILE);
      addLog('[proxy] Восстановлены исходные параметры прокси из бэкапа.');
    } catch (e) {}
  } else {
    const current = getSystemProxyState();
    if (current && (current.ProxyEnable === 1 || current.ProxyServer || current.AutoConfigURL)) {
      try {
        fs.writeFileSync(PROXY_BACKUP_FILE, JSON.stringify(current, null, 2), 'utf8');
      } catch (e) {}
    }
  }
}

function enableWindowsProxy(port = 2080, cb) {
  if (!fs.existsSync(PROXY_BACKUP_FILE)) {
    const current = getSystemProxyState();
    if (current) {
      try {
        fs.writeFileSync(PROXY_BACKUP_FILE, JSON.stringify(current, null, 2), 'utf8');
      } catch (e) {}
    }
  }
  const helper = path.join(BIN_DIR, 'proxy_helper.exe');
  if (fs.existsSync(helper)) {
    exec(`"${helper}" enable ${port}`, { windowsHide: true }, (err) => {
      addLog(`Системный прокси Windows переключен на 127.0.0.1:${port} через helper.`);
      cb && cb();
    });
  } else {
    exec(`reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f && reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyServer /t REG_SZ /d "127.0.0.1:${port}" /f`, { windowsHide: true }, () => {
      addLog(`Системный прокси Windows включен на 127.0.0.1:${port}.`);
      cb && cb();
    });
  }
}

function disableWindowsProxy(cb) {
  let backup = null;
  if (fs.existsSync(PROXY_BACKUP_FILE)) {
    try {
      backup = JSON.parse(fs.readFileSync(PROXY_BACKUP_FILE, 'utf8'));
      fs.unlinkSync(PROXY_BACKUP_FILE);
    } catch (e) {}
  }
  if (backup) {
    restoreProxyStateSync(backup);
    addLog(`Параметры прокси восстановлены из бэкапа.`);
    cb && cb();
    return;
  }
  const helper = path.join(BIN_DIR, 'proxy_helper.exe');
  if (fs.existsSync(helper)) {
    exec(`"${helper}" disable`, { windowsHide: true }, () => {
      addLog(`Системный прокси Windows отключен через helper.`);
      cb && cb();
    });
  } else {
    exec('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f', { windowsHide: true }, () => {
      addLog('Системный прокси Windows отключен.');
      cb && cb();
    });
  }
}

function fetchSubscription(urlStr) {
  return new Promise((resolve, reject) => {
    try {
      const parsedUrl = new URL(urlStr);
      const isHttps = parsedUrl.protocol === 'https:';
      const client = isHttps ? https : http;

      let hwid = '';
      try {
        const out = execSync('reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid', {
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'ignore'],
          windowsHide: true
        });
        const m = out.match(/MachineGuid\s+REG_SZ\s+([a-zA-Z0-9\-]+)/i);
        if (m && m[1]) {
          hwid = crypto.createHash('md5').update(m[1].trim()).digest('hex');
        }
      } catch (e) {}
      if (!hwid) {
        hwid = crypto.createHash('md5').update(os.hostname() + '-' + os.userInfo().username).digest('hex');
      }

      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'GET',
        headers: {
          'User-Agent': 'WouldApp/2.0.0 (Windows NT 10.0; Win64; x64) sing-box/1.14',
          'Accept': '*/*',
          'x-hwid': hwid,
          'x-device-id': hwid
        },
        timeout: 12000
      };

      const req = client.request(options, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          const redirectUrl = new URL(res.headers.location, urlStr).toString();
          return fetchSubscription(redirectUrl).then(resolve).catch(reject);
        }
        if (res.statusCode !== 200) {
          let errBody = '';
          res.on('data', c => errBody += c);
          res.on('end', () => {
            const low = errBody.toLowerCase();
            if (res.statusCode === 403 || low.includes('device limit') || low.includes('limit reached')) {
              reject(new Error(`Ошибка подписки: Превышен лимит подключенных устройств (код ${res.statusCode}). Сбросьте привязку устройств у провайдера.`));
            } else {
              reject(new Error(`Сервер подписки вернул статус ${res.statusCode}: ${res.statusMessage || ''}`));
            }
          });
          return;
        }

        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve(data));
      });

      req.on('error', err => reject(new Error(`Ошибка подключения к подписке: ${err.message}`)));
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Превышен таймаут загрузки подписки (12 сек)'));
      });
      req.end();
    } catch (e) {
      reject(e);
    }
  });
}

function tryDecodeBase64(str) {
  let s = str.trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  try {
    const decoded = Buffer.from(s, 'base64').toString('utf8');
    if (decoded.includes('://') || decoded.includes('proxies:') || decoded.includes('"outbounds"')) {
      return decoded;
    }
  } catch (e) {}
  return null;
}

function parseVlessUrl(link) {
  try {
    let raw = link.trim();
    const match = raw.match(/(vless|trojan|ss|hysteria2|hy2):\/\/[^\s"'<>]+/i);
    if (!match) return null;
    raw = match[0];

    const hashParts = raw.split('#');
    const name = hashParts[1] ? safeDecodeURIComponent(hashParts[1]) : 'Пользовательский узел';
    const mainUri = hashParts[0];

    if (raw.toLowerCase().startsWith('ss://')) {
      try {
        const withoutProto = mainUri.substring(5);
        if (withoutProto.includes('@')) {
          const atParts = withoutProto.split('@');
          let creds = atParts[0];
          try {
            creds = Buffer.from(creds.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
          } catch(e) {}
          const [method, password] = creds.split(':');
          const [host, portStr] = atParts[1].split(':');
          return {
            name,
            outbound: {
              type: 'shadowsocks',
              tag: 'proxy',
              server: host,
              server_port: parseInt(portStr, 10) || 8388,
              method: method || 'aes-256-gcm',
              password: password || ''
            },
            rawLink: raw
          };
        } else {
          let decoded = Buffer.from(withoutProto.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
          const [creds, hostPort] = decoded.split('@');
          const [method, password] = creds.split(':');
          const [host, portStr] = hostPort.split(':');
          return {
            name,
            outbound: {
              type: 'shadowsocks',
              tag: 'proxy',
              server: host,
              server_port: parseInt(portStr, 10) || 8388,
              method: method || 'aes-256-gcm',
              password: password || ''
            },
            rawLink: raw
          };
        }
      } catch (err) {
        return null;
      }
    }

    const parsed = new URL(mainUri);
    let type = parsed.protocol.replace(':', '').toLowerCase();
    if (type === 'hy2') type = 'hysteria2';
    const uuid = safeDecodeURIComponent(parsed.username || '');
    const server = parsed.hostname;
    const port = parseInt(parsed.port, 10) || 443;
    const params = Object.fromEntries(parsed.searchParams.entries());

    let outbound;

    if (type === 'hysteria2') {
      outbound = {
        type: 'hysteria2',
        tag: 'proxy',
        server: server,
        server_port: port,
        password: uuid,
        tls: {
          enabled: true,
          server_name: params.sni || server,
          insecure: params.insecure === '1' || params.allowInsecure === '1'
        }
      };
      if (params.obfs && params.obfs !== 'none') {
        outbound.obfs = {
          type: params.obfs,
          password: params['obfs-password'] || ''
        };
      }
    } else if (type === 'trojan') {
      outbound = {
        type: 'trojan',
        tag: 'proxy',
        server: server,
        server_port: port,
        password: uuid
      };
      if (params.security === 'tls' || params.security === 'reality' || port === 443 || params.sni) {
        outbound.tls = {
          enabled: true,
          server_name: params.sni || server,
          utls: {
            enabled: true,
            fingerprint: params.fp || 'chrome'
          }
        };
      }
    } else {
      outbound = {
        type: 'vless',
        tag: 'proxy',
        server: server,
        server_port: port,
        uuid: uuid
      };
      if (params.flow) outbound.flow = params.flow;
      if (params.security === 'reality') {
        outbound.tls = {
          enabled: true,
          server_name: params.sni || server,
          reality: {
            enabled: true,
            public_key: params.pbk || '',
            short_id: params.sid || ''
          },
          utls: {
            enabled: true,
            fingerprint: params.fp || 'chrome'
          }
        };
      } else if (params.security === 'tls' || port === 443 || params.sni) {
        outbound.tls = {
          enabled: true,
          server_name: params.sni || server,
          utls: {
            enabled: true,
            fingerprint: params.fp || 'chrome'
          }
        };
      }
    }

    const netType = (params.type || '').toLowerCase();
    if (netType === 'ws') {
      outbound.transport = {
        type: 'ws',
        path: params.path ? safeDecodeURIComponent(params.path) : '/',
        headers: params.host ? { Host: safeDecodeURIComponent(params.host) } : undefined
      };
    } else if (netType === 'grpc') {
      outbound.transport = {
        type: 'grpc',
        service_name: params.serviceName ? safeDecodeURIComponent(params.serviceName) : ''
      };
    } else if (netType === 'httpupgrade') {
      outbound.transport = {
        type: 'httpupgrade',
        path: params.path ? safeDecodeURIComponent(params.path) : '/',
        host: params.host ? safeDecodeURIComponent(params.host) : undefined
      };
    }

    return { name, outbound, rawLink: raw };
  } catch (e) {
    return null;
  }
}

async function parseAnyInput(input) {
  if (!input) return [];
  let raw = input.trim();

  if (raw.startsWith('http://') || raw.startsWith('https://')) {
    addLog(`Загрузка подписки по URL: ${raw}`);
    raw = await fetchSubscription(raw);
  }

  if (!raw.includes('vless://') && !raw.includes('trojan://') && !raw.includes('ss://') && !raw.includes('hysteria2://')) {
    const decoded = tryDecodeBase64(raw);
    if (decoded) raw = decoded;
  }

  const nodes = [];
  const linkRegex = /(?:vless|trojan|ss|hysteria2|hy2):\/\/[^\s"'<>]+/gi;
  const matches = raw.match(linkRegex);

  if (matches && matches.length > 0) {
    for (const link of matches) {
      const item = parseVlessUrl(link);
      if (item) nodes.push(item);
    }
  }

  if (nodes.length === 0) {
    const lines = raw.split(/[\r\n]+/).map(l => l.trim()).filter(Boolean);
    for (const line of lines) {
      const item = parseVlessUrl(line);
      if (item) nodes.push(item);
    }
  }

  return nodes;
}

function checkIpDirect() {
  return new Promise((resolve) => {
    const options = {
      hostname: 'api.ipify.org',
      port: 443,
      path: '/?format=json',
      method: 'GET',
      timeout: 3500
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          resolve({ success: true, ip: parsed.ip, country: 'Определен', proxied: (activeMode !== 'disconnected') });
        } catch (e) {
          resolve({ success: false, ip: '127.0.0.1', country: 'Не определен' });
        }
      });
    });
    req.on('error', () => resolve({ success: false, ip: '127.0.0.1', country: 'Не определен' }));
    req.on('timeout', () => { req.destroy(); resolve({ success: false, ip: '127.0.0.1', country: 'Не определен' }); });
    req.end();
  });
}

function buildSingBoxConfig(outbound, requestedMode = 'proxy', dnsChoice = 'google') {
  const isTun = requestedMode === 'tun';

  const dnsServers = {
    google: { address: 'https://dns.google/dns-query', address_resolver: 'default-dns', detour: 'direct' },
    cloudflare: { address: 'https://1.1.1.1/dns-query', address_resolver: 'default-dns', detour: 'direct' },
    adguard: { address: 'https://dns.adguard-dns.com/dns-query', address_resolver: 'default-dns', detour: 'direct' }
  };
  const selectedDns = dnsServers[dnsChoice] || dnsServers.google;

  const inbounds = [
    {
      type: 'mixed',
      tag: 'mixed-in',
      listen: '127.0.0.1',
      listen_port: 2080
    }
  ];

  if (isTun) {
    inbounds.push({
      type: 'tun',
      tag: 'tun-in',
      interface_name: 'WouldApp-TUN',
      inet4_address: '172.19.0.1/30',
      auto_route: true,
      strict_route: true,
      stack: 'system',
      sniff: true
    });
  }

  const outbounds = [
    { ...outbound, tag: 'proxy' },
    { type: 'direct', tag: 'direct' },
    { type: 'block', tag: 'block' }
  ];

  return {
    log: { level: 'info', timestamp: true },
    experimental: {
      clash_api: {
        external_controller: '127.0.0.1:9090',
        external_ui: ''
      }
    },
    dns: {
      servers: [
        { tag: 'remote-dns', ...selectedDns },
        { tag: 'default-dns', address: '8.8.8.8', detour: 'direct' }
      ]
    },
    inbounds,
    outbounds,
    route: {
      rules: [
        { protocol: 'dns', outbound: 'direct' },
        { ip_is_private: true, outbound: 'direct' }
      ],
      auto_detect_interface: true
    }
  };
}

function killOrphanSingbox() {
  try {
    execSync('taskkill /F /IM sing-box.exe', { stdio: 'ignore', windowsHide: true });
  } catch (e) {}
}

function waitForPort(port = 2080, timeoutMs = 3500) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const tryConnect = () => {
      const sock = new net.Socket();
      sock.setTimeout(300);
      sock.on('connect', () => {
        sock.destroy();
        resolve(true);
      });
      sock.on('error', () => {
        sock.destroy();
        if (Date.now() - start > timeoutMs) {
          reject(new Error(`Таймаут открытия порта ${port}`));
        } else {
          setTimeout(tryConnect, 200);
        }
      });
      sock.on('timeout', () => {
        sock.destroy();
        if (Date.now() - start > timeoutMs) {
          reject(new Error(`Таймаут открытия порта ${port}`));
        } else {
          setTimeout(tryConnect, 200);
        }
      });
      sock.connect(port, '127.0.0.1');
    };
    tryConnect();
  });
}

let isTransitioning = false;

function stopSingBox(cb) {
  isTrafficBlocked = false;
  const p = (async () => {
    if (singboxProcess) {
      addLog(`Остановка процесса sing-box (PID: ${singboxProcess.pid})...`);
      try {
        process.kill(singboxProcess.pid);
      } catch (e) {}
      singboxProcess = null;
      processStartTime = null;
    }
    killOrphanSingbox();
    await new Promise(r => disableWindowsProxy(r));
    try {
      if (fs.existsSync(CONFIG_PATH)) fs.unlinkSync(CONFIG_PATH);
    } catch (e) {}
    addLog('Соединение разорвано. Системный прокси сброшен.');
  })();
  p.then(() => cb && cb()).catch(() => cb && cb());
  return p;
}

function startSingBox(outbound, requestedMode, cb) {
  isTrafficBlocked = false;
  const p = new Promise(async (resolve, reject) => {
    try {
      await stopSingBox();

      const tryTun = (requestedMode === 'tun');
      if (tryTun) {
        let isAdmin = false;
        try {
          execSync('net session', { stdio: 'ignore', windowsHide: true });
          isAdmin = true;
        } catch (e) {}
        if (!isAdmin) {
          const err = new Error('Режим TUN требует запуска от имени администратора!');
          err.code = 'tun_requires_admin';
          return reject(err);
        }
      }

      const config = buildSingBoxConfig(outbound, requestedMode, serverSettings.dns);
      fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');

      addLog(`Запуск sing-box (режим: ${tryTun ? 'TUN (Wintun)' : 'Системный прокси'})...`);

      const proc = spawn(SINGBOX_EXE, ['run', '-c', CONFIG_PATH], {
        cwd: BIN_DIR,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let isReady = false;
      let errorOutput = '';

      proc.stdout.on('data', d => {
        const str = d.toString();
        addLog(`[sing-box] ${str.trim()}`);
      });

      proc.stderr.on('data', d => {
        const str = d.toString();
        errorOutput += str;
        addLog(`[sing-box err] ${str.trim()}`);
      });

      proc.on('exit', (code) => {
        addLog(`sing-box завершил работу (код ${code}).`);
        if (singboxProcess === proc) {
          singboxProcess = null;
          processStartTime = null;
          if (serverSettings.killSwitch && isReady) {
            isTrafficBlocked = true;
            addLog('[kill-switch] Туннель прерван! Kill Switch активирован.');
          } else {
            disableWindowsProxy();
          }
        }
        if (!isReady) {
          reject(new Error(errorOutput.trim() || `sing-box завершился с кодом ${code}`));
        }
      });

      await waitForPort(2080, 4000);

      isReady = true;
      singboxProcess = proc;
      processStartTime = Date.now();
      activeMode = requestedMode;

      if (!tryTun) {
        await new Promise(r => enableWindowsProxy(2080, r));
      }

      addLog(`Успешное подключение к узлу: ${outbound.server}`);
      resolve({ running: true, mode: activeMode, pid: proc.pid });
    } catch (err) {
      addLog(`Ошибка запуска sing-box: ${err.message}`);
      await stopSingBox();
      reject(err);
    }
  });

  if (cb) {
    p.then(res => cb(null, res)).catch(err => cb(err));
  }
  return p;
}

// ==============================================================
// ELECTRON APPLICATION LIFECYCLE & WINDOW MANAGEMENT
// ==============================================================

let mainWindow = null;
let tray = null;
let isQuitting = false;

fs.appendFileSync(path.join(__dirname, 'boot.log'), 'Checking single instance lock...\n');
const gotTheLock = app.requestSingleInstanceLock();
fs.appendFileSync(path.join(__dirname, 'boot.log'), 'gotTheLock: ' + gotTheLock + '\n');
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      if (!mainWindow.isVisible()) mainWindow.show();
      mainWindow.focus();
    }
  });

  app.whenReady().then(() => {
    fs.appendFileSync(path.join(__dirname, 'boot.log'), 'app.whenReady reached\n');
    loadSettingsFromDisk();
    restoreProxyOnStartup();
    createWindow();
    createTray();
    setupIpcHandlers();
    fs.appendFileSync(path.join(__dirname, 'boot.log'), 'createWindow & Tray initialized\n');
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1120,
    height: 780,
    minWidth: 900,
    minHeight: 650,
    frame: false,
    show: false,
    backgroundColor: '#0b0f19',
    icon: path.join(DIR, 'app.ico'),
    webPreferences: {
      preload: path.join(DIR, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.loadFile('index.html');

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('close', (e) => {
    if (!isQuitting && serverSettings.minimizeToTray !== false) {
      e.preventDefault();
      mainWindow.hide();
    }
  });
}

function createTray() {
  try {
    const iconPath = path.join(DIR, 'app.ico');
    const trayImg = nativeImage.createFromPath(fs.existsSync(iconPath) ? iconPath : path.join(DIR, 'app_icon.png'));
    tray = new Tray(trayImg);
    tray.setToolTip('WouldApp VPN');

    const contextMenu = Menu.buildFromTemplate([
      {
        label: 'Открыть WouldApp',
        click: () => {
          if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
          }
        }
      },
      { type: 'separator' },
      {
        label: 'Отключить VPN',
        click: async () => {
          await stopSingBox();
        }
      },
      { type: 'separator' },
      {
        label: 'Выход',
        click: () => {
          isQuitting = true;
          app.quit();
        }
      }
    ]);

    tray.setContextMenu(contextMenu);
    tray.on('double-click', () => {
      if (mainWindow) {
        mainWindow.show();
        mainWindow.focus();
      }
    });
  } catch (err) {
    console.error('Tray creation skipped/failed:', err.message);
  }
}

function setupIpcHandlers() {
  ipcMain.handle('get-status', async () => {
    const isRunning = !!singboxProcess;
    let uptimeSeconds = 0;
    if (isRunning && processStartTime) {
      uptimeSeconds = Math.floor((Date.now() - processStartTime) / 1000);
    }
    const traffic = await fetchSingboxTraffic();
    return {
      running: isRunning,
      mode: activeMode,
      uptimeSeconds,
      killSwitch: serverSettings.killSwitch,
      blocked: isTrafficBlocked,
      settings: { ...serverSettings },
      traffic: { downBytes: traffic.downBytes, upBytes: traffic.upBytes },
      logs: logsBuffer.slice(-30)
    };
  });

  ipcMain.handle('connect', async (event, payload) => {
    if (isTransitioning) {
      return { success: false, error: 'Операция уже выполняется, подождите...' };
    }
    isTransitioning = true;
    try {
      let outbound = payload.outbound;
      if (payload.killSwitch !== undefined) {
        serverSettings.killSwitch = !!payload.killSwitch;
      }
      if (!outbound && payload.link) {
        const parsed = parseVlessUrl(payload.link);
        if (parsed) outbound = parsed.outbound;
      }
      if (!outbound || !outbound.server || !outbound.type) {
        isTransitioning = false;
        return { success: false, error: 'Некорректные параметры узла', code: 'invalid_outbound' };
      }
      const result = await startSingBox(outbound, payload.mode || 'proxy');
      isTransitioning = false;
      return { success: true, result };
    } catch (err) {
      isTransitioning = false;
      return { success: false, error: err.message, code: err.code };
    }
  });

  ipcMain.handle('disconnect', async () => {
    isTransitioning = true;
    await stopSingBox();
    isTransitioning = false;
    return { success: true, disconnected: true };
  });

  ipcMain.handle('parse', async (event, payload) => {
    try {
      const link = payload.link || payload.raw || payload.text || '';
      const nodes = await parseAnyInput(link);
      if (nodes && nodes.length > 0) {
        return {
          success: true,
          count: nodes.length,
          data: nodes[0],
          nodes: nodes
        };
      }
      return { success: false, error: 'Не удалось распознать ключи или подписку' };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle('ping', async (event, payload) => {
    try {
      const servers = payload.servers;
      if (!Array.isArray(servers)) {
        return { success: false, error: 'servers must be an array' };
      }
      const results = await Promise.all(servers.map(async (s) => {
        const ping = await tcpPing(s.server, s.port || 443);
        return { id: s.id, ping };
      }));
      return { success: true, results };
    } catch (e) {
      return { success: false, error: e.message };
    }
  });

  ipcMain.handle('check-ip', async () => {
    return await checkIpDirect();
  });

  ipcMain.handle('get-settings', async () => {
    return { success: true, settings: { ...serverSettings } };
  });

  ipcMain.handle('save-settings', async (event, partial) => {
    try {
      const allowed = ['dns', 'mode', 'killSwitch', 'autoConnect', 'autoStart', 'sound', 'minimizeToTray'];
      for (const key of allowed) {
        if (key in partial) serverSettings[key] = partial[key];
      }
      if ('mode' in partial) activeMode = partial.mode;
      if ('autoStart' in partial) applyAutoStart(partial.autoStart);
      saveSettingsToDisk();
      return { success: true, settings: { ...serverSettings } };
    } catch (e) {
      return { success: false, error: e.message };
    }
  });

  ipcMain.handle('window-minimize', () => {
    if (mainWindow) mainWindow.minimize();
  });

  ipcMain.handle('window-close', () => {
    if (mainWindow) {
      if (serverSettings.minimizeToTray !== false) {
        mainWindow.hide();
      } else {
        isQuitting = true;
        app.quit();
      }
    }
  });
}

app.on('before-quit', async (e) => {
  if (!isQuitting) {
    isQuitting = true;
  }
  try {
    if (singboxProcess) {
      process.kill(singboxProcess.pid);
    }
    killOrphanSingbox();
    const backup = fs.existsSync(PROXY_BACKUP_FILE) ? JSON.parse(fs.readFileSync(PROXY_BACKUP_FILE, 'utf8')) : null;
    restoreProxyStateSync(backup);
  } catch (err) {}
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    if (serverSettings.minimizeToTray === false) {
      app.quit();
    }
  }
});
