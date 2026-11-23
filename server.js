const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const net = require('net');
const { spawn, exec, execSync } = require('child_process');
const { URL } = require('url');

const PORT = 3005;
const DIR = __dirname;
let BIN_DIR = path.join(DIR, 'bin');

// Windows/Go non-ASCII path protection:
// When the project directory contains Cyrillic/non-ASCII characters (e.g. C:\Users\Ярослав\...),
// sing-box (Go runtime / lazy DLL loader) crashes with "A dynamic link library (DLL) initialization routine failed".
// Moving runtime binaries to %ProgramData%\WouldApp\bin guarantees a 100% pure ASCII path on any Windows system.
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
  } catch (e) {
    // fallback to original BIN_DIR
  }
}

const SINGBOX_EXE = path.join(BIN_DIR, 'sing-box.exe');
const CONFIG_PATH = path.join(BIN_DIR, 'active-config.json');

// Session token for API authentication (API_CONTRACT §0)
const SESSION_TOKEN = crypto.randomBytes(24).toString('hex');

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
  sound: true
};

// Traffic tracking for /api/traffic (API_CONTRACT §2)
let lastTrafficDown = 0;
let lastTrafficUp = 0;

// Fetch real traffic from sing-box Clash API (localhost:9090)
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

// Real TCP ping to a server (API_CONTRACT §6)
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

// AutoStart: manage HKCU\Run registry entry
function applyAutoStart(enabled) {
  try {
    if (enabled) {
      const appPath = path.join(DIR, 'WouldApp.exe');
      const target = fs.existsSync(appPath) ? appPath : path.join(DIR, 'Запустить WouldApp.bat');
      execSync(`reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v WouldApp /t REG_SZ /d "\\"${target}\\"" /f`, { stdio: 'ignore', windowsHide: true });
    } else {
      execSync(`reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v WouldApp /f`, { stdio: 'ignore', windowsHide: true });
    }
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
    const out = execSync('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v WouldApp', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'ignore'],
      windowsHide: true
    });
    serverSettings.autoStart = out.includes('WouldApp');
  } catch (e) {
    serverSettings.autoStart = false;
  }
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

// Read current registry settings for Internet Settings
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

// Synchronously restore registry proxy state (used on exit / crash / restore)
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
      // User had an active proxy beforehand: restore it fully
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
  } catch (e) {
    addLog(`[proxy] Ошибка при восстановлении реестра: ${e.message}`);
  }
}

// Restore proxy on startup if left hanging from previous crash
function restoreProxyOnStartup() {
  if (fs.existsSync(PROXY_BACKUP_FILE)) {
    try {
      const backup = JSON.parse(fs.readFileSync(PROXY_BACKUP_FILE, 'utf8'));
      addLog('[proxy] Восстановление настроек прокси из файла аварийного бэкапа...');
      restoreProxyStateSync(backup);
      fs.unlinkSync(PROXY_BACKUP_FILE);
      addLog('[proxy] Настройки прокси успешно восстановлены из бэкапа.');
      return;
    } catch (e) {
      addLog(`[proxy] Ошибка чтения бэкапа: ${e.message}`);
    }
  }

  // Check if system proxy was left pointing to our local port (127.0.0.1:2080)
  const current = getSystemProxyState();
  if (current && current.ProxyEnable === 1 && current.ProxyServer && current.ProxyServer.includes('127.0.0.1:2080')) {
    addLog('[proxy] Обнаружен зависший системный прокси WouldApp (127.0.0.1:2080), сбрасываем...');
    if (fs.existsSync(PROXY_HELPER_EXE)) {
      execSync(`"${PROXY_HELPER_EXE}" disable`, { stdio: 'ignore', windowsHide: true });
    } else {
      execSync('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f', { stdio: 'ignore', windowsHide: true });
    }
    addLog('[proxy] Зависший прокси сброшен, доступ в интернет восстановлен.');
  } else {
    addLog('[proxy] Системный прокси проверен: сторонние настройки сохранены.');
  }
}

// Windows System Proxy Manager (With Backup & WinINet Broadcast Notification)
function enableWindowsProxy(proxyPort = 2080, cb) {
  // 1. Save backup before first modification if not already saved
  if (!fs.existsSync(PROXY_BACKUP_FILE)) {
    const currentState = getSystemProxyState();
    if (currentState) {
      try {
        fs.writeFileSync(PROXY_BACKUP_FILE, JSON.stringify(currentState, null, 2), 'utf8');
      } catch (e) {
        addLog(`[proxy] Предупреждение: не удалось сохранить бэкап прокси: ${e.message}`);
      }
      if (currentState.AutoConfigURL) {
        addLog(`[warning] Обнаружен активный PAC-скрипт (${currentState.AutoConfigURL}). Он может переопределять системный прокси.`);
      }
    }
  }

  // 2. Activate proxy
  if (fs.existsSync(PROXY_HELPER_EXE)) {
    exec(`"${PROXY_HELPER_EXE}" enable ${proxyPort}`, (err) => {
      if (err) addLog(`[proxy] Ошибка: ${err.message}`);
      else addLog(`[proxy] Системный прокси Windows активирован на 127.0.0.1:${proxyPort} (WinINet обновлен)`);
      if (cb) cb();
    });
  } else {
    const cmd = `reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f && reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyServer /t REG_SZ /d "127.0.0.1:${proxyPort}" /f && reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyOverride /t REG_SZ /d "localhost;127.0.0.1;<local>" /f`;
    exec(cmd, () => {
      addLog(`[proxy] Системный прокси Windows активирован на 127.0.0.1:${proxyPort}`);
      if (cb) cb();
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
    addLog(`[proxy] Системный прокси возвращен в исходное состояние.`);
    if (cb) cb();
  } else {
    if (fs.existsSync(PROXY_HELPER_EXE)) {
      exec(`"${PROXY_HELPER_EXE}" disable`, () => {
        addLog(`[proxy] Системный прокси Windows отключен (WinINet сброшен)`);
        if (cb) cb();
      });
    } else {
      const cmd = `reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f`;
      exec(cmd, () => {
        addLog(`[proxy] Системный прокси Windows отключен`);
        if (cb) cb();
      });
    }
  }
}

// Emergency cleanup on crashes / signals
function emergencyProxyCleanup() {
  killOrphanSingBox();
  try {
    if (fs.existsSync(PROXY_BACKUP_FILE)) {
      const backup = JSON.parse(fs.readFileSync(PROXY_BACKUP_FILE, 'utf8'));
      restoreProxyStateSync(backup);
      fs.unlinkSync(PROXY_BACKUP_FILE);
    }
  } catch (e) {}
}

// Universal parser for vless://, trojan://, ss://, hysteria2://
function parseVlessUrl(link) {
  try {
    let raw = link.trim();
    const match = raw.match(/(vless|trojan|ss|hysteria2|hy2):\/\/[^\s"'<>]+/i);
    if (!match) return null;
    raw = match[0];

    const hashParts = raw.split('#');
    const name = hashParts[1] ? safeDecodeURIComponent(hashParts[1]) : 'Пользовательский узел';
    const mainUri = hashParts[0];

    // Handle legacy Shadowsocks: ss://BASE64#name or ss://BASE64@host:port#name
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
      if (params.obfs) {
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
        type: type,
        tag: 'proxy',
        server: server,
        server_port: port,
        uuid: uuid
      };

      if (params.flow) outbound.flow = params.flow;

      if (params.security === 'reality' || params.security === 'tls') {
        outbound.tls = {
          enabled: true,
          server_name: params.sni || server,
          utls: {
            enabled: true,
            fingerprint: params.fp || 'chrome'
          }
        };

        if (params.security === 'reality') {
          outbound.tls.reality = {
            enabled: true,
            public_key: params.pbk || '',
            short_id: params.sid || ''
          };
        }
      }
    }

    // Transport (WebSocket, gRPC, HTTPUpgrade)
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
  } catch (err) {
    return null;
  }
}

// Persistent Machine HWID for device-bound subscriptions (Remnawave, KavkazVPN, Happ)
let machineHwid = null;
function getMachineHwid() {
  if (machineHwid) return machineHwid;
  try {
    const stdout = execSync('reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid', { encoding: 'utf8' });
    const match = stdout.match(/MachineGuid\s+REG_SZ\s+([a-f0-9-]+)/i);
    if (match && match[1]) {
      machineHwid = crypto.createHash('md5').update(match[1].trim()).digest('hex');
      return machineHwid;
    }
  } catch (e) {}
  machineHwid = 'wouldapp-' + crypto.createHash('md5').update(os.hostname() + '-' + os.userInfo().username).digest('hex');
  return machineHwid;
}

function mapJsonOutboundToSingbox(ob, name) {
  try {
    if (!ob) return null;
    const proto = (ob.protocol || ob.type || '').toLowerCase();

    if (proto === 'vless') {
      const vnext = ob.settings?.vnext?.[0];
      const server = vnext?.address || ob.server;
      const port = parseInt(vnext?.port || ob.server_port || 443, 10);
      const user = vnext?.users?.[0];
      const uuid = user?.id || ob.uuid;
      const flow = user?.flow || ob.flow || '';

      // Skip dummy 0.0.0.0 placeholder nodes
      if (!server || server === '0.0.0.0' || server === '127.0.0.1') return null;

      const stream = ob.streamSettings || {};
      const sec = (stream.security || (ob.tls?.enabled ? (ob.tls.reality ? 'reality' : 'tls') : 'none')).toLowerCase();
      const reality = stream.realitySettings || ob.tls?.reality;

      const outbound = {
        type: 'vless',
        tag: 'proxy',
        server: server,
        server_port: port,
        uuid: uuid
      };
      if (flow) outbound.flow = flow;

      if (sec === 'reality' || reality) {
        outbound.tls = {
          enabled: true,
          server_name: reality.serverName || reality.server_name || server,
          utls: {
            enabled: true,
            fingerprint: reality.fingerprint || 'chrome'
          },
          reality: {
            enabled: true,
            public_key: reality.publicKey || reality.public_key || '',
            short_id: reality.shortId || reality.short_id || ''
          }
        };
      } else if (sec === 'tls' || ob.tls?.enabled) {
        const tlsSettings = stream.tlsSettings || ob.tls || {};
        outbound.tls = {
          enabled: true,
          server_name: tlsSettings.serverName || tlsSettings.server_name || server,
          utls: {
            enabled: true,
            fingerprint: tlsSettings.fingerprint || 'chrome'
          }
        };
      }

      if (stream.network === 'ws') {
        const ws = stream.wsSettings || {};
        outbound.transport = {
          type: 'ws',
          path: ws.path || '/',
          headers: ws.headers || (ws.host ? { Host: ws.host } : undefined)
        };
      }

      return {
        name: name || ob.tag || `VLESS Reality (${server})`,
        outbound: outbound,
        rawLink: `vless://${uuid}@${server}:${port}?security=${sec}#${encodeURIComponent(name || ob.tag || 'Узел')}`
      };
    }
  } catch(e) {
    return null;
  }
}

// Fetch subscription from URL (supports HTTP/HTTPS, self-signed/expired certs, redirects, HWID)
function fetchSubscription(urlStr, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) {
      return reject(new Error('Слишком много перенаправлений (redirect loop)'));
    }
    try {
      const hwid = getMachineHwid();
      const isHttps = urlStr.startsWith('https:');
      const client = isHttps ? https : http;
      const options = {
        headers: {
          'User-Agent': 'Happ/3.6.5 (Windows NT 10.0; Win64; x64)',
          'x-hwid': hwid,
          'x-device-id': hwid,
          'Accept': '*/*'
        },
        timeout: 12000
      };

      if (isHttps) {
        options.agent = new https.Agent({ rejectUnauthorized: false });
      }

      const req = client.get(urlStr, options, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          const redirectUrl = new URL(res.headers.location, urlStr).toString();
          return resolve(fetchSubscription(redirectUrl, redirects + 1));
        }

        if (res.statusCode !== 200) {
          return reject(new Error(`Сервер подписки ответил ошибкой HTTP ${res.statusCode}`));
        }

        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => resolve(body));
      });

      req.on('error', err => reject(new Error(`Ошибка подключения к подписке: ${err.message}`)));
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Превышен таймаут загрузки подписки (12 сек)'));
      });
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
    if (decoded.includes('://') || decoded.includes('proxies:') || decoded.includes('"outbounds"') || decoded.includes('{"')) {
      return decoded;
    }
  } catch (e) {}
  return null;
}

// Universal parser for: single link, multiline links, base64 data, JSON configs (Happ/Sing-box), or subscription URL
async function parseAnyInput(input) {
  if (!input) return [];
  let raw = input.trim();

  // If input is an HTTP/HTTPS subscription URL
  if (raw.startsWith('http://') || raw.startsWith('https://')) {
    addLog(`[sub] Загрузка подписки по URL: ${raw}...`);
    raw = await fetchSubscription(raw);
  }

  // Check if content is Base64 encoded
  if (!raw.includes('vless://') && !raw.includes('trojan://') && !raw.includes('ss://') && !raw.includes('hysteria2://') && !raw.startsWith('[') && !raw.startsWith('{')) {
    const decoded = tryDecodeBase64(raw);
    if (decoded) raw = decoded;
  }

  // Check if provider returned device limit message (handle URL-encoded and plain text)
  let readableText = raw;
  try { readableText = decodeURIComponent(raw); } catch(e) {}

  if (readableText.includes('Подписка не рассчитана') || 
      readableText.includes('количества устройств') || 
      readableText.includes('Лимит устройств') || 
      readableText.includes('лишние устройства') ||
      readableText.includes('Приложение не поддерживается')) {
    throw new Error('Подписка KavkazVPN: исчерпан лимит устройств. Перейдите в Telegram-бот KavkazVPN и нажмите «Удалить лишние устройства» (или сбросьте устройства).');
  }

  const nodes = [];

  // 1. Check if response is a JSON config (Happ / Sing-box / Xray array)
  if (raw.startsWith('[') || raw.startsWith('{')) {
    try {
      const parsedJson = JSON.parse(raw);
      const items = Array.isArray(parsedJson) ? parsedJson : [parsedJson];
      for (const item of items) {
        const remarks = item.remarks || item.tag || '';
        if (item.outbounds && Array.isArray(item.outbounds)) {
          for (const ob of item.outbounds) {
            const mapped = mapJsonOutboundToSingbox(ob, remarks);
            if (mapped) nodes.push(mapped);
          }
        }
      }
      if (nodes.length > 0) {
        addLog(`[sub] Распознано ${nodes.length} узлов из JSON-конфигурации`);
        return nodes;
      }
    } catch(e) {}
  }

  // 2. Global regex search for all valid proxy URLs
  const linkRegex = /(?:vless|trojan|ss|hysteria2|hy2):\/\/[^\s"'<>]+/gi;
  const matches = raw.match(linkRegex);

  if (matches && matches.length > 0) {
    for (const link of matches) {
      const item = parseVlessUrl(link);
      if (item && item.outbound?.server !== '0.0.0.0') nodes.push(item);
    }
  }

  // 3. Fallback: line by line
  if (nodes.length === 0) {
    const lines = raw.split(/[\r\n]+/).map(l => l.trim()).filter(Boolean);
    for (const line of lines) {
      const item = parseVlessUrl(line);
      if (item && item.outbound?.server !== '0.0.0.0') nodes.push(item);
    }
  }

  addLog(`[sub] Распознано узлов: ${nodes.length}`);
  return nodes;
}

// Build valid sing-box 1.14 configuration with native DNS & Route
function buildSingBoxConfig(outbound, withTun = false) {
  const inbounds = [
    {
      type: 'mixed',
      tag: 'mixed-in',
      listen: '127.0.0.1',
      listen_port: 2080
    }
  ];

  if (withTun) {
    inbounds.push({
      type: 'tun',
      tag: 'tun-in',
      interface_name: 'wintun',
      address: ['172.19.0.1/30'],
      auto_route: true,
      strict_route: true,
      stack: 'system'
    });
  }

  return {
    log: {
      level: 'info',
      timestamp: true
    },
    experimental: {
      clash_api: {
        external_controller: '127.0.0.1:9090'
      }
    },
    dns: {
      servers: [
        {
          type: 'udp',
          tag: 'remote-dns',
          server: '8.8.8.8',
          detour: 'proxy'
        },
        {
          type: 'local',
          tag: 'local-dns'
        }
      ],
      strategy: 'prefer_ipv4'
    },
    inbounds: inbounds,
    outbounds: [
      outbound,
      {
        type: 'direct',
        tag: 'direct'
      }
    ],
    route: {
      default_domain_resolver: 'local-dns',
      rules: [
        {
          action: 'sniff'
        },
        {
          protocol: 'dns',
          action: 'hijack-dns'
        }
      ],
      auto_detect_interface: true,
      final: 'proxy'
    }
  };
}

// Check Administrator privileges (needed for wintun TUN adapter)
function isRunningAsAdmin() {
  try {
    execSync('fltmc', { stdio: 'ignore', windowsHide: true });
    return true;
  } catch (e) {
    return false;
  }
}

// Kill any orphaned sing-box processes
function killOrphanSingBox() {
  try {
    execSync('taskkill /F /IM sing-box.exe', { stdio: 'ignore', windowsHide: true });
  } catch (e) {}
}

// Kill process and reliably wait for exit without fixed arbitrary delays
function killProcessWait(proc, timeoutMs = 2500) {
  return new Promise((resolve) => {
    if (!proc || proc.killed || proc.exitCode !== null) return resolve();
    let resolved = false;
    const done = () => {
      if (!resolved) {
        resolved = true;
        resolve();
      }
    };

    proc.once('exit', done);

    try {
      proc.kill('SIGTERM');
    } catch (e) {}

    // Fallback force kill if process hangs
    setTimeout(() => {
      if (!resolved) {
        try {
          execSync(`taskkill /F /T /PID ${proc.pid}`, { stdio: 'ignore', windowsHide: true });
        } catch (e) {}
        done();
      }
    }, 800);

    setTimeout(done, timeoutMs);
  });
}

// Wait for sing-box inbound port 2080 to start accepting connections (health-check)
function waitForPort(port = 2080, timeoutMs = 3500) {
  return new Promise((resolve) => {
    const start = Date.now();
    const tryConnect = () => {
      const socket = net.connect({ port, host: '127.0.0.1' });
      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });
      socket.on('error', () => {
        socket.destroy();
        if (Date.now() - start >= timeoutMs) {
          resolve(false);
        } else {
          setTimeout(tryConnect, 80);
        }
      });
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
      const proc = singboxProcess;
      singboxProcess = null;
      processStartTime = null;
      await killProcessWait(proc);
    }
    killOrphanSingBox();
    await new Promise(res => disableWindowsProxy(res));
  })();

  if (typeof cb === 'function') {
    p.then(() => cb()).catch(() => cb());
  }
  return p;
}

function startSingBox(outbound, requestedMode, cb) {
  const p = (async () => {
    const tryTun = requestedMode === 'tun';

    if (tryTun && !isRunningAsAdmin()) {
      const err = new Error('TUN-режим требует прав администратора. Запустите WouldApp от имени администратора или переключитесь на Системный прокси.');
      err.code = 'tun_requires_admin';
      throw err;
    }

    // Stop any existing process and wait for clean termination
    await stopSingBox();

    // Reset traffic counters for new session
    lastTrafficDown = 0;
    lastTrafficUp = 0;

    const configObj = buildSingBoxConfig(outbound, tryTun);
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(configObj, null, 2), 'utf8');

    addLog(`Запуск sing-box (режим: ${tryTun ? 'TUN (Wintun)' : 'Системный прокси'})...`);

    return new Promise((resolve, reject) => {
      let errorOutput = '';
      let isReady = false;

      const proc = spawn(SINGBOX_EXE, ['run', '-c', CONFIG_PATH], {
        cwd: BIN_DIR,
        windowsHide: true
      });

      // Track immediately to eliminate untracked orphan processes
      singboxProcess = proc;

      proc.stdout.on('data', (d) => {
        addLog(`[stdout] ${d.toString().trim()}`);
      });

      proc.stderr.on('data', (d) => {
        const msg = d.toString().trim();
        addLog(`[stderr] ${msg}`);
        errorOutput += msg + '\n';
      });

      proc.on('exit', (code) => {
        if (singboxProcess === proc) {
          singboxProcess = null;
          processStartTime = null;
          if (serverSettings.killSwitch && isReady) {
            isTrafficBlocked = true;
            addLog('[kill-switch] Туннель прерван! Kill Switch активирован, прямой трафик заблокирован.');
          } else {
            disableWindowsProxy();
          }
        }
        if (!isReady) {
          reject(new Error(errorOutput.trim() || `sing-box завершился с кодом ${code}`));
        }
      });

      // Health-check: wait for 127.0.0.1:2080 to become ready
      waitForPort(2080, 3500).then((portOpen) => {
        if (portOpen && singboxProcess === proc) {
          isReady = true;
          processStartTime = Date.now();
          activeMode = tryTun ? 'tun' : 'proxy';

          if (!tryTun) {
            enableWindowsProxy(2080);
          }

          resolve({ running: true, pid: proc.pid, mode: activeMode });
        } else if (!isReady) {
          stopSingBox().catch(() => {});
          reject(new Error(errorOutput.trim() || 'Таймаут: sing-box не открыл порт 2080'));
        }
      });
    });
  })();

  if (typeof cb === 'function') {
    p.then(res => cb(null, res)).catch(err => cb(err));
  }
  return p;
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.ttf': 'font/ttf',
  '.webp': 'image/webp'
};

const server = http.createServer((req, res) => {
  const urlParsed = req.url.split('?')[0];

  // 1. Host header validation (DNS-rebinding protection)
  const host = (req.headers['host'] || '').toLowerCase();
  const allowedHosts = [`127.0.0.1:${PORT}`, `localhost:${PORT}`, `127.0.0.1`, `localhost`, `[::1]:${PORT}`];
  if (host && !allowedHosts.includes(host)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('403 Forbidden: Invalid Host');
  }

  // 2. Origin validation (CSRF protection)
  const origin = req.headers['origin'];
  if (origin) {
    const allowedOrigins = [`http://127.0.0.1:${PORT}`, `http://localhost:${PORT}`, `http://[::1]:${PORT}`];
    if (!allowedOrigins.includes(origin)) {
      res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('403 Forbidden: Invalid Origin');
    }
  }

  // 3. Token authentication for all /api/* routes (API_CONTRACT §0)
  if (urlParsed.startsWith('/api/')) {
    const clientToken = req.headers['x-wouldapp-token'];
    if (!clientToken || clientToken !== SESSION_TOKEN) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ success: false, error: 'unauthorized' }));
    }
    // POST requests require Content-Type: application/json (API_CONTRACT §0)
    if (req.method === 'POST') {
      const cType = (req.headers['content-type'] || '').toLowerCase();
      if (!cType.includes('application/json')) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ success: false, error: 'Content-Type must be application/json' }));
      }
    }
  }

  // API: Get Status (API_CONTRACT §1)
  if (req.method === 'GET' && urlParsed === '/api/status') {
    const running = !!singboxProcess;
    const uptimeSeconds = processStartTime ? Math.floor((Date.now() - processStartTime) / 1000) : 0;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      success: true,
      running,
      mode: activeMode,
      uptimeSeconds,
      killSwitch: serverSettings.killSwitch,
      blocked: isTrafficBlocked,
      settings: { ...serverSettings },
      traffic: { downBytes: lastTrafficDown, upBytes: lastTrafficUp },
      logs: logsBuffer.slice(-30)
    }));
  }

  // API: Get Traffic (API_CONTRACT §2)
  if (req.method === 'GET' && urlParsed === '/api/traffic') {
    fetchSingboxTraffic().then((traffic) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, ...traffic }));
    });
    return;
  }

  // API: Ping servers (API_CONTRACT §6)
  if (req.method === 'POST' && urlParsed === '/api/ping') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { servers } = JSON.parse(body);
        if (!Array.isArray(servers)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'servers must be an array' }));
        }
        const results = await Promise.all(servers.map(async (s) => {
          const ping = await tcpPing(s.server, s.port || 443);
          return { id: s.id, ping };
        }));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, results }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: e.message }));
      }
    });
    return;
  }

  // API: Get/Set Settings (API_CONTRACT §6)
  if (urlParsed === '/api/settings') {
    if (req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ success: true, settings: { ...serverSettings } }));
    }
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const partial = JSON.parse(body);
          const allowed = ['dns', 'mode', 'killSwitch', 'autoConnect', 'autoStart', 'sound'];
          for (const key of allowed) {
            if (key in partial) serverSettings[key] = partial[key];
          }
          if ('mode' in partial) activeMode = partial.mode;
          if ('autoStart' in partial) applyAutoStart(partial.autoStart);
          saveSettingsToDisk();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, settings: { ...serverSettings } }));
        } catch (e) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: e.message }));
        }
      });
      return;
    }
  }

  // API: Check Public IP & Geolocation
  if (req.method === 'GET' && urlParsed === '/api/check-ip') {
    const isRunning = !!singboxProcess;
    const reqOpts = isRunning
      ? { host: '127.0.0.1', port: 2080, path: 'http://ip-api.com/json', headers: { Host: 'ip-api.com' }, timeout: 6000 }
      : { host: 'ip-api.com', path: '/json', timeout: 5000 };

    const ipReq = http.get(reqOpts, (ipRes) => {
      let data = '';
      ipRes.on('data', chunk => data += chunk);
      ipRes.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            success: true,
            ip: parsed.query || '127.0.0.1',
            country: parsed.country || 'Неизвестно',
            countryCode: (parsed.countryCode || 'UN').toLowerCase(),
            city: parsed.city || '',
            isp: parsed.isp || '',
            proxied: isRunning
          }));
        } catch (e) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'Ошибка парсинга геоданных' }));
        }
      });
    });

    ipReq.on('error', (err) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: err.message, proxied: isRunning }));
    });
    return;
  }

  // API: Parse single link or subscription URL or multiline keys
  if (req.method === 'POST' && urlParsed === '/api/parse') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body);
        const link = payload.link || payload.raw || payload.text || '';
        const nodes = await parseAnyInput(link);
        if (nodes && nodes.length > 0) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            success: true,
            count: nodes.length,
            data: nodes[0],
            nodes: nodes
          }));
        } else {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'Не удалось распознать ключи или подписку' }));
        }
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: err.message }));
      }
    });
    return;
  }

  // API: Connect
  if (req.method === 'POST' && urlParsed === '/api/connect') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      if (isTransitioning) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ success: false, error: 'Операция уже выполняется, подождите...' }));
      }
      isTransitioning = true;
      try {
        const payload = JSON.parse(body);
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
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'Некорректные параметры узла (отсутствует server или type)', code: 'invalid_outbound' }));
        }

        const result = await startSingBox(outbound, payload.mode || 'proxy');
        isTransitioning = false;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, result }));
      } catch (err) {
        isTransitioning = false;
        const status = err.code === 'tun_requires_admin' ? 403 : 500;
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: err.message, code: err.code }));
      }
    });
    return;
  }

  // API: Disconnect
  if (req.method === 'POST' && urlParsed === '/api/disconnect') {
    isTransitioning = true;
    stopSingBox(() => {
      isTransitioning = false;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, disconnected: true }));
    });
    return;
  }

  // Serve static files — with path traversal protection
  let reqPath = urlParsed === '/' ? '/index.html' : safeDecodeURIComponent(urlParsed);

  // Resolve to absolute and normalize (collapses ../ sequences)
  const filePath = path.resolve(DIR, '.' + reqPath);

  // 1. Block any path that escapes the application root directory
  if (!filePath.startsWith(DIR + path.sep) && filePath !== DIR) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('403 Forbidden');
  }

  // 2. Compute path relative to DIR for blocklist checks
  const relPath = path.relative(DIR, filePath).toLowerCase().replace(/\\/g, '/');
  const firstSegment = relPath.split('/')[0];

  // Block access to sensitive directories and files
  const BLOCKED_PREFIXES = ['.git', 'bin', 'node_modules', 'runtimes'];
  const BLOCKED_FILES = ['server.js', 'package.json', 'package-lock.json', '.gitignore', '.env'];
  if (BLOCKED_PREFIXES.includes(firstSegment) ||
      BLOCKED_FILES.includes(relPath) ||
      firstSegment.startsWith('.')) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('403 Forbidden');
  }

  // 3. Whitelist allowed file extensions only
  const ext = path.extname(filePath).toLowerCase();
  const ALLOWED_EXT = ['.html', '.css', '.js', '.json', '.ico', '.png', '.jpg', '.jpeg', '.svg', '.woff2', '.woff', '.ttf', '.webp'];
  if (!ALLOWED_EXT.includes(ext)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('403 Forbidden');
  }

  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    // Dynamically inject session token into index.html (API_CONTRACT §0)
    if (filePath === path.join(DIR, 'index.html')) {
      try {
        const html = fs.readFileSync(filePath, 'utf8');
        const injected = html.replace('__WOULDAPP_TOKEN__', SESSION_TOKEN);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(injected);
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('500 Internal Server Error');
      }
    }

    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    fs.createReadStream(filePath).pipe(res);
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('404 Not Found');
  }
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.log(`[info] Порт ${PORT} уже занят (сервер WouldApp уже активен в фоне).`);
    process.exit(0);
  } else {
    console.error('Ошибка сервера:', err.message);
  }
});

server.listen(PORT, '127.0.0.1', () => {
  loadSettingsFromDisk();
  restoreProxyOnStartup();
  console.log(`WouldApp Server running at http://localhost:${PORT}/`);
  addLog(`WouldApp backend initialized with Sing-box 1.14 engine.`);
});

// Process signal & crash handlers to guarantee proxy restoration
process.on('exit', () => {
  emergencyProxyCleanup();
});
process.on('SIGINT', () => {
  stopSingBox(() => process.exit(0));
});
process.on('SIGTERM', () => {
  stopSingBox(() => process.exit(0));
});
process.on('uncaughtException', (err) => {
  console.error('[fatal] Неперехваченное исключение:', err);
  addLog(`[fatal] Ошибка сервера: ${err.message}`);
  emergencyProxyCleanup();
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error('[error] Unhandled Rejection:', reason);
  addLog(`[error] Необработанный промис: ${reason}`);
});
