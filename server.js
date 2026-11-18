const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { spawn, exec, execSync } = require('child_process');
const { URL } = require('url');

const PORT = 3005;
const DIR = __dirname;
const BIN_DIR = path.join(DIR, 'bin');
const SINGBOX_EXE = path.join(BIN_DIR, 'sing-box.exe');
const CONFIG_PATH = path.join(BIN_DIR, 'active-config.json');

let singboxProcess = null;
let processStartTime = null;
let logsBuffer = [];
let activeMode = 'proxy'; // 'tun' or 'proxy'

function addLog(msg) {
  const line = `[${new Date().toTimeString().split(' ')[0]}] ${msg}`;
  logsBuffer.push(line);
  if (logsBuffer.length > 100) logsBuffer.shift();
  console.log(line);
}

const PROXY_HELPER_EXE = path.join(BIN_DIR, 'proxy_helper.exe');

// Windows System Proxy Manager (With WinINet Broadcast Notification)
function enableWindowsProxy(proxyPort = 2080, cb) {
  if (fs.existsSync(PROXY_HELPER_EXE)) {
    exec(`"${PROXY_HELPER_EXE}" enable ${proxyPort}`, (err, stdout) => {
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

// Universal parser for vless://, trojan://, ss://, hysteria2://
function parseVlessUrl(link) {
  try {
    let raw = link.trim();
    const match = raw.match(/(vless|trojan|ss|hysteria2|hy2):\/\/[^\s"'<>]+/i);
    if (!match) return null;
    raw = match[0];

    const hashParts = raw.split('#');
    const name = hashParts[1] ? decodeURIComponent(hashParts[1]) : 'Пользовательский узел';
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
    const uuid = decodeURIComponent(parsed.username || '');
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
        path: params.path ? decodeURIComponent(params.path) : '/',
        headers: params.host ? { Host: decodeURIComponent(params.host) } : undefined
      };
    } else if (netType === 'grpc') {
      outbound.transport = {
        type: 'grpc',
        service_name: params.serviceName ? decodeURIComponent(params.serviceName) : ''
      };
    } else if (netType === 'httpupgrade') {
      outbound.transport = {
        type: 'httpupgrade',
        path: params.path ? decodeURIComponent(params.path) : '/',
        host: params.host ? decodeURIComponent(params.host) : undefined
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

function startSingBox(outbound, requestedMode, cb) {
  stopSingBox(() => {
    const tryTun = requestedMode === 'tun';
    const configObj = buildSingBoxConfig(outbound, tryTun);
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(configObj, null, 2), 'utf8');

    addLog(`Запуск sing-box (режим: ${tryTun ? 'TUN (Wintun)' : 'Системный прокси'})...`);
    let proc = spawn(SINGBOX_EXE, ['run', '-c', CONFIG_PATH], {
      cwd: BIN_DIR,
      windowsHide: true
    });

    let hasExited = false;
    let exitError = null;

    proc.stdout.on('data', (d) => {
      addLog(`[stdout] ${d.toString().trim()}`);
    });

    proc.stderr.on('data', (d) => {
      const msg = d.toString().trim();
      addLog(`[stderr] ${msg}`);
      if (msg.includes('Access is denied') || msg.includes('FATAL')) {
        exitError = msg;
      }
    });

    proc.on('exit', (code) => {
      hasExited = true;
      if (singboxProcess === proc) {
        singboxProcess = null;
        processStartTime = null;
        disableWindowsProxy();
      }
    });

    // Check after 600ms if process survived
    setTimeout(() => {
      if (!hasExited && !exitError) {
        singboxProcess = proc;
        processStartTime = Date.now();
        activeMode = tryTun ? 'tun' : 'proxy';

        if (!tryTun) {
          enableWindowsProxy(2080);
        }

        return cb(null, { running: true, pid: proc.pid, mode: activeMode });
      }

      // If TUN failed due to Access is denied (not running as Administrator), gracefully fallback to System Proxy!
      if (tryTun) {
        addLog(`[warning] TUN режим требует прав Администратора. Автоматическое переключение на системный прокси Windows (127.0.0.1:2080)...`);
        try { proc.kill('SIGTERM'); } catch (e) {}

        const fallbackConfig = buildSingBoxConfig(outbound, false);
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(fallbackConfig, null, 2), 'utf8');

        let fallbackHasExited = false;
        let fallbackError = null;

        let fallbackProc = spawn(SINGBOX_EXE, ['run', '-c', CONFIG_PATH], {
          cwd: BIN_DIR,
          windowsHide: true
        });

        fallbackProc.stdout.on('data', d => addLog(`[stdout] ${d.toString().trim()}`));
        fallbackProc.stderr.on('data', (d) => {
          const msg = d.toString().trim();
          addLog(`[stderr] ${msg}`);
          if (msg.includes('FATAL') || msg.includes('ERROR')) {
            fallbackError = msg;
          }
        });

        fallbackProc.on('exit', () => {
          fallbackHasExited = true;
          if (singboxProcess === fallbackProc) {
            singboxProcess = null;
            processStartTime = null;
            disableWindowsProxy();
          }
        });

        setTimeout(() => {
          if (!fallbackHasExited && !fallbackError) {
            singboxProcess = fallbackProc;
            processStartTime = Date.now();
            activeMode = 'proxy';
            enableWindowsProxy(2080);
            return cb(null, { running: true, pid: fallbackProc.pid, mode: 'proxy', note: 'Запущен в режиме системного прокси' });
          } else {
            singboxProcess = null;
            processStartTime = null;
            disableWindowsProxy();
            return cb(new Error(fallbackError || exitError || 'Не удалось запустить sing-box'));
          }
        }, 600);
      } else {
        singboxProcess = null;
        processStartTime = null;
        disableWindowsProxy();
        cb(new Error(exitError || 'Не удалось запустить sing-box'));
      }
    }, 600);
  });
}

function stopSingBox(cb) {
  disableWindowsProxy(() => {
    if (singboxProcess) {
      addLog(`Остановка процесса sing-box (PID: ${singboxProcess.pid})...`);
      try {
        singboxProcess.kill('SIGTERM');
      } catch (e) {}
      singboxProcess = null;
      processStartTime = null;
      setTimeout(cb, 300);
    } else {
      if (cb) cb();
    }
  });
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
  '.jpeg': 'image/jpeg'
};

const server = http.createServer((req, res) => {
  const urlParsed = req.url.split('?')[0];

  // API: Get Status
  if (req.method === 'GET' && urlParsed === '/api/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      running: !!singboxProcess,
      mode: activeMode,
      uptime: processStartTime ? Math.floor((Date.now() - processStartTime) / 1000) : 0,
      logs: logsBuffer.slice(-20)
    }));
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
        const { link } = JSON.parse(body);
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
    req.on('end', () => {
      try {
        const payload = JSON.parse(body);
        let outbound = payload.outbound;

        if (!outbound && payload.link) {
          const parsed = parseVlessUrl(payload.link);
          if (parsed) outbound = parsed.outbound;
        }

        if (!outbound) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ success: false, error: 'Нет данных узла' }));
        }

        startSingBox(outbound, payload.mode || 'proxy', (err, result) => {
          if (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: err.message }));
          } else {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, result }));
          }
        });
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: err.message }));
      }
    });
    return;
  }

  // API: Disconnect
  if (req.method === 'POST' && urlParsed === '/api/disconnect') {
    stopSingBox(() => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, disconnected: true }));
    });
    return;
  }

  // Serve static files
  let reqPath = urlParsed === '/' ? '/index.html' : urlParsed;
  const filePath = path.join(DIR, reqPath);

  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'text/html; charset=utf-8' });
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
  disableWindowsProxy();
  console.log(`WouldApp Server running at http://localhost:${PORT}/`);
  addLog(`WouldApp backend initialized with Sing-box 1.14 engine.`);
});

// Clean up proxy on exit
process.on('SIGINT', () => { stopSingBox(() => process.exit(0)); });
process.on('SIGTERM', () => { stopSingBox(() => process.exit(0)); });
