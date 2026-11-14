const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn, exec } = require('child_process');
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

// Windows System Proxy Manager (No Admin Rights Required!)
function enableWindowsProxy(proxyPort = 2080, cb) {
  const cmd = `reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f && reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyServer /t REG_SZ /d "127.0.0.1:${proxyPort}" /f`;
  exec(cmd, (err) => {
    if (err) addLog(`[proxy] Ошибка включения системного прокси: ${err.message}`);
    else addLog(`[proxy] Системный прокси Windows активирован на 127.0.0.1:${proxyPort}`);
    if (cb) cb();
  });
}

function disableWindowsProxy(cb) {
  const cmd = `reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f`;
  exec(cmd, (err) => {
    if (err) addLog(`[proxy] Ошибка отключения системного прокси: ${err.message}`);
    else addLog(`[proxy] Системный прокси Windows отключен`);
    if (cb) cb();
  });
}

// Universal parser for vless://, trojan://, ss://
function parseVlessUrl(link) {
  try {
    const raw = link.trim();
    if (!raw.startsWith('vless://') && !raw.startsWith('trojan://') && !raw.startsWith('ss://')) {
      return null;
    }

    const hashParts = raw.split('#');
    const name = hashParts[1] ? decodeURIComponent(hashParts[1]) : 'Пользовательский узел';
    const mainUri = hashParts[0];

    const parsed = new URL(mainUri);
    const type = parsed.protocol.replace(':', '');
    const uuid = parsed.username;
    const server = parsed.hostname;
    const port = parseInt(parsed.port, 10) || 443;
    const params = Object.fromEntries(parsed.searchParams.entries());

    const outbound = {
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

    return { name, outbound };
  } catch (err) {
    console.error('Parse error:', err);
    return null;
  }
}

// Build valid sing-box 1.14 configuration
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
    inbounds: inbounds,
    outbounds: [
      outbound,
      {
        type: 'direct',
        tag: 'direct'
      }
    ],
    route: {
      rules: [
        {
          action: 'sniff'
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

        let fallbackProc = spawn(SINGBOX_EXE, ['run', '-c', CONFIG_PATH], {
          cwd: BIN_DIR,
          windowsHide: true
        });

        fallbackProc.stdout.on('data', d => addLog(`[stdout] ${d.toString().trim()}`));
        fallbackProc.stderr.on('data', d => addLog(`[stderr] ${d.toString().trim()}`));
        fallbackProc.on('exit', () => {
          singboxProcess = null;
          processStartTime = null;
          disableWindowsProxy();
        });

        setTimeout(() => {
          singboxProcess = fallbackProc;
          processStartTime = Date.now();
          activeMode = 'proxy';
          enableWindowsProxy(2080);
          return cb(null, { running: true, pid: fallbackProc.pid, mode: 'proxy', note: 'Запущен в режиме системного прокси' });
        }, 500);
      } else {
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
  '.svg': 'image/svg+xml'
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

  // API: Parse link
  if (req.method === 'POST' && urlParsed === '/api/parse') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { link } = JSON.parse(body);
        const parsed = parseVlessUrl(link);
        if (parsed) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, data: parsed }));
        } else {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'Неверный формат ссылки' }));
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

        startSingBox(outbound, payload.mode || 'tun', (err, result) => {
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

server.listen(PORT, '127.0.0.1', () => {
  disableWindowsProxy();
  console.log(`WouldApp Server running at http://localhost:${PORT}/`);
  addLog(`WouldApp backend initialized with Sing-box 1.14 engine.`);
});

// Clean up proxy on exit
process.on('SIGINT', () => { stopSingBox(() => process.exit(0)); });
process.on('SIGTERM', () => { stopSingBox(() => process.exit(0)); });
