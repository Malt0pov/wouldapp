const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { URL } = require('url');

const PORT = 3005;
const DIR = __dirname;
const BIN_DIR = path.join(DIR, 'bin');
const SINGBOX_EXE = path.join(BIN_DIR, 'sing-box.exe');
const CONFIG_PATH = path.join(BIN_DIR, 'active-config.json');

let singboxProcess = null;
let processStartTime = null;
let logsBuffer = [];

function addLog(msg) {
  const line = `[${new Date().toTimeString().split(' ')[0]}] ${msg}`;
  logsBuffer.push(line);
  if (logsBuffer.length > 100) logsBuffer.shift();
  console.log(line);
}

// Universal parser for vless:// and other URLs
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

// Generate sing-box 1.14 valid config
function buildSingBoxConfig(outbound, mode = 'tun') {
  const inbounds = [
    {
      type: 'mixed',
      tag: 'mixed-in',
      listen: '127.0.0.1',
      listen_port: 2080,
      sniff: true
    }
  ];

  if (mode === 'tun') {
    inbounds.push({
      type: 'tun',
      tag: 'tun-in',
      interface_name: 'wintun',
      inet4_address: '172.19.0.1/30',
      auto_route: true,
      strict_route: true,
      stack: 'system',
      sniff: true
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
    inbounds: inbounds,
    outbounds: [
      outbound,
      {
        type: 'direct',
        tag: 'direct'
      }
    ],
    route: {
      auto_detect_interface: true,
      final: 'proxy'
    }
  };
}

function startSingBox(configObj, cb) {
  stopSingBox(() => {
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(configObj, null, 2), 'utf8');

    addLog(`Запуск ядра sing-box...`);
    singboxProcess = spawn(SINGBOX_EXE, ['run', '-c', CONFIG_PATH], {
      cwd: BIN_DIR,
      windowsHide: true
    });

    processStartTime = Date.now();

    singboxProcess.stdout.on('data', (data) => {
      addLog(`[stdout] ${data.toString().trim()}`);
    });

    singboxProcess.stderr.on('data', (data) => {
      addLog(`[stderr] ${data.toString().trim()}`);
    });

    singboxProcess.on('error', (err) => {
      addLog(`[error] Ошибка запуска: ${err.message}`);
    });

    singboxProcess.on('exit', (code) => {
      addLog(`Ядро sing-box остановлено с кодом ${code}`);
      singboxProcess = null;
      processStartTime = null;
    });

    setTimeout(() => {
      if (singboxProcess) {
        cb(null, { running: true, pid: singboxProcess.pid });
      } else {
        cb(new Error('Не удалось запустить sing-box (проверьте права администратора для TUN).'));
      }
    }, 700);
  });
}

function stopSingBox(cb) {
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

        const config = buildSingBoxConfig(outbound, payload.mode || 'tun');
        startSingBox(config, (err, result) => {
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
  console.log(`WouldApp Server running at http://localhost:${PORT}/`);
  addLog(`WouldApp backend initialized with Sing-box 1.14 engine.`);
});
