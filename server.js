const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { Server } = require('socket.io');
const { exec, spawn } = require('child_process');
const screenshot = require('screenshot-desktop');
const sharp = require('sharp');
const qrcode = require('qrcode-terminal');
const selfsigned = require('selfsigned');
const si = require('systeminformation');

const app = express();
const PORT = 3000;
const SECURITY_FILE = path.join(__dirname, 'security.json');
const CERT_DIR = path.join(__dirname, 'certs');
const LOG_FILE = path.join(__dirname, 'activity.log');

function loadOrCreateSecurity() {
  if (fs.existsSync(SECURITY_FILE)) {
    try { return JSON.parse(fs.readFileSync(SECURITY_FILE, 'utf8')); } catch(e) {}
  }
  const sec = { masterKey: crypto.randomBytes(24).toString('hex'), whitelist: [] };
  fs.writeFileSync(SECURITY_FILE, JSON.stringify(sec, null, 2));
  return sec;
}
let security = loadOrCreateSecurity();
function saveSecurity() { fs.writeFileSync(SECURITY_FILE, JSON.stringify(security, null, 2)); }

function logActivity(ip, action, detail = '') {
  try { fs.appendFileSync(LOG_FILE, `[${new Date().toLocaleString('tr-TR')}] ${ip} | ${action} ${detail}\n`); } catch(e) {}
}

async function ensureCertificates() {
  if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });
  const keyPath = path.join(CERT_DIR, 'key.pem');
  const certPath = path.join(CERT_DIR, 'cert.pem');
  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    return { key: fs.readFileSync(keyPath, 'utf8'), cert: fs.readFileSync(certPath, 'utf8') };
  }
  const attrs = [{ name: 'commonName', value: 'novapad.local' }];
  let pems;
  try {
    const result = selfsigned.generate(attrs, {
      days: 3650, keySize: 2048, algorithm: 'sha256',
      extensions: [
        { name: 'basicConstraints', cA: true },
        { name: 'keyUsage', keyCertSign: true, digitalSignature: true, keyEncipherment: true },
        { name: 'subjectAltName', altNames: [{ type: 2, value: 'localhost' }, { type: 7, ip: '127.0.0.1' }] }
      ]
    });
    pems = (result && typeof result.then === 'function') ? await result : result;
  } catch (e) { console.error('❌ Sertifika hatası:', e.message); process.exit(1); }
  const pk = pems.private || pems.privateKey || pems.key;
  const ct = pems.cert || pems.certificate;
  fs.writeFileSync(keyPath, pk);
  fs.writeFileSync(certPath, ct);
  return { key: pk, cert: ct };
}

function getClientIP(socket) {
  let ip = socket.handshake.address;
  if (ip && ip.startsWith('::ffff:')) ip = ip.substring(7);
  if (ip === '::1') ip = '127.0.0.1';
  return ip;
}

function startApp(cmd) {
  if (cmd.startsWith('http')) exec(`start chrome ${cmd}`);
  else exec(`start ${cmd}`);
}

let mouseProcess = null;
function startMouseProcess() {
  if (mouseProcess && !mouseProcess.killed) return;
  const ps = `
    Add-Type -AssemblyName System.Windows.Forms;
    Add-Type -MemberDefinition '[DllImport("user32.dll")] public static extern void mouse_event(int dwFlags, int dx, int dy, int dwData, int dwExtraInfo);' -Name M -Namespace W;
    while ($true) {
      $line = [Console]::ReadLine();
      if ($line -match '^move (-?\\d+),(-?\\d+)$') {
        $x=[int]$Matches[1]; $y=[int]$Matches[2];
        $p=[System.Windows.Forms.Cursor]::Position;
        [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point(($p.X+$x),($p.Y+$y));
      } elseif ($line -match '^setpos (-?\\d+),(-?\\d+)$') {
        $x=[int]$Matches[1]; $y=[int]$Matches[2];
        [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point($x,$y);
      } elseif ($line -eq 'click') {
        [W.M]::mouse_event(0x0002,0,0,0,0); [W.M]::mouse_event(0x0004,0,0,0,0);
      } elseif ($line -eq 'rightclick') {
        [W.M]::mouse_event(0x0008,0,0,0,0); [W.M]::mouse_event(0x0010,0,0,0,0);
      } elseif ($line -eq 'dblclick') {
        [W.M]::mouse_event(0x0002,0,0,0,0); [W.M]::mouse_event(0x0004,0,0,0,0);
        Start-Sleep -Milliseconds 80;
        [W.M]::mouse_event(0x0002,0,0,0,0); [W.M]::mouse_event(0x0004,0,0,0,0);
      } elseif ($line -eq 'exit') { break }
    }
  `;
  mouseProcess = spawn('powershell', ['-NoProfile', '-Command', ps], { stdio: ['pipe', 'pipe', 'pipe'] });
  mouseProcess.stdin.setDefaultEncoding('utf-8');
}
function moveMouse(dx, dy) {
  if (!mouseProcess || mouseProcess.killed) startMouseProcess();
  if (mouseProcess && mouseProcess.stdin) mouseProcess.stdin.write(`move ${Math.round(dx)},${Math.round(dy)}\n`);
}
function moveMouseAbsolute(x, y) {
  if (!mouseProcess || mouseProcess.killed) startMouseProcess();
  if (mouseProcess && mouseProcess.stdin) mouseProcess.stdin.write(`setpos ${Math.round(x)},${Math.round(y)}\n`);
}
function click(b='left') {
  if (!mouseProcess || mouseProcess.killed) startMouseProcess();
  if (mouseProcess && mouseProcess.stdin) mouseProcess.stdin.write(b==='left'?'click\n':'rightclick\n');
}
function dblClick() {
  if (!mouseProcess || mouseProcess.killed) startMouseProcess();
  if (mouseProcess && mouseProcess.stdin) mouseProcess.stdin.write('dblclick\n');
}
function sendKey(key) {
  exec(`powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('${key}')"`);
}
startMouseProcess();

function listDirectory(dirPath) {
  return new Promise((resolve, reject) => {
    fs.readdir(dirPath, { withFileTypes: true }, (err, items) => {
      if (err) return reject(err);
      const result = items.map(item => {
        const fullPath = path.join(dirPath, item.name);
        const stats = fs.statSync(fullPath);
        return { name: item.name, isDirectory: item.isDirectory(), size: stats.size, modified: stats.mtime.toLocaleString('tr-TR'), fullPath };
      });
      result.sort((a, b) => {
        if (a.isDirectory && !b.isDirectory) return -1;
        if (!a.isDirectory && b.isDirectory) return 1;
        return a.name.localeCompare(b.name);
      });
      resolve(result);
    });
  });
}
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024, s = ['B','KB','MB','GB','TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + s[i];
}

async function startServer() {
  const credentials = await ensureCertificates();
  const server = https.createServer(credentials, app);
  const io = new Server(server, { maxHttpBufferSize: 100 * 1024 * 1024 });

  app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
  app.use(express.static(path.join(__dirname)));

  io.use((socket, next) => {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    const ip = getClientIP(socket);
    if (!token || token !== security.masterKey) {
      logActivity(ip, '❌ YETKİSİZ');
      return next(new Error('AUTH_REQUIRED'));
    }
    if (!security.whitelist.includes(ip)) {
      security.whitelist.push(ip);
      saveSecurity();
      logActivity(ip, '✅ EŞLEŞTİRİLDİ');
    }
    socket.clientIP = ip;
    logActivity(ip, '🔗 BAĞLANDI');
    next();
  });

  io.on('connection', (socket) => {
    console.log(`📱 Bağlandı: ${socket.clientIP}`);

    socket.on('getSystemStats', async () => {
      try {
        const [cpu, mem, disks, temp, battery, net] = await Promise.all([
          si.currentLoad(), si.mem(), si.fsSize(), si.cpuTemperature(), si.battery(), si.networkStats()
        ]);
        socket.emit('systemStats', {
          cpu: { load: cpu.currentLoad ? cpu.currentLoad.toFixed(1) : 0, cores: cpu.cpus ? cpu.cpus.length : 0 },
          mem: { usedFormatted: formatBytes(mem.used), totalFormatted: formatBytes(mem.total), percent: (mem.used/mem.total*100).toFixed(1) },
          disks: disks.map(d => ({ fs: d.fs, usedFormatted: formatBytes(d.used), sizeFormatted: formatBytes(d.size), use: d.use ? d.use.toFixed(1) : 0 })),
          temp: { main: temp.main || 0, max: temp.max || 0 },
          battery: { percent: battery.percent || 0, isCharging: battery.isCharging, hasBattery: battery.hasBattery },
          net: { rxFormatted: net[0] ? formatBytes(Math.max(0, net[0].rx_sec)) + '/s' : '0 B/s', txFormatted: net[0] ? formatBytes(Math.max(0, net[0].tx_sec)) + '/s' : '0 B/s' }
        });
      } catch (err) { socket.emit('systemError', err.message); }
    });

    socket.on('downloadFile', (filePath) => {
      try {
        if (!fs.existsSync(filePath)) return socket.emit('downloadError', 'Dosya bulunamadı');
        const stat = fs.statSync(filePath);
        if (stat.size > 50 * 1024 * 1024) return socket.emit('downloadError', 'Dosya 50MB üstü');
        const data = fs.readFileSync(filePath);
        socket.emit('fileDownloaded', { name: path.basename(filePath), data: data.toString('base64'), size: stat.size });
        logActivity(socket.clientIP, '📥 İNDİRDİ', path.basename(filePath));
      } catch (err) { socket.emit('downloadError', err.message); }
    });

    socket.on('setWallpaper', (data) => {
      try {
        const m = data.match(/^data:image\/(png|jpeg|jpg);base64,(.+)$/);
        if (!m) return socket.emit('wallpaperError', 'Geçersiz resim');
        const buf = Buffer.from(m[2], 'base64');
        const f = path.join(os.tmpdir(), `wall_${Date.now()}.jpg`);
        fs.writeFileSync(f, buf);
        exec(`powershell -Command "Add-Type -MemberDefinition '[DllImport(\\"user32.dll\\")] public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);' -Name W -Namespace S; [S.W]::SystemParametersInfo(20, 0, '${f.replace(/\\/g,'\\\\')}', 3)"`, (err) => {
          if (err) socket.emit('wallpaperError', 'Değiştirilemedi');
          else { socket.emit('wallpaperDone'); logActivity(socket.clientIP, '🖼️ DUVAR KAĞIDI'); }
        });
      } catch (_) { socket.emit('wallpaperError'); }
    });

    socket.on('setWallpaperUrl', (url) => {
      const tmp = path.join(os.tmpdir(), `wall_${Date.now()}.jpg`);
      const psCmd = `powershell -Command "$wc = New-Object System.Net.WebClient; $wc.DownloadFile('${url}', '${tmp.replace(/\\/g, '\\\\')}'); Add-Type -MemberDefinition '[DllImport(\\"user32.dll\\")] public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);' -Name W -Namespace S; [S.W]::SystemParametersInfo(20, 0, '${tmp.replace(/\\/g, '\\\\')}', 3)"`;
      exec(psCmd, (err) => {
        if (err) socket.emit('wallpaperError', 'İndirilemedi');
        else { socket.emit('wallpaperDone'); logActivity(socket.clientIP, '🎨 DUVAR KAĞIDI', url.substring(0, 40)); }
      });
    });

    socket.on('setVolume', (level) => {
      const vol = Math.max(0, Math.min(100, parseInt(level) || 0));
      exec(`powershell -Command "$wsh = New-Object -ComObject WScript.Shell; 1..50 | ForEach-Object { $wsh.SendKeys([char]174) }"`, () => {
        const steps = Math.ceil(vol / 2);
        for (let i = 0; i < steps; i++) exec('powershell -Command "(New-Object -ComObject WScript.Shell).SendKeys([char]175)"');
        socket.emit('volumeDone', vol);
        logActivity(socket.clientIP, '🔊 SES', vol + '%');
      });
    });

    socket.on('getLogs', () => {
      try {
        if (!fs.existsSync(LOG_FILE)) return socket.emit('logsData', []);
        const lines = fs.readFileSync(LOG_FILE, 'utf8').trim().split('\n').slice(-100).reverse();
        socket.emit('logsData', lines);
      } catch (err) { socket.emit('logsData', []); }
    });
    socket.on('clearLogs', () => {
      try { fs.writeFileSync(LOG_FILE, ''); socket.emit('logsCleared'); } catch(e) {}
    });

    socket.on('modeGame', () => {
      exec('start steam://open/main');
      socket.emit('modeDone', '🎮 Oyun Modu — Steam açıldı');
      logActivity(socket.clientIP, '🎮 MOD', 'Oyun');
    });

    socket.on('modeWork', () => {
      exec('start devenv', (err) => {
        if (err) {
          exec('start code', (err2) => {
            if (err2) exec('start "" "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\devenv.exe"');
          });
        }
      });
      setTimeout(() => exec('start chrome https://music.youtube.com'), 2000);
      socket.emit('modeDone', '💼 İş Modu — Visual Studio + YT Music açıldı');
      logActivity(socket.clientIP, '💼 MOD', 'İş');
    });

    socket.on('modeMovie', () => {
      exec('powershell -Command "$wsh = New-Object -ComObject WScript.Shell; 1..50 | ForEach-Object { $wsh.SendKeys([char]175) }"');
      socket.emit('modeDone', '🎬 Film Gecesi — Ses 100%');
      logActivity(socket.clientIP, '🎬 MOD', 'Film');
    });

    socket.on('takeScreenshot', async () => {
      try {
        const img = await screenshot({ format: 'jpeg' });
        const resized = await sharp(img).resize({ width: 1920, fit: 'inside' }).jpeg({ quality: 85 }).toBuffer();
        const f = path.join(os.homedir(), 'Desktop', `EkranGoruntusu_${Date.now()}.jpg`);
        fs.writeFileSync(f, resized);
        socket.emit('screenshotSaved', path.basename(f));
        logActivity(socket.clientIP, '📷 EKRAN FOTOĞRAFI');
      } catch (err) { socket.emit('screenshotError', err.message); }
    });

    socket.on('openCamera', () => {
      exec('start microsoft.windows.camera:');
      socket.emit('cameraOpened');
      logActivity(socket.clientIP, '🎥 KAMERA');
    });

    socket.on('startScreenRecord', () => {
      exec('start ms-gamebar:');
      socket.emit('recordStarted');
      logActivity(socket.clientIP, '📹 KAYIT', 'Başladı');
    });

    // 🔍 EKRAN ANALİZİ
    socket.on('analyzeScreen', async () => {
      try {
        const img = await screenshot({ format: 'jpeg' });
        const resized = await sharp(img).resize({ width: 1024, fit: 'inside' }).jpeg({ quality: 75 }).toBuffer();
        socket.emit('screenAnalysis', 'data:image/jpeg;base64,' + resized.toString('base64'));
        logActivity(socket.clientIP, '🔍 EKRAN ANALİZİ');
      } catch (err) { socket.emit('screenAnalysisError', err.message); }
    });

    // 📝 KOD YAZICI
    socket.on('writeCode', (data) => {
      try {
        const { filename, code, language } = data;
        if (!code) return socket.emit('codeError', 'Kod boş');
        const extMap = { python:'py', javascript:'js', typescript:'ts', java:'java', cpp:'cpp', c:'c', csharp:'cs', html:'html', css:'css', php:'php', ruby:'rb', go:'go', rust:'rs', kotlin:'kt', swift:'swift', sql:'sql', bash:'sh', json:'json', xml:'xml', yaml:'yml' };
        const ext = extMap[language] || 'txt';
        const base = (filename || 'kod_' + Date.now()).replace(/[^a-zA-Z0-9_\-]/g, '_');
        const finalName = base.endsWith('.' + ext) ? base : base + '.' + ext;
        const f = path.join(os.homedir(), 'Desktop', finalName);
        fs.writeFileSync(f, code);
        exec(`start code "${f}"`, (err) => { if (err) exec(`start "" "${f}"`); });
        socket.emit('codeWritten', finalName);
        logActivity(socket.clientIP, '📝 KOD YAZDI', finalName);
      } catch (err) { socket.emit('codeError', err.message); }
    });

    // 💀 SAHTE BSOD
    socket.on('fakeBSOD', () => {
      const ps = `
        Add-Type -AssemblyName System.Windows.Forms;
        Add-Type -AssemblyName System.Drawing;
        $form = New-Object System.Windows.Forms.Form;
        $form.WindowState = 'Maximized';
        $form.FormBorderStyle = 'None';
        $form.TopMost = $true;
        $form.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215);
        $form.Cursor = [System.Windows.Forms.Cursors]::Default;
        $label = New-Object System.Windows.Forms.Label;
        $label.Text = [char]0xD83D + [char]0xDE1F + "\`n\`nBir sorun oluştu ve bilgisayarınız yeniden başlatılması gerekiyor.\`n\`n%0 tamamlandı\`n\`nHata kodu: 0x000000FF";
        $label.ForeColor = 'White';
        $label.Font = New-Object System.Drawing.Font('Segoe UI', 26);
        $label.AutoSize = $false;
        $label.Dock = 'Fill';
        $label.TextAlign = 'MiddleCenter';
        $form.Controls.Add($label);
        $form.KeyPreview = $true;
        $form.Add_KeyDown({ $form.Close() });
        $form.Add_MouseClick({ $form.Close() });
        [System.Windows.Forms.Application]::Run($form);
      `;
      const tmp = path.join(os.tmpdir(), 'bsod_novapad.ps1');
      fs.writeFileSync(tmp, ps);
      spawn('powershell', ['-NoProfile', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-File', tmp], { detached: true });
      socket.emit('bsodShown');
      logActivity(socket.clientIP, '💀 SAHTE BSOD');
    });

    // 🕵️ GİZLİ KAMERA
    socket.on('secretPhoto', () => {
      try {
        const ffmpegPath = require('ffmpeg-static');
        const out = path.join(os.homedir(), 'Desktop', `gizli_${Date.now()}.jpg`);
        exec(`powershell -Command "Get-PnpDevice -Class Camera | Select-Object -First 1 -ExpandProperty FriendlyName"`, (err, stdout) => {
          let camName = 'Integrated Camera';
          if (!err && stdout.trim()) camName = stdout.trim();
          exec(`"${ffmpegPath}" -f dshow -i video="${camName}" -frames:v 1 -y "${out}"`, (err2) => {
            if (err2) {
              exec(`"${ffmpegPath}" -f dshow -i video="default" -frames:v 1 -y "${out}"`, (err3) => {
                if (err3) socket.emit('secretPhotoError', 'Kamera bulunamadı');
                else { socket.emit('secretPhotoDone', path.basename(out)); logActivity(socket.clientIP, '🕵️ GİZLİ FOTO'); }
              });
            } else { socket.emit('secretPhotoDone', path.basename(out)); logActivity(socket.clientIP, '🕵️ GİZLİ FOTO'); }
          });
        });
      } catch (err) { socket.emit('secretPhotoError', err.message); }
    });

    // 🎂 DOĞUM GÜNÜ MODU
    socket.on('birthdayMode', (data) => {
      const isim = (data && data.name) ? data.name : 'Sevgili Dostum';
      const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
        body { margin:0; background:linear-gradient(135deg,#0f0f1a,#1a1a3e); color:#fff; font-family:'Segoe UI',sans-serif; text-align:center; padding:60px 20px; min-height:100vh; overflow:hidden; }
        h1 { font-size:64px; text-shadow:0 0 20px #ff4dff,0 0 40px #6c63ff; animation:pulse 1.5s infinite alternate; margin-bottom:30px; }
        p { font-size:26px; color:#ffd740; margin-bottom:20px; }
        .confetti { position:fixed; top:-50px; font-size:28px; animation:fall linear forwards; pointer-events:none; }
        @keyframes fall { to { transform:translateY(110vh) rotate(720deg); opacity:0; } }
        @keyframes pulse { from{ transform:scale(1); } to{ transform:scale(1.05); } }
      </style></head><body>
        <h1>🎂 Doğum Günün Kutlu Olsun! 🎉</h1>
        <p>${isim} 🌟</p>
        <p>Nice mutlu, sağlıklı ve başarılı senelere!</p>
        <p style="font-size:18px;opacity:0.7;">— NovaPad Nexus 💜</p>
        <script>
          const emojis = ['🎉','🎊','🎈','🎁','⭐','💜','🌟','✨','🥳','🎂'];
          for (let i = 0; i < 120; i++) {
            setTimeout(() => {
              const c = document.createElement('div');
              c.className = 'confetti';
              c.textContent = emojis[Math.floor(Math.random()*emojis.length)];
              c.style.left = Math.random()*100 + '%';
              c.style.animationDuration = (2 + Math.random()*3) + 's';
              c.style.fontSize = (20 + Math.random()*30) + 'px';
              document.body.appendChild(c);
            }, i * 80);
          }
        <\/script>
      </body></html>`;
      const tmp = path.join(os.homedir(), 'Desktop', 'dogum_gunu_novapad.html');
      fs.writeFileSync(tmp, html);
      exec(`start chrome --start-fullscreen "${tmp}"`);
      socket.emit('birthdayDone');
      logActivity(socket.clientIP, '🎂 DOĞUM GÜNÜ MODU', isim);
    });

    // 📍 KONUM KAYDET
    socket.on('saveLocation', (data) => {
      try {
        const locFile = path.join(__dirname, 'locations.json');
        let list = [];
        if (fs.existsSync(locFile)) { try { list = JSON.parse(fs.readFileSync(locFile, 'utf8')); } catch(e) {} }
        list.push({ lat: data.lat, lng: data.lng, accuracy: data.accuracy, time: new Date().toLocaleString('tr-TR') });
        if (list.length > 100) list = list.slice(-100);
        fs.writeFileSync(locFile, JSON.stringify(list, null, 2));
        socket.emit('locationSaved', { lat: data.lat, lng: data.lng });
        logActivity(socket.clientIP, '📍 KONUM', `${data.lat.toFixed(4)}, ${data.lng.toFixed(4)}`);
      } catch (err) { socket.emit('locationError', err.message); }
    });

    socket.on('listDirectory', async (dirPath) => {
      try {
        const validPath = dirPath || os.homedir();
        const items = await listDirectory(validPath);
        const itemsWithSize = items.map(item => ({ ...item, sizeFormatted: item.isDirectory ? 'Klasör' : formatBytes(item.size) }));
        socket.emit('directoryList', { path: validPath, parentPath: path.dirname(validPath), items: itemsWithSize });
      } catch (err) { socket.emit('directoryError', 'Klasör okunamadı: ' + err.message); }
    });

    socket.on('openPath', (fp) => {
      exec(`start "" "${fp}"`, (err) => {
        if (err) socket.emit('openError', 'Açılamadı');
        else { socket.emit('opened', fp); logActivity(socket.clientIP, '📂 AÇTI', path.basename(fp)); }
      });
    });

    socket.on('clipboard', (text) => {
      if (!text || !text.trim()) return;
      const safe = text.replace(/'/g, "''").replace(/"/g, '\\"');
      exec(`powershell -Command "Set-Clipboard -Value '${safe}'"`, (err) => {
        if (err) socket.emit('clipboardError'); else socket.emit('clipboardDone', text);
      });
    });
    socket.on('typeText', (text) => {
      if (!text || !text.trim()) return;
      const safe = text.replace(/'/g, "''").replace(/"/g, '\\"');
      exec(`powershell -Command "Set-Clipboard -Value '${safe}'"`, (err) => { if (!err) sendKey('^v'); });
    });
    socket.on('readClipboard', () => {
      exec('powershell -Command "Get-Clipboard"', (err, out) => {
        socket.emit('clipboardContent', (!err && out.trim()) ? out.trim() : '');
      });
    });

    socket.on('photo', (data) => {
      try {
        const m = data.match(/^data:image\/(png|jpeg|jpg|gif|webp);base64,(.+)$/);
        if (!m) return socket.emit('photoError');
        const buf = Buffer.from(m[2], 'base64');
        const f = path.join(os.homedir(), 'Desktop', `NovaPad_${Date.now()}.${m[1]==='jpeg'?'jpg':m[1]}`);
        fs.writeFileSync(f, buf);
        exec(`start "" "${f}"`);
        socket.emit('photoSent');
      } catch (_) { socket.emit('photoError'); }
    });

    socket.on('fileUpload', (data) => {
      try {
        const m = data.data.match(/^data:(.*);base64,(.+)$/);
        if (!m) return socket.emit('fileError');
        const buf = Buffer.from(m[2], 'base64');
        const f = path.join(os.homedir(), 'Desktop', data.name || `Dosya_${Date.now()}.bin`);
        fs.writeFileSync(f, buf);
        socket.emit('fileSent', data.name);
        logActivity(socket.clientIP, '📤 YÜKLEDİ', data.name);
      } catch (_) { socket.emit('fileError'); }
    });

    socket.on('cleanStorage', () => {
      exec('powershell -Command "Clear-RecycleBin -Force -EA 0; rm $env:TEMP\\* -Recurse -Force -EA 0; rm $env:WINDIR\\Temp\\* -Recurse -Force -EA 0"');
      socket.emit('storageCleaned');
      logActivity(socket.clientIP, '🧹 TEMİZLİK');
    });

    socket.on('timerShutdown', (min) => {
      const sec = parseInt(min) * 60;
      if (isNaN(sec) || sec <= 0) return;
      exec(`shutdown /s /t ${sec}`, (err) => {
        if (err) socket.emit('timerError');
        else { socket.emit('timerStarted', min); logActivity(socket.clientIP, '⏱️ KAPATMA', min + 'dk'); }
      });
    });
    socket.on('cancelShutdown', () => {
      exec('shutdown /a', (err) => {
        if (err) socket.emit('cancelError'); else socket.emit('shutdownCancelled');
      });
    });

    socket.on('type', (text) => startApp(`https://www.google.com/search?q=${encodeURIComponent(text)}`));

    socket.on('key', (key) => {
      logActivity(socket.clientIP, '⌨️ TUŞ', key);
      switch (key) {
        case 'ctrl+t': sendKey('^t'); break;
        case 'ctrl+w': sendKey('^w'); break;
        case 'alt+left': sendKey('%{LEFT}'); break;
        case 'alt+right': sendKey('%{RIGHT}'); break;
        case 'volume_up': exec('powershell -Command "(New-Object -ComObject WScript.Shell).SendKeys([char]175)"'); break;
        case 'volume_down': exec('powershell -Command "(New-Object -ComObject WScript.Shell).SendKeys([char]174)"'); break;
        case 'volume_mute': exec('powershell -Command "(New-Object -ComObject WScript.Shell).SendKeys([char]173)"'); break;
        case 'media_play_pause': exec('powershell -Command "(New-Object -ComObject WScript.Shell).SendKeys([char]179)"'); break;
        case 'media_prev': exec('powershell -Command "(New-Object -ComObject WScript.Shell).SendKeys([char]177)"'); break;
        case 'media_next': exec('powershell -Command "(New-Object -ComObject WScript.Shell).SendKeys([char]176)"'); break;
        case 'escape': sendKey('{ESC}'); break;
        case 'enter': sendKey('{ENTER}'); break;
        case 'tab': sendKey('{TAB}'); break;
        case 'shiftTab': sendKey('+{TAB}'); break;
        case 'up': sendKey('{UP}'); break;
        case 'down': sendKey('{DOWN}'); break;
        case 'left': sendKey('{LEFT}'); break;
        case 'right': sendKey('{RIGHT}'); break;
        case 'lock': exec('rundll32.exe user32.dll,LockWorkStation'); break;
        case 'chrome': startApp('chrome'); break;
        case 'notepad': startApp('notepad'); break;
        case 'calc': startApp('calc'); break;
        case 'explorer': startApp('explorer'); break;
        case 'taskmgr': startApp('taskmgr'); break;
        case 'control': startApp('control'); break;
        case 'snipping': startApp('snippingtool'); break;
        case 'spotify': startApp('https://open.spotify.com'); break;
        case 'youtubeMusic': startApp('https://music.youtube.com'); break;
        case 'youtube': startApp('https://youtube.com'); break;
        case 'gmail': startApp('https://mail.google.com'); break;
        case 'whatsapp': startApp('https://web.whatsapp.com'); break;
        case 'github': startApp('https://github.com'); break;
        case 'minimizeAll': exec('powershell -Command "$shell = New-Object -ComObject shell.application; $shell.MinimizeAll()"'); break;
        case 'monitorOff': exec('powershell -Command "Add-Type -MemberDefinition \'[DllImport(\\\"user32.dll\\\")] public static extern int SendMessage(int hWnd, int Msg, int wParam, int lParam);\' -Name W -Namespace S; [S.W]::SendMessage(0xFFFF,0x0112,0xF170,2)"'); break;
        case 'shutdown': exec('shutdown /s /t 0'); break;
        case 'restart': exec('shutdown /r /t 0'); break;
        case 'screenFlip': exec('powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.DisplaySettings]::SetDisplayMode(0,0,16,90)"'); break;
        case 'screenNormal': exec('powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.DisplaySettings]::SetDisplayMode(0,0,16,0)"'); break;
        case 'mouseCrazy': (() => { for (let i=0;i<40;i++) setTimeout(() => moveMouse((Math.random()-0.5)*60,(Math.random()-0.5)*60), i*25); })(); break;
        case 'matrix': exec('start powershell -NoExit -Command "$r=New-Object Random; while($true){Write-Host -NoNewline ([char]$r.Next(33,126));Start-Sleep -Milliseconds 50;if($r.Next(100) -lt 5){Write-Host \'\';Start-Sleep -Milliseconds 200}}"'); break;
        case 'emojiRain': (() => {
          const emojis = ['😂','🎉','❤️','🔥','⭐','🎊','😎','🚀','🌈','💫'];
          for (let i = 0; i < 20; i++) setTimeout(() => sendKey(emojis[Math.floor(Math.random()*emojis.length)]), i * 120);
        })(); break;
        default: if (key.startsWith('http')) startApp(key); break;
      }
    });

    socket.on('mouseMove', (data) => moveMouse(data.dx, data.dy));
    socket.on('mouseMoveTo', (data) => moveMouseAbsolute(data.x, data.y));
    socket.on('mouseClick', () => click('left'));
    socket.on('mouseRightClick', () => click('right'));
    socket.on('mouseDoubleClick', () => dblClick());

    let screenShareInterval = null;
    socket.on('startScreenShare', () => {
      if (screenShareInterval) return;
      screenShareInterval = setInterval(async () => {
        try {
          const img = await screenshot({ format: 'jpeg' });
          const resized = await sharp(img).resize({ width: 1280, height: 720, fit: 'inside' }).jpeg({ quality: 60 }).toBuffer();
          socket.emit('screenFrame', 'data:image/jpeg;base64,' + resized.toString('base64'));
        } catch (err) { socket.emit('screenError', err.message); }
      }, 500);
    });
    socket.on('stopScreenShare', () => {
      if (screenShareInterval) { clearInterval(screenShareInterval); screenShareInterval = null; }
    });
    socket.on('getScreenSize', async () => {
      try {
        const d = await screenshot.listDisplays();
        if (d.length > 0) socket.emit('screenSize', { width: d[0].width, height: d[0].height });
      } catch (err) { socket.emit('screenError', err.message); }
    });

    socket.on('disconnect', () => {
      if (screenShareInterval) { clearInterval(screenShareInterval); screenShareInterval = null; }
      logActivity(socket.clientIP, '❌ AYRILDI');
    });
  });

  function getLocalIPs() {
    const ifs = os.networkInterfaces();
    const addrs = [];
    for (const name of Object.keys(ifs)) {
      for (const iface of ifs[name]) {
        if (iface.family === 'IPv4' && !iface.internal) addrs.push({ name, address: iface.address });
      }
    }
    return addrs;
  }

  server.listen(PORT, '0.0.0.0', () => {
    const ips = getLocalIPs();
    console.log('\n╔═══════════════════════════════════════════════════════╗');
    console.log('║   🔐 NOVAPAD NEXUS — GÜVENLİ SUNUCU BAŞLATILDI 🔐     ║');
    console.log('╚═══════════════════════════════════════════════════════╝\n');
    console.log('✅ HTTPS/WSS Aktif');
    console.log(`📋 Whitelist: ${security.whitelist.length} cihaz`);
    if (ips.length > 0) {
      const primaryIP = ips[0].address;
      const url = `https://${primaryIP}:${PORT}/?k=${security.masterKey}`;
      console.log('\n📱 QR KODU OKUTUN:\n');
      qrcode.generate(url, { small: true });
      console.log(`\n🔗 Link: ${url}\n`);
    }
    console.log('🔒 Kapatmak için CTRL+C\n');
  });
}

startServer().catch(err => { console.error('❌', err); process.exit(1); });