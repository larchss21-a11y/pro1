<?php
/**
 * NEXUS FIREWALL — Servidor (un solo archivo) para Hostinger
 * - Cuentas de usuarios de la app, Gratis / Premium (días, ilimitado, revocar)
 * - Planes con precios y pagos PayPal (REST, verificación en servidor)
 * - Panel de administración
 * - URL MCP para que tus IA controlen los teléfonos (cola de comandos)
 * - IA (Gemini) con la clave SOLO en el servidor; modelos cargados dinámicamente
 */
declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '0');
date_default_timezone_set('UTC');

const NFW_VERSION = '1.0.0';
const NFW_CONFIG = __DIR__ . '/nexus_fw_config.php';
const NFW_FEATURES = [
    'firewall_apps' => 'Firewall por aplicación',
    'bypass_apps' => 'Apps que pasan sin filtro',
    'learning' => 'Aprendizaje automático de anuncios',
    'custom_rules' => 'Reglas de dominios propias',
    'custom_lists' => 'Listas de bloqueo personalizadas',
    'mcp_local' => 'Servidor MCP local',
    'mcp_remote' => 'Control remoto MCP vía servidor',
    'ai_assistant' => 'Asistente IA',
    'cloner' => 'Clonador de aplicaciones',
    'themes' => 'Temas extra',
    'vpn_manager' => 'Gestor de mis VPN',
];

/* ============================================================ utilidades */
function h($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function now(): int { return time(); }
function json_out(array $d, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Headers: Content-Type, X-Nexus-Token, Authorization, Mcp-Session-Id, Mcp-Protocol-Version');
    echo json_encode($d, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function fail(string $msg, int $code = 400): void { json_out(['ok' => false, 'error' => $msg], $code); }
function body_json(): array {
    static $b = null;
    if ($b === null) { $raw = file_get_contents('php://input') ?: ''; $b = json_decode($raw, true); if (!is_array($b)) $b = []; }
    return $b;
}
function rand_token(int $bytes = 24): string { return bin2hex(random_bytes($bytes)); }
function self_url(): string {
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    return ($https ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . strtok($_SERVER['REQUEST_URI'] ?? '/', '?');
}

/* ============================================================ instalación */
if (!file_exists(NFW_CONFIG)) { install_page(); exit; }
require NFW_CONFIG;

function db(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    $pdo = new PDO('mysql:host=' . NFW_DB_HOST . ';dbname=' . NFW_DB_NAME . ';charset=utf8mb4', NFW_DB_USER, NFW_DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    return $pdo;
}
function q(string $sql, array $p = []): PDOStatement { $s = db()->prepare($sql); $s->execute($p); return $s; }

function create_tables(PDO $pdo): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS nfw_settings (k VARCHAR(64) PRIMARY KEY, v MEDIUMTEXT) DEFAULT CHARSET=utf8mb4");
    $pdo->exec("CREATE TABLE IF NOT EXISTS nfw_users (
        id INT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(190) UNIQUE, name VARCHAR(120), pass_hash VARCHAR(255),
        token VARCHAR(80) UNIQUE, premium_until INT DEFAULT 0, premium_unlimited TINYINT DEFAULT 0, banned TINYINT DEFAULT 0,
        note VARCHAR(255) DEFAULT '', created_at INT, last_seen INT DEFAULT 0) DEFAULT CHARSET=utf8mb4");
    $pdo->exec("CREATE TABLE IF NOT EXISTS nfw_plans (
        id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(120), days INT DEFAULT 30, price DECIMAL(10,2) DEFAULT 0,
        currency VARCHAR(8) DEFAULT 'USD', description VARCHAR(255) DEFAULT '', active TINYINT DEFAULT 1, sort INT DEFAULT 0) DEFAULT CHARSET=utf8mb4");
    $pdo->exec("CREATE TABLE IF NOT EXISTS nfw_payments (
        id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, plan_id INT, order_id VARCHAR(64) UNIQUE, amount DECIMAL(10,2),
        currency VARCHAR(8), status VARCHAR(32), payer_email VARCHAR(190) DEFAULT '', days INT DEFAULT 0, created_at INT, raw MEDIUMTEXT) DEFAULT CHARSET=utf8mb4");
    $pdo->exec("CREATE TABLE IF NOT EXISTS nfw_devices (
        id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, device_id VARCHAR(80), model VARCHAR(120) DEFAULT '', state MEDIUMTEXT,
        last_seen INT, UNIQUE KEY ud (user_id, device_id)) DEFAULT CHARSET=utf8mb4");
    $pdo->exec("CREATE TABLE IF NOT EXISTS nfw_commands (
        id INT AUTO_INCREMENT PRIMARY KEY, device_row INT, tool VARCHAR(64), args MEDIUMTEXT, status VARCHAR(16) DEFAULT 'pending',
        result MEDIUMTEXT, source VARCHAR(120) DEFAULT '', created_at INT, done_at INT DEFAULT 0, KEY dr (device_row, status)) DEFAULT CHARSET=utf8mb4");
    $pdo->exec("CREATE TABLE IF NOT EXISTS nfw_mcp_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(120), token VARCHAR(80) UNIQUE, user_id INT DEFAULT 0,
        scope VARCHAR(16) DEFAULT 'full', created_at INT, last_used INT DEFAULT 0) DEFAULT CHARSET=utf8mb4");
}

function install_page(): void {
    $err = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $host = trim($_POST['host'] ?? 'localhost'); $name = trim($_POST['name'] ?? '');
        $user = trim($_POST['user'] ?? ''); $pass = (string)($_POST['pass'] ?? ''); $admin = (string)($_POST['admin'] ?? '');
        if (strlen($admin) < 8) $err = 'La contraseña de administrador debe tener al menos 8 caracteres.';
        else {
            try {
                $pdo = new PDO("mysql:host=$host;dbname=$name;charset=utf8mb4", $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
                create_tables($pdo);
                $st = $pdo->prepare("REPLACE INTO nfw_settings (k,v) VALUES (?,?)");
                $st->execute(['admin_hash', password_hash($admin, PASSWORD_DEFAULT)]);
                $st->execute(['paypal_email', 'larchss21@gmail.com']);
                $st->execute(['paypal_mode', 'live']);
                $st->execute(['premium_features', json_encode(['firewall_apps', 'learning', 'mcp_local', 'mcp_remote', 'ai_assistant', 'cloner', 'themes', 'custom_lists'])]);
                $st->execute(['trial_days', '0']);
                $cfg = "<?php\n// Configuración generada por el instalador de Nexus Firewall. No la compartas.\n" .
                    "const NFW_DB_HOST = " . var_export($host, true) . ";\nconst NFW_DB_NAME = " . var_export($name, true) . ";\n" .
                    "const NFW_DB_USER = " . var_export($user, true) . ";\nconst NFW_DB_PASS = " . var_export($pass, true) . ";\n" .
                    "const NFW_SECRET = " . var_export(rand_token(32), true) . ";\n";
                if (file_put_contents(NFW_CONFIG, $cfg) === false) $err = 'No pude escribir nexus_fw_config.php (revisa permisos de la carpeta).';
                else { header('Location: ' . self_url() . '?page=admin'); exit; }
            } catch (Throwable $e) { $err = 'Error de base de datos: ' . $e->getMessage(); }
        }
    }
    page_head('Instalar Nexus Firewall');
    echo '<div class="wrap narrow"><div class="card"><h1><span class="r">NEXUS</span> FIREWALL · Instalación</h1>';
    if ($err) echo '<div class="alert">' . h($err) . '</div>';
    echo '<p class="muted">Crea una base de datos MySQL en hPanel (Bases de datos › MySQL) y escribe sus datos aquí.</p>
    <form method="post">
      <label>Servidor MySQL</label><input name="host" value="localhost">
      <label>Nombre de la base</label><input name="name" required>
      <label>Usuario</label><input name="user" required>
      <label>Contraseña</label><input name="pass" type="password">
      <label>Contraseña del panel de administrador (mín. 8)</label><input name="admin" type="password" required>
      <button class="btn">Instalar</button>
    </form></div></div>';
    page_foot();
}

/* ============================================================ ajustes */
function setting(string $k, string $def = ''): string {
    static $cache = null;
    if ($cache === null) { $cache = []; foreach (q("SELECT k,v FROM nfw_settings")->fetchAll() as $r) $cache[$r['k']] = $r['v']; }
    return array_key_exists($k, $cache) ? (string)$cache[$k] : $def;
}
function set_setting(string $k, string $v): void { q("REPLACE INTO nfw_settings (k,v) VALUES (?,?)", [$k, $v]); }
function premium_features(): array { $a = json_decode(setting('premium_features', '[]'), true); return is_array($a) ? array_values($a) : []; }

/* ============================================================ usuarios / licencia */
function user_by_token(?string $t): ?array {
    if (!$t) return null;
    $u = q("SELECT * FROM nfw_users WHERE token=?", [$t])->fetch();
    if (!$u || (int)$u['banned'] === 1) return null;
    q("UPDATE nfw_users SET last_seen=? WHERE id=?", [now(), $u['id']]);
    return $u;
}
function api_user(): array {
    $t = $_SERVER['HTTP_X_NEXUS_TOKEN'] ?? (body_json()['token'] ?? ($_GET['token'] ?? ''));
    $u = user_by_token(is_string($t) ? $t : '');
    if (!$u) fail('Sesión inválida, vuelve a iniciar sesión', 401);
    return $u;
}
function is_premium(array $u): bool { return (int)$u['premium_unlimited'] === 1 || (int)$u['premium_until'] > now(); }
function license(array $u): array {
    return [
        'premium' => is_premium($u),
        'expires' => (int)$u['premium_unlimited'] === 1 ? 0 : (int)$u['premium_until'],
        'unlimited' => (int)$u['premium_unlimited'] === 1,
    ];
}
function feature_ok(array $u, string $f): bool { return !in_array($f, premium_features(), true) || is_premium($u); }
function add_days(int $uid, int $days): void {
    if ($days <= 0) { q("UPDATE nfw_users SET premium_unlimited=1 WHERE id=?", [$uid]); return; }
    $u = q("SELECT premium_until FROM nfw_users WHERE id=?", [$uid])->fetch();
    $base = max(now(), (int)($u['premium_until'] ?? 0));
    q("UPDATE nfw_users SET premium_until=? WHERE id=?", [$base + $days * 86400, $uid]);
}
function public_plans(): array {
    $out = [];
    foreach (q("SELECT * FROM nfw_plans WHERE active=1 ORDER BY sort, price")->fetchAll() as $p) {
        $out[] = ['id' => (int)$p['id'], 'name' => $p['name'], 'days' => (int)$p['days'], 'price' => number_format((float)$p['price'], 2, '.', ''),
            'currency' => $p['currency'], 'description' => $p['description']];
    }
    return $out;
}

/* ============================================================ PayPal */
function paypal_base(): string { return setting('paypal_mode', 'live') === 'sandbox' ? 'https://api-m.sandbox.paypal.com' : 'https://api-m.paypal.com'; }
function paypal_token(): string {
    $cid = setting('paypal_client_id'); $sec = setting('paypal_secret');
    if (!$cid || !$sec) throw new Exception('PayPal no está configurado en el panel');
    $r = http_req('POST', paypal_base() . '/v1/oauth2/token', 'grant_type=client_credentials',
        ['Content-Type: application/x-www-form-urlencoded', 'Authorization: Basic ' . base64_encode("$cid:$sec")]);
    if (empty($r['json']['access_token'])) throw new Exception('PayPal rechazó las credenciales');
    return $r['json']['access_token'];
}
function http_req(string $method, string $url, ?string $body, array $headers, int $timeout = 60): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_CUSTOMREQUEST => $method, CURLOPT_HTTPHEADER => $headers, CURLOPT_TIMEOUT => $timeout]);
    if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    $txt = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    if ($txt === false) throw new Exception('Error de red: ' . $err);
    return ['code' => $code, 'json' => json_decode((string)$txt, true), 'raw' => (string)$txt];
}

/* ============================================================ Gemini (clave solo en servidor) */
function gemini_models(): array {
    $key = setting('gemini_key');
    if (!$key) throw new Exception('Falta la clave de Gemini en el panel');
    $r = http_req('GET', 'https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000&key=' . urlencode($key), null, []);
    if ($r['code'] !== 200) throw new Exception('Gemini respondió ' . $r['code'] . ': ' . ($r['json']['error']['message'] ?? ''));
    $out = [];
    foreach ($r['json']['models'] ?? [] as $m) {
        if (in_array('generateContent', $m['supportedGenerationMethods'] ?? [], true)) $out[] = ['name' => $m['name'], 'label' => $m['displayName'] ?? $m['name']];
    }
    if (!$out) throw new Exception('Tu clave no tiene modelos con generateContent disponibles');
    return $out;
}
function gemini_json(string $prompt): array {
    $key = setting('gemini_key'); $model = setting('gemini_model');
    if (!$key) throw new Exception('Falta la clave de Gemini en el panel de administración');
    if (!$model) throw new Exception('Elige un modelo de Gemini en Ajustes del panel (se cargan de tu cuenta)');
    $url = 'https://generativelanguage.googleapis.com/v1beta/' . $model . ':generateContent?key=' . urlencode($key);
    $payload = ['contents' => [['role' => 'user', 'parts' => [['text' => $prompt]]]], 'generationConfig' => ['responseMimeType' => 'application/json', 'temperature' => 0.2]];
    $r = http_req('POST', $url, json_encode($payload), ['Content-Type: application/json'], 90);
    if ($r['code'] !== 200) throw new Exception('Gemini error ' . $r['code'] . ': ' . ($r['json']['error']['message'] ?? 'sin detalle'));
    $text = $r['json']['candidates'][0]['content']['parts'][0]['text'] ?? '';
    $j = json_decode($text, true);
    if (!is_array($j)) throw new Exception('La IA no devolvió JSON válido');
    return $j;
}

/* ============================================================ dispositivos / comandos */
const DEVICE_TOOLS = [
    ['get_status', 'Estado del firewall del teléfono (instantáneo, desde la última sincronización).', false, []],
    ['start_firewall', 'Activa el firewall.', true, []],
    ['stop_firewall', 'Detiene el firewall.', true, []],
    ['get_logs', 'Últimas consultas DNS.', false, ['limit' => 'integer', 'solo_bloqueadas' => 'boolean']],
    ['top_domains', 'Dominios más consultados.', false, ['limit' => 'integer']],
    ['list_apps', 'Apps instaladas con sus reglas.', false, ['incluir_sistema' => 'boolean']],
    ['set_app_rule', 'Bloquear internet de una app o dejarla pasar sin filtro.', true, ['package' => 'string', 'bloquear_internet' => 'boolean', 'sin_filtro' => 'boolean']],
    ['block_domain', 'Bloquea un dominio y subdominios.', true, ['domain' => 'string']],
    ['allow_domain', 'Permite siempre un dominio.', true, ['domain' => 'string']],
    ['remove_domain_rule', 'Quita reglas de un dominio.', true, ['domain' => 'string']],
    ['list_rules', 'Reglas propias, aprendidas y listas.', false, []],
    ['set_learning', 'Activa/desactiva aprendizaje.', true, ['enabled' => 'boolean']],
    ['set_upstream_dns', 'Cambia el DNS superior.', true, ['dns' => 'string']],
    ['update_blocklists', 'Actualiza listas de bloqueo.', true, []],
    ['add_blocklist', 'Agrega lista por URL.', true, ['name' => 'string', 'url' => 'string']],
    ['clear_logs', 'Borra el registro.', true, []],
];
const ADMIN_TOOLS = [
    ['list_users', 'Lista usuarios y su estado premium.', ['search' => 'string']],
    ['grant_premium', 'Da días premium a un usuario (days=0 → ilimitado).', ['email' => 'string', 'days' => 'integer']],
    ['revoke_premium', 'Quita el premium a un usuario.', ['email' => 'string']],
    ['list_payments', 'Últimos pagos.', ['limit' => 'integer']],
    ['list_plans', 'Planes y precios.', []],
    ['set_plan', 'Crea o edita un plan (id opcional).', ['id' => 'integer', 'name' => 'string', 'days' => 'integer', 'price' => 'number', 'currency' => 'string', 'active' => 'boolean']],
    ['set_premium_features', 'Define qué funciones son premium (lista de claves).', ['features' => 'array']],
];

function queue_command(int $deviceRow, string $tool, array $args, string $source): int {
    q("INSERT INTO nfw_commands (device_row,tool,args,status,source,created_at) VALUES (?,?,?,?,?,?)",
        [$deviceRow, $tool, json_encode($args, JSON_UNESCAPED_UNICODE), 'pending', $source, now()]);
    return (int)db()->lastInsertId();
}
function wait_result(int $cmdId, int $seconds = 25): ?array {
    $end = microtime(true) + $seconds;
    while (microtime(true) < $end) {
        $c = q("SELECT status,result FROM nfw_commands WHERE id=?", [$cmdId])->fetch();
        if ($c && $c['status'] === 'done') return json_decode((string)$c['result'], true) ?: ['resultado' => 'hecho'];
        usleep(800000);
    }
    return null;
}

/* ============================================================ enrutador */
$api = $_GET['api'] ?? null;
$page = $_GET['page'] ?? null;
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') json_out(['ok' => true]);
try {
    if (isset($_GET['mcp'])) { mcp_endpoint(); exit; }
    if ($api !== null) { api_route((string)$api); exit; }
    if ($page === 'pay') { pay_page(); exit; }
    admin_route();
} catch (Throwable $e) {
    if ($api !== null || isset($_GET['mcp'])) fail('Error del servidor: ' . $e->getMessage(), 500);
    page_head('Error'); echo '<div class="wrap"><div class="alert">' . h($e->getMessage()) . '</div></div>'; page_foot();
}

/* ============================================================ API de la app */
function api_route(string $a): void {
    $b = body_json();
    switch ($a) {
        case 'register':
            $email = strtolower(trim((string)($b['email'] ?? ''))); $pass = (string)($b['password'] ?? '');
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) fail('Correo inválido');
            if (strlen($pass) < 6) fail('La contraseña debe tener al menos 6 caracteres');
            if (q("SELECT id FROM nfw_users WHERE email=?", [$email])->fetch()) fail('Ese correo ya está registrado');
            $tok = rand_token();
            $trial = (int)setting('trial_days', '0');
            q("INSERT INTO nfw_users (email,name,pass_hash,token,premium_until,created_at) VALUES (?,?,?,?,?,?)",
                [$email, mb_substr(trim((string)($b['name'] ?? '')), 0, 120), password_hash($pass, PASSWORD_DEFAULT), $tok, $trial > 0 ? now() + $trial * 86400 : 0, now()]);
            json_out(['ok' => true, 'token' => $tok]);
        case 'login':
            $email = strtolower(trim((string)($b['email'] ?? '')));
            $u = q("SELECT * FROM nfw_users WHERE email=?", [$email])->fetch();
            if (!$u || !password_verify((string)($b['password'] ?? ''), $u['pass_hash'])) fail('Correo o contraseña incorrectos', 401);
            if ((int)$u['banned'] === 1) fail('Cuenta suspendida', 403);
            json_out(['ok' => true, 'token' => $u['token']]);
        case 'me':
            $u = api_user();
            json_out(['ok' => true, 'user' => ['email' => $u['email'], 'name' => $u['name']], 'license' => license($u),
                'premium_features' => premium_features(), 'plans' => public_plans(), 'paypal' => setting('paypal_client_id') !== '']);
        case 'device_sync':
            $u = api_user();
            $did = substr((string)($b['device_id'] ?? ''), 0, 80);
            if ($did === '') fail('Falta device_id');
            q("INSERT INTO nfw_devices (user_id,device_id,model,state,last_seen) VALUES (?,?,?,?,?)
               ON DUPLICATE KEY UPDATE model=VALUES(model), state=VALUES(state), last_seen=VALUES(last_seen)",
                [$u['id'], $did, substr((string)($b['model'] ?? ''), 0, 120), json_encode($b['state'] ?? [], JSON_UNESCAPED_UNICODE), now()]);
            $row = q("SELECT id FROM nfw_devices WHERE user_id=? AND device_id=?", [$u['id'], $did])->fetch();
            $cmds = [];
            if ($row && feature_ok($u, 'mcp_remote')) {
                foreach (q("SELECT id,tool,args FROM nfw_commands WHERE device_row=? AND status='pending' ORDER BY id LIMIT 20", [$row['id']])->fetchAll() as $c) {
                    $cmds[] = ['id' => (int)$c['id'], 'tool' => $c['tool'], 'args' => json_decode((string)$c['args'], true) ?: new stdClass()];
                    q("UPDATE nfw_commands SET status='sent' WHERE id=?", [$c['id']]);
                }
            }
            json_out(['ok' => true, 'commands' => $cmds, 'license' => license($u)]);
        case 'command_result':
            $u = api_user();
            $id = (int)($b['id'] ?? 0);
            q("UPDATE nfw_commands c JOIN nfw_devices d ON d.id=c.device_row SET c.status='done', c.result=?, c.done_at=? WHERE c.id=? AND d.user_id=?",
                [json_encode($b['result'] ?? [], JSON_UNESCAPED_UNICODE), now(), $id, $u['id']]);
            json_out(['ok' => true]);
        case 'ai_classify':
            $u = api_user();
            if (!feature_ok($u, 'ai_assistant')) fail('Función premium', 403);
            $domains = array_slice(array_values(array_filter((array)($b['domains'] ?? []), 'is_string')), 0, 300);
            if (!$domains) fail('Sin dominios');
            $j = gemini_json("Eres un experto en bloqueo de anuncios. De esta lista de dominios DNS, devuelve SOLO los que con alta seguridad son de publicidad, rastreo, telemetría o analítica publicitaria. " .
                "No incluyas dominios necesarios para que funcionen las apps (login, CDN de contenido, APIs, pagos, mensajería). Responde JSON {\"ads\":[\"dominio\"],\"note\":\"explicación corta en español\"}.\nDominios:\n" . implode("\n", $domains));
            $ads = array_values(array_intersect(array_map('strtolower', (array)($j['ads'] ?? [])), array_map('strtolower', $domains)));
            json_out(['ok' => true, 'ads' => $ads, 'note' => (string)($j['note'] ?? '')]);
        case 'ai_command':
            $u = api_user();
            if (!feature_ok($u, 'ai_assistant')) fail('Función premium', 403);
            $text = mb_substr(trim((string)($b['text'] ?? '')), 0, 2000);
            if ($text === '') fail('Escribe algo');
            $state = json_encode($b['state'] ?? [], JSON_UNESCAPED_UNICODE);
            $tools = json_encode($b['tools'] ?? [], JSON_UNESCAPED_UNICODE);
            $j = gemini_json("Eres el asistente de Nexus Firewall, un firewall/bloqueador de anuncios Android. Responde en español.\n" .
                "Herramientas disponibles (nombre, descripción, esquema): $tools\nEstado actual del teléfono: $state\n" .
                "Orden del usuario: \"$text\"\nSi el usuario nombra una app, usa su nombre de paquete Android más probable (ej. TikTok = com.zhiliaoapp.musically). " .
                "Responde SOLO JSON: {\"reply\":\"respuesta corta\",\"actions\":[{\"tool\":\"nombre\",\"args\":{}}]}. Si no hace falta acción, actions vacío.");
            $actions = [];
            $valid = array_column(DEVICE_TOOLS, 0);
            foreach ((array)($j['actions'] ?? []) as $act) {
                if (is_array($act) && in_array($act['tool'] ?? '', $valid, true)) $actions[] = ['tool' => $act['tool'], 'args' => is_array($act['args'] ?? null) ? $act['args'] : new stdClass()];
            }
            json_out(['ok' => true, 'reply' => (string)($j['reply'] ?? ''), 'actions' => $actions]);
        case 'paypal_create':
            $u = api_user();
            $plan = q("SELECT * FROM nfw_plans WHERE id=? AND active=1", [(int)($b['plan'] ?? 0)])->fetch();
            if (!$plan) fail('Plan no disponible');
            $tok = paypal_token();
            $order = ['intent' => 'CAPTURE', 'purchase_units' => [[
                'reference_id' => 'plan_' . $plan['id'],
                'custom_id' => $u['id'] . ':' . $plan['id'],
                'description' => mb_substr('Nexus Firewall Premium - ' . $plan['name'], 0, 120),
                'amount' => ['currency_code' => $plan['currency'], 'value' => number_format((float)$plan['price'], 2, '.', '')],
                'payee' => ['email_address' => setting('paypal_email', 'larchss21@gmail.com')],
            ]], 'application_context' => ['brand_name' => 'Nexus Firewall', 'shipping_preference' => 'NO_SHIPPING', 'user_action' => 'PAY_NOW']];
            $r = http_req('POST', paypal_base() . '/v2/checkout/orders', json_encode($order), ['Content-Type: application/json', "Authorization: Bearer $tok"]);
            if (empty($r['json']['id'])) fail('PayPal: ' . ($r['json']['message'] ?? $r['raw']));
            q("INSERT INTO nfw_payments (user_id,plan_id,order_id,amount,currency,status,days,created_at,raw) VALUES (?,?,?,?,?,?,?,?,?)",
                [$u['id'], $plan['id'], $r['json']['id'], $plan['price'], $plan['currency'], 'CREATED', $plan['days'], now(), $r['raw']]);
            json_out(['ok' => true, 'id' => $r['json']['id']]);
        case 'paypal_capture':
            $u = api_user();
            $oid = preg_replace('/[^A-Za-z0-9-]/', '', (string)($b['orderID'] ?? ''));
            $p = q("SELECT * FROM nfw_payments WHERE order_id=? AND user_id=?", [$oid, $u['id']])->fetch();
            if (!$p) fail('Orden desconocida');
            if ($p['status'] === 'COMPLETED') json_out(['ok' => true, 'already' => true]);
            $tok = paypal_token();
            $r = http_req('POST', paypal_base() . "/v2/checkout/orders/$oid/capture", '{}', ['Content-Type: application/json', "Authorization: Bearer $tok"]);
            $j = $r['json'] ?? [];
            $cap = $j['purchase_units'][0]['payments']['captures'][0] ?? null;
            $ok = ($j['status'] ?? '') === 'COMPLETED' && $cap && ($cap['status'] ?? '') === 'COMPLETED'
                && abs((float)$cap['amount']['value'] - (float)$p['amount']) < 0.01
                && strtoupper($cap['amount']['currency_code']) === strtoupper($p['currency']);
            q("UPDATE nfw_payments SET status=?, payer_email=?, raw=? WHERE id=?",
                [$ok ? 'COMPLETED' : ('FAILED:' . ($j['status'] ?? $r['code'])), (string)($j['payer']['email_address'] ?? ''), $r['raw'], $p['id']]);
            if (!$ok) fail('El pago no se completó o no coincide con el plan');
            add_days((int)$u['id'], (int)$p['days']);
            $u2 = q("SELECT * FROM nfw_users WHERE id=?", [$u['id']])->fetch();
            json_out(['ok' => true, 'license' => license($u2)]);
        case 'plans':
            json_out(['ok' => true, 'plans' => public_plans()]);
        default:
            fail('Acción desconocida', 404);
    }
}

/* ============================================================ página de pago */
function pay_page(): void {
    $token = (string)($_GET['token'] ?? '');
    $u = user_by_token($token);
    $plan = q("SELECT * FROM nfw_plans WHERE id=? AND active=1", [(int)($_GET['plan'] ?? 0)])->fetch();
    page_head('Pagar Premium');
    echo '<div class="wrap narrow"><div class="card">';
    echo '<h1><span class="r">NEXUS</span> FIREWALL <span class="badge">PREMIUM</span></h1>';
    $cid = setting('paypal_client_id');
    if (!$u) echo '<div class="alert">Sesión inválida. Abre esta página desde la app.</div>';
    elseif (!$plan) echo '<div class="alert">El plan no existe o está desactivado.</div>';
    elseif (!$cid) echo '<div class="alert">El administrador aún no configuró PayPal.</div>';
    else {
        $days = (int)$plan['days'];
        echo '<h2>' . h($plan['name']) . '</h2><p class="big">' . h(number_format((float)$plan['price'], 2)) . ' ' . h($plan['currency']) . '</p>';
        echo '<p class="muted">' . ($days === 0 ? 'Premium para siempre' : "$days días de Premium") . ' para ' . h($u['email']) . '</p>';
        if ($plan['description']) echo '<p>' . h($plan['description']) . '</p>';
        echo '<div id="pp"></div><div id="msg"></div>';
        $sdk = 'https://www.paypal.com/sdk/js?client-id=' . urlencode($cid) . '&currency=' . urlencode($plan['currency']) . '&intent=capture';
        $api = h(self_url());
        echo '<script src="' . h($sdk) . '"></script><script>
        const T=' . json_encode($token) . ', P=' . (int)$plan['id'] . ', API="' . $api . '";
        async function call(a,d){const r=await fetch(API+"?api="+a,{method:"POST",headers:{"Content-Type":"application/json","X-Nexus-Token":T},body:JSON.stringify(d)});const j=await r.json();if(!j.ok)throw new Error(j.error||"error");return j;}
        const msg=t=>document.getElementById("msg").innerHTML=t;
        paypal.Buttons({style:{color:"black",shape:"rect",label:"pay"},
          createOrder:async()=>{try{return (await call("paypal_create",{plan:P})).id}catch(e){msg("<div class=alert>"+e.message+"</div>");throw e}},
          onApprove:async(d)=>{msg("Confirmando pago…");try{await call("paypal_capture",{orderID:d.orderID});msg("<div class=ok>✅ ¡Pago completado! Ya eres Premium. Vuelve a la app y toca “Actualizar estado”.</div>");document.getElementById("pp").remove()}catch(e){msg("<div class=alert>"+e.message+"</div>")}},
          onError:e=>msg("<div class=alert>PayPal: "+e+"</div>")}).render("#pp");
        </script>';
    }
    echo '</div></div>';
    page_foot();
}

/* ============================================================ MCP remoto */
function mcp_endpoint(): void {
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'GET') {
        http_response_code(405); header('Allow: POST'); exit;
    }
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
    if ($auth === '' && function_exists('getallheaders')) { foreach (getallheaders() as $hk => $hv) if (strtolower($hk) === 'authorization') $auth = $hv; }
    $key = preg_replace('/^Bearer\s+/i', '', trim($auth)) ?: (string)($_GET['key'] ?? '');
    $tok = $key ? q("SELECT * FROM nfw_mcp_tokens WHERE token=?", [$key])->fetch() : null;
    if (!$tok) json_out(['jsonrpc' => '2.0', 'id' => null, 'error' => ['code' => -32001, 'message' => 'Token MCP inválido']], 401);
    q("UPDATE nfw_mcp_tokens SET last_used=? WHERE id=?", [now(), $tok['id']]);
    $req = body_json();
    if (isset($req[0])) { // lote
        $out = [];
        foreach ($req as $r) { $x = mcp_handle(is_array($r) ? $r : [], $tok); if ($x !== null) $out[] = $x; }
        if (!$out) { http_response_code(202); exit; }
        json_out($out);
    }
    $res = mcp_handle($req, $tok);
    if ($res === null) { http_response_code(202); exit; }
    json_out($res);
}

function schema(array $props): array {
    $p = [];
    foreach ($props as $k => $t) $p[$k] = $t === 'array' ? ['type' => 'array', 'items' => ['type' => 'string']] : ['type' => $t];
    return ['type' => 'object', 'properties' => (object)$p];
}

function mcp_tools(array $tok): array {
    $tools = [['name' => 'list_devices', 'description' => 'Lista los teléfonos con Nexus Firewall vinculados y su última conexión.', 'inputSchema' => schema([])]];
    foreach (DEVICE_TOOLS as [$n, $d, $w, $props]) {
        if ($tok['scope'] === 'read' && $w) continue;
        $tools[] = ['name' => $n, 'description' => $d . ' Parámetro "device": id del teléfono (opcional si solo hay uno).',
            'inputSchema' => schema(['device' => 'string'] + $props)];
    }
    if ($tok['scope'] === 'admin') foreach (ADMIN_TOOLS as [$n, $d, $props]) $tools[] = ['name' => $n, 'description' => '[ADMIN] ' . $d, 'inputSchema' => schema($props)];
    return $tools;
}

function mcp_devices(array $tok): array {
    if ($tok['scope'] === 'admin' && (int)$tok['user_id'] === 0) return q("SELECT d.*, u.email FROM nfw_devices d JOIN nfw_users u ON u.id=d.user_id ORDER BY last_seen DESC")->fetchAll();
    return q("SELECT d.*, u.email FROM nfw_devices d JOIN nfw_users u ON u.id=d.user_id WHERE d.user_id=? ORDER BY last_seen DESC", [(int)$tok['user_id']])->fetchAll();
}

function mcp_text($data, bool $err = false): array {
    return ['content' => [['type' => 'text', 'text' => is_string($data) ? $data : json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT)]], 'isError' => $err];
}

function mcp_handle(array $req, array $tok): ?array {
    $id = $req['id'] ?? null;
    $method = (string)($req['method'] ?? '');
    if ($id === null || strpos($method, 'notifications/') === 0) return null;
    $res = ['jsonrpc' => '2.0', 'id' => $id];
    switch ($method) {
        case 'initialize':
            $res['result'] = ['protocolVersion' => (string)($req['params']['protocolVersion'] ?? '2025-06-18'),
                'capabilities' => ['tools' => new stdClass()],
                'serverInfo' => ['name' => 'nexus-firewall-remoto', 'version' => NFW_VERSION],
                'instructions' => 'Controla los teléfonos con Nexus Firewall. Usa list_devices primero. Token: ' . $tok['name'] . ' (' . $tok['scope'] . ').'];
            return $res;
        case 'ping': $res['result'] = new stdClass(); return $res;
        case 'tools/list': $res['result'] = ['tools' => mcp_tools($tok)]; return $res;
        case 'tools/call':
            $name = (string)($req['params']['name'] ?? '');
            $args = (array)($req['params']['arguments'] ?? []);
            try { $res['result'] = mcp_call($name, $args, $tok); }
            catch (Throwable $e) { $res['result'] = mcp_text('Error: ' . $e->getMessage(), true); }
            return $res;
        default:
            $res['error'] = ['code' => -32601, 'message' => "Método no soportado: $method"];
            return $res;
    }
}

function mcp_call(string $name, array $args, array $tok): array {
    $admin = $tok['scope'] === 'admin';
    // ---- herramientas de administración
    $adminNames = array_column(ADMIN_TOOLS, 0);
    if (in_array($name, $adminNames, true)) {
        if (!$admin) return mcp_text('Este token no es de administrador', true);
        switch ($name) {
            case 'list_users':
                $s = '%' . ($args['search'] ?? '') . '%';
                $rows = q("SELECT id,email,name,premium_until,premium_unlimited,banned,created_at,last_seen FROM nfw_users WHERE email LIKE ? OR name LIKE ? ORDER BY id DESC LIMIT 200", [$s, $s])->fetchAll();
                foreach ($rows as &$r) { $r['premium'] = is_premium($r); $r['vence'] = $r['premium_unlimited'] ? 'ilimitado' : ($r['premium_until'] ? gmdate('Y-m-d H:i', (int)$r['premium_until']) : '-'); }
                return mcp_text($rows);
            case 'grant_premium':
                $u = q("SELECT id FROM nfw_users WHERE email=?", [strtolower(trim((string)($args['email'] ?? '')))])->fetch();
                if (!$u) return mcp_text('Usuario no encontrado', true);
                add_days((int)$u['id'], (int)($args['days'] ?? 30));
                return mcp_text('Premium otorgado a ' . $args['email']);
            case 'revoke_premium':
                q("UPDATE nfw_users SET premium_until=0, premium_unlimited=0 WHERE email=?", [strtolower(trim((string)($args['email'] ?? '')))]);
                return mcp_text('Premium retirado');
            case 'list_payments':
                return mcp_text(q("SELECT p.id,u.email,p.amount,p.currency,p.status,p.payer_email,p.days,FROM_UNIXTIME(p.created_at) fecha FROM nfw_payments p LEFT JOIN nfw_users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT " . max(1, min(200, (int)($args['limit'] ?? 30))))->fetchAll());
            case 'list_plans':
                return mcp_text(q("SELECT * FROM nfw_plans ORDER BY sort, price")->fetchAll());
            case 'set_plan':
                $f = [mb_substr((string)($args['name'] ?? 'Plan'), 0, 120), (int)($args['days'] ?? 30), (float)($args['price'] ?? 0), strtoupper((string)($args['currency'] ?? 'USD')), isset($args['active']) ? (int)(bool)$args['active'] : 1];
                if (!empty($args['id'])) { q("UPDATE nfw_plans SET name=?,days=?,price=?,currency=?,active=? WHERE id=?", array_merge($f, [(int)$args['id']])); return mcp_text('Plan actualizado'); }
                q("INSERT INTO nfw_plans (name,days,price,currency,active) VALUES (?,?,?,?,?)", $f);
                return mcp_text('Plan creado #' . db()->lastInsertId());
            case 'set_premium_features':
                $fs = array_values(array_intersect((array)($args['features'] ?? []), array_keys(NFW_FEATURES)));
                set_setting('premium_features', json_encode($fs));
                return mcp_text(['premium_features' => $fs]);
        }
    }
    // ---- dispositivos
    $devices = mcp_devices($tok);
    if ($name === 'list_devices') {
        return mcp_text(array_map(fn($d) => ['device' => $d['device_id'], 'modelo' => $d['model'], 'usuario' => $d['email'],
            'ultima_conexion' => gmdate('Y-m-d H:i:s', (int)$d['last_seen']) . ' UTC', 'en_linea' => (now() - (int)$d['last_seen']) < 40], $devices));
    }
    $def = null;
    foreach (DEVICE_TOOLS as $t) if ($t[0] === $name) $def = $t;
    if (!$def) return mcp_text("Herramienta desconocida: $name", true);
    if ($def[2] && $tok['scope'] === 'read') return mcp_text('Token de solo lectura', true);
    if (!$devices) return mcp_text('No hay teléfonos vinculados. En la app: Cuenta › iniciar sesión, luego IA/MCP › Activar control remoto.', true);
    $want = (string)($args['device'] ?? '');
    $dev = null;
    foreach ($devices as $d) if ($want !== '' && ($d['device_id'] === $want || (string)$d['id'] === $want)) $dev = $d;
    if (!$dev) { if (count($devices) === 1 || $want === '') $dev = $devices[0]; else return mcp_text('Indica "device" (usa list_devices)', true); }
    unset($args['device']);
    if ($name === 'get_status') {
        $st = json_decode((string)$dev['state'], true) ?: [];
        $st['ultima_sincronizacion_utc'] = gmdate('Y-m-d H:i:s', (int)$dev['last_seen']);
        $st['en_linea'] = (now() - (int)$dev['last_seen']) < 40;
        return mcp_text($st);
    }
    $cid = queue_command((int)$dev['id'], $name, $args, 'mcp:' . $tok['name']);
    $r = wait_result($cid, 25);
    if ($r === null) return mcp_text("Comando #$cid en cola. El teléfono lo ejecutará en cuanto se conecte (¿tiene internet y el control remoto activo?).");
    return mcp_text($r, isset($r['error']));
}

/* ============================================================ panel de administración */
function admin_route(): void {
    session_name('nfwadm');
    session_start();
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = rand_token(16);
    $act = $_POST['act'] ?? '';
    if ($act === 'login') {
        if (password_verify((string)($_POST['password'] ?? ''), setting('admin_hash'))) { session_regenerate_id(true); $_SESSION['adm'] = 1; }
        else { sleep(1); $_SESSION['flash'] = 'Contraseña incorrecta'; }
        header('Location: ' . self_url() . '?page=admin'); exit;
    }
    if (empty($_SESSION['adm'])) { admin_login(); return; }
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) { $_SESSION['flash'] = 'Sesión expirada, intenta otra vez'; }
        else admin_action((string)$act);
        $tab = preg_replace('/[^a-z]/', '', (string)($_POST['tab'] ?? 'dash'));
        header('Location: ' . self_url() . '?page=admin&tab=' . $tab); exit;
    }
    if (isset($_GET['ajax']) && $_GET['ajax'] === 'models') {
        try { json_out(['ok' => true, 'models' => gemini_models()]); } catch (Throwable $e) { fail($e->getMessage()); }
    }
    admin_page();
}

function admin_action(string $a): void {
    $f = &$_SESSION['flash'];
    switch ($a) {
        case 'logout': $_SESSION = []; session_destroy(); return;
        case 'grant':
            $uid = (int)$_POST['uid'];
            if (!empty($_POST['unlimited'])) q("UPDATE nfw_users SET premium_unlimited=1 WHERE id=?", [$uid]);
            else add_days($uid, max(1, (int)$_POST['days']));
            $f = 'Premium otorgado'; return;
        case 'set_until':
            $ts = strtotime((string)$_POST['until'] . ' 23:59:59 UTC');
            q("UPDATE nfw_users SET premium_until=?, premium_unlimited=0 WHERE id=?", [$ts ?: 0, (int)$_POST['uid']]); $f = 'Fecha actualizada'; return;
        case 'revoke': q("UPDATE nfw_users SET premium_until=0, premium_unlimited=0 WHERE id=?", [(int)$_POST['uid']]); $f = 'Premium retirado'; return;
        case 'ban': q("UPDATE nfw_users SET banned=1-banned WHERE id=?", [(int)$_POST['uid']]); $f = 'Estado de bloqueo cambiado'; return;
        case 'deluser': q("DELETE FROM nfw_users WHERE id=?", [(int)$_POST['uid']]); $f = 'Usuario eliminado'; return;
        case 'newuser':
            $email = strtolower(trim((string)$_POST['email']));
            if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen((string)$_POST['password']) < 6) { $f = 'Correo o contraseña inválidos'; return; }
            q("INSERT INTO nfw_users (email,name,pass_hash,token,created_at) VALUES (?,?,?,?,?)", [$email, (string)$_POST['name'], password_hash((string)$_POST['password'], PASSWORD_DEFAULT), rand_token(), now()]);
            $id = (int)db()->lastInsertId();
            if ((int)($_POST['days'] ?? 0) > 0) add_days($id, (int)$_POST['days']);
            if (!empty($_POST['unlimited'])) q("UPDATE nfw_users SET premium_unlimited=1 WHERE id=?", [$id]);
            $f = 'Usuario creado'; return;
        case 'resetpass':
            if (strlen((string)$_POST['password']) < 6) { $f = 'Mínimo 6 caracteres'; return; }
            q("UPDATE nfw_users SET pass_hash=?, token=? WHERE id=?", [password_hash((string)$_POST['password'], PASSWORD_DEFAULT), rand_token(), (int)$_POST['uid']]); $f = 'Contraseña cambiada'; return;
        case 'saveplan':
            $vals = [mb_substr(trim((string)$_POST['name']), 0, 120), max(0, (int)$_POST['days']), max(0, (float)$_POST['price']),
                strtoupper(substr(preg_replace('/[^A-Za-z]/', '', (string)$_POST['currency']), 0, 3) ?: 'USD'), mb_substr((string)$_POST['description'], 0, 255),
                empty($_POST['active']) ? 0 : 1, (int)$_POST['sort']];
            if (!empty($_POST['id'])) q("UPDATE nfw_plans SET name=?,days=?,price=?,currency=?,description=?,active=?,sort=? WHERE id=?", array_merge($vals, [(int)$_POST['id']]));
            else q("INSERT INTO nfw_plans (name,days,price,currency,description,active,sort) VALUES (?,?,?,?,?,?,?)", $vals);
            $f = 'Plan guardado'; return;
        case 'delplan': q("DELETE FROM nfw_plans WHERE id=?", [(int)$_POST['id']]); $f = 'Plan eliminado'; return;
        case 'newtoken':
            q("INSERT INTO nfw_mcp_tokens (name,token,user_id,scope,created_at) VALUES (?,?,?,?,?)",
                [mb_substr(trim((string)$_POST['name']) ?: 'IA', 0, 120), 'nfw_' . rand_token(20), (int)$_POST['user_id'], in_array($_POST['scope'], ['read', 'full', 'admin'], true) ? $_POST['scope'] : 'read', now()]);
            $f = 'Token creado'; return;
        case 'deltoken': q("DELETE FROM nfw_mcp_tokens WHERE id=?", [(int)$_POST['id']]); $f = 'Token eliminado'; return;
        case 'sendcmd':
            $tool = (string)$_POST['tool'];
            if (!in_array($tool, array_column(DEVICE_TOOLS, 0), true)) { $f = 'Comando inválido'; return; }
            $args = json_decode((string)($_POST['args'] ?? '{}'), true) ?: [];
            queue_command((int)$_POST['device'], $tool, $args, 'panel');
            $f = 'Comando enviado; el teléfono lo ejecuta en segundos'; return;
        case 'settings':
            foreach (['paypal_client_id', 'paypal_email', 'paypal_mode', 'trial_days', 'gemini_model'] as $k) if (isset($_POST[$k])) set_setting($k, trim((string)$_POST[$k]));
            if (trim((string)($_POST['paypal_secret'] ?? '')) !== '') set_setting('paypal_secret', trim((string)$_POST['paypal_secret']));
            if (trim((string)($_POST['gemini_key'] ?? '')) !== '') set_setting('gemini_key', trim((string)$_POST['gemini_key']));
            $fs = array_values(array_intersect((array)($_POST['features'] ?? []), array_keys(NFW_FEATURES)));
            set_setting('premium_features', json_encode($fs));
            if (strlen((string)($_POST['newadmin'] ?? '')) >= 8) set_setting('admin_hash', password_hash((string)$_POST['newadmin'], PASSWORD_DEFAULT));
            $f = 'Ajustes guardados'; return;
    }
}

function admin_login(): void {
    page_head('Admin Nexus Firewall');
    echo '<div class="wrap narrow"><div class="card"><h1><span class="r">NEXUS</span> FIREWALL · Admin</h1>';
    if (!empty($_SESSION['flash'])) { echo '<div class="alert">' . h($_SESSION['flash']) . '</div>'; unset($_SESSION['flash']); }
    echo '<form method="post"><input type="hidden" name="act" value="login"><label>Contraseña</label><input type="password" name="password" autofocus><button class="btn">Entrar</button></form></div></div>';
    page_foot();
}

function form_open(string $act, string $tab): string {
    return '<form method="post" class="inline"><input type="hidden" name="csrf" value="' . h($_SESSION['csrf']) . '"><input type="hidden" name="act" value="' . h($act) . '"><input type="hidden" name="tab" value="' . h($tab) . '">';
}

function admin_page(): void {
    $tab = preg_replace('/[^a-z]/', '', (string)($_GET['tab'] ?? 'dash')) ?: 'dash';
    page_head('Admin Nexus Firewall');
    $tabs = ['dash' => '⚡ Resumen', 'users' => '👥 Usuarios', 'plans' => '💲 Planes', 'payments' => '💳 Pagos', 'devices' => '📱 Teléfonos', 'mcp' => '🤖 MCP / IA', 'settings' => '⚙ Ajustes'];
    echo '<header class="top"><div class="logo"><span class="r">NEXUS</span> FIREWALL</div><nav>';
    foreach ($tabs as $k => $v) echo '<a class="' . ($k === $tab ? 'on' : '') . '" href="?page=admin&tab=' . $k . '">' . $v . '</a>';
    echo '</nav>' . form_open('logout', 'dash') . '<button class="btn ghost sm">Salir</button></form></header><div class="wrap">';
    if (!empty($_SESSION['flash'])) { echo '<div class="ok">' . h($_SESSION['flash']) . '</div>'; unset($_SESSION['flash']); }

    if ($tab === 'dash') {
        $users = (int)q("SELECT COUNT(*) c FROM nfw_users")->fetch()['c'];
        $prem = (int)q("SELECT COUNT(*) c FROM nfw_users WHERE premium_unlimited=1 OR premium_until>?", [now()])->fetch()['c'];
        $dev = (int)q("SELECT COUNT(*) c FROM nfw_devices WHERE last_seen>?", [now() - 60])->fetch()['c'];
        $inc = q("SELECT currency, SUM(amount) s FROM nfw_payments WHERE status='COMPLETED' GROUP BY currency")->fetchAll();
        echo '<div class="grid">';
        foreach ([['Usuarios', $users], ['Premium activos', $prem], ['Teléfonos en línea', $dev]] as [$l, $v]) echo '<div class="card stat"><div class="muted">' . $l . '</div><div class="big">' . $v . '</div></div>';
        echo '<div class="card stat"><div class="muted">Ingresos</div><div class="big">' . ($inc ? implode('<br>', array_map(fn($r) => number_format((float)$r['s'], 2) . ' ' . h($r['currency']), $inc)) : '0') . '</div></div></div>';
        echo '<div class="card"><h2>Enlaces</h2><p>URL del servidor para la app:<br><code>' . h(self_url()) . '</code></p><p>URL MCP para tus IA:<br><code>' . h(self_url()) . '?mcp=1</code> (con cabecera <code>Authorization: Bearer TOKEN</code>)</p>';
        $miss = [];
        if (!setting('paypal_client_id') || !setting('paypal_secret')) $miss[] = 'PayPal (Ajustes)';
        if (!q("SELECT id FROM nfw_plans WHERE active=1 LIMIT 1")->fetch()) $miss[] = 'al menos un plan (Planes)';
        if ($miss) echo '<div class="alert">Falta configurar: ' . h(implode(', ', $miss)) . '</div>';
        echo '</div>';
    }

    if ($tab === 'users') {
        $s = trim((string)($_GET['s'] ?? ''));
        echo '<div class="card"><h2>Usuarios</h2><form method="get" class="row"><input type="hidden" name="page" value="admin"><input type="hidden" name="tab" value="users"><input name="s" placeholder="Buscar correo o nombre" value="' . h($s) . '"><button class="btn sm">Buscar</button></form>';
        $rows = q("SELECT * FROM nfw_users WHERE email LIKE ? OR name LIKE ? ORDER BY id DESC LIMIT 300", ["%$s%", "%$s%"])->fetchAll();
        echo '<div class="table"><table><tr><th>Usuario</th><th>Estado</th><th>Dar Premium</th><th>Acciones</th></tr>';
        foreach ($rows as $u) {
            $st = (int)$u['premium_unlimited'] === 1 ? '<span class="badge">👑 ILIMITADO</span>' : ((int)$u['premium_until'] > now() ? '<span class="badge">👑 hasta ' . gmdate('d/m/Y', (int)$u['premium_until']) . '</span>' : '<span class="muted">Gratis</span>');
            if ((int)$u['banned'] === 1) $st .= ' <span class="badge red">SUSPENDIDO</span>';
            echo '<tr><td><b>' . h($u['email']) . '</b><br><span class="muted">' . h($u['name']) . ' · #' . $u['id'] . ' · visto ' . ($u['last_seen'] ? gmdate('d/m H:i', (int)$u['last_seen']) : '-') . '</span></td><td>' . $st . '</td><td>';
            echo form_open('grant', 'users') . '<input type="hidden" name="uid" value="' . $u['id'] . '"><input name="days" type="number" min="1" value="30" class="xs"> días <label class="chk"><input type="checkbox" name="unlimited" value="1"> ilimitado</label><button class="btn sm">Dar</button></form>';
            echo form_open('set_until', 'users') . '<input type="hidden" name="uid" value="' . $u['id'] . '"><input type="date" name="until" class="xs2"><button class="btn ghost sm">Fijar fecha</button></form></td><td>';
            echo form_open('revoke', 'users') . '<input type="hidden" name="uid" value="' . $u['id'] . '"><button class="btn ghost sm">Quitar premium</button></form>';
            echo form_open('ban', 'users') . '<input type="hidden" name="uid" value="' . $u['id'] . '"><button class="btn ghost sm">' . ((int)$u['banned'] ? 'Reactivar' : 'Suspender') . '</button></form>';
            echo form_open('resetpass', 'users') . '<input type="hidden" name="uid" value="' . $u['id'] . '"><input name="password" placeholder="nueva clave" class="xs2"><button class="btn ghost sm">Cambiar clave</button></form>';
            echo form_open('deluser', 'users') . '<input type="hidden" name="uid" value="' . $u['id'] . '"><button class="btn ghost sm" onclick="return confirm(\'¿Eliminar usuario?\')">Eliminar</button></form></td></tr>';
        }
        echo '</table></div></div>';
        echo '<div class="card"><h2>Crear usuario</h2>' . form_open('newuser', 'users') . '<div class="grid2"><input name="email" placeholder="correo"><input name="name" placeholder="nombre"><input name="password" placeholder="contraseña"><input name="days" type="number" placeholder="días premium (0 = gratis)"></div><label class="chk"><input type="checkbox" name="unlimited" value="1"> Premium ilimitado</label><button class="btn">Crear</button></form></div>';
    }

    if ($tab === 'plans') {
        echo '<div class="card"><h2>Planes y precios</h2><p class="muted">Días = 0 significa Premium para siempre. Los pagos llegan a: <b>' . h(setting('paypal_email', 'larchss21@gmail.com')) . '</b></p>';
        $plans = q("SELECT * FROM nfw_plans ORDER BY sort, price")->fetchAll();
        $plans[] = ['id' => '', 'name' => '', 'days' => 30, 'price' => '', 'currency' => 'USD', 'description' => '', 'active' => 1, 'sort' => 0];
        foreach ($plans as $p) {
            echo '<div class="plan">' . form_open('saveplan', 'plans') . '<input type="hidden" name="id" value="' . h($p['id']) . '"><div class="grid2">
            <input name="name" placeholder="Nombre (ej. Mensual)" value="' . h($p['name']) . '" required>
            <input name="days" type="number" min="0" placeholder="Días" value="' . h($p['days']) . '">
            <input name="price" type="number" step="0.01" min="0" placeholder="Precio" value="' . h($p['price']) . '" required>
            <input name="currency" placeholder="Moneda (USD, MXN…)" value="' . h($p['currency']) . '">
            <input name="description" placeholder="Descripción" value="' . h($p['description']) . '">
            <input name="sort" type="number" placeholder="Orden" value="' . h($p['sort']) . '"></div>
            <label class="chk"><input type="checkbox" name="active" value="1" ' . ((int)$p['active'] ? 'checked' : '') . '> Activo</label>
            <button class="btn sm">' . ($p['id'] ? 'Guardar' : '➕ Agregar plan') . '</button></form>';
            if ($p['id']) echo form_open('delplan', 'plans') . '<input type="hidden" name="id" value="' . h($p['id']) . '"><button class="btn ghost sm" onclick="return confirm(\'¿Eliminar plan?\')">Eliminar</button></form>';
            echo '</div>';
        }
        echo '</div>';
    }

    if ($tab === 'payments') {
        $rows = q("SELECT p.*, u.email, pl.name plan FROM nfw_payments p LEFT JOIN nfw_users u ON u.id=p.user_id LEFT JOIN nfw_plans pl ON pl.id=p.plan_id ORDER BY p.id DESC LIMIT 300")->fetchAll();
        echo '<div class="card"><h2>Pagos</h2><div class="table"><table><tr><th>Fecha</th><th>Usuario</th><th>Plan</th><th>Monto</th><th>Estado</th><th>Pagador</th><th>Orden</th></tr>';
        foreach ($rows as $r) echo '<tr><td>' . gmdate('d/m/Y H:i', (int)$r['created_at']) . '</td><td>' . h($r['email']) . '</td><td>' . h($r['plan']) . ' (' . ((int)$r['days'] ?: '∞') . ' d)</td><td>' . h($r['amount'] . ' ' . $r['currency']) . '</td><td>' . ($r['status'] === 'COMPLETED' ? '<span class="badge">COMPLETADO</span>' : h($r['status'])) . '</td><td>' . h($r['payer_email']) . '</td><td><code>' . h($r['order_id']) . '</code></td></tr>';
        echo '</table></div></div>';
    }

    if ($tab === 'devices') {
        $rows = q("SELECT d.*, u.email FROM nfw_devices d JOIN nfw_users u ON u.id=d.user_id ORDER BY last_seen DESC LIMIT 200")->fetchAll();
        echo '<div class="card"><h2>Teléfonos vinculados</h2>';
        if (!$rows) echo '<p class="muted">Aún no hay teléfonos. En la app: Cuenta › entrar, y en IA/MCP › “Activar control remoto”.</p>';
        foreach ($rows as $d) {
            $st = json_decode((string)$d['state'], true) ?: [];
            $on = (now() - (int)$d['last_seen']) < 40;
            echo '<div class="plan"><b>' . h($d['model'] ?: 'Teléfono') . '</b> · ' . h($d['email']) . ' · ' . ($on ? '<span class="badge">EN LÍNEA</span>' : '<span class="muted">visto ' . gmdate('d/m H:i', (int)$d['last_seen']) . '</span>') . '<br>';
            echo '<span class="muted">Firewall: ' . (!empty($st['firewall_activo']) ? 'activo' : 'apagado') . ' · consultas ' . (int)($st['consultas_totales'] ?? 0) . ' · bloqueadas ' . (int)($st['bloqueadas_totales'] ?? 0) . '</span><br>';
            echo form_open('sendcmd', 'devices') . '<input type="hidden" name="device" value="' . $d['id'] . '"><select name="tool">';
            foreach (DEVICE_TOOLS as $t) echo '<option value="' . h($t[0]) . '">' . h($t[0] . ' — ' . $t[1]) . '</option>';
            echo '</select><input name="args" placeholder=\'{"domain":"ejemplo.com"}\' class="xs3"><button class="btn sm">Enviar</button></form>';
            $last = q("SELECT * FROM nfw_commands WHERE device_row=? ORDER BY id DESC LIMIT 5", [$d['id']])->fetchAll();
            foreach ($last as $c) echo '<div class="muted small">#' . $c['id'] . ' ' . h($c['tool']) . ' · ' . h($c['status']) . ' · ' . h($c['source']) . ($c['result'] ? ' → <code>' . h(mb_substr((string)$c['result'], 0, 160)) . '</code>' : '') . '</div>';
            echo '</div>';
        }
        echo '</div>';
    }

    if ($tab === 'mcp') {
        echo '<div class="card"><h2>Conectar tus IA por MCP</h2><p>URL: <code>' . h(self_url()) . '?mcp=1</code></p>
        <p class="muted">Crea un token por cada IA. <b>Lectura</b>: solo consulta. <b>Total</b>: controla el firewall. <b>Admin</b>: además administra usuarios, premium, planes y pagos (proyecto completo).</p>';
        $toks = q("SELECT t.*, u.email FROM nfw_mcp_tokens t LEFT JOIN nfw_users u ON u.id=t.user_id ORDER BY t.id DESC")->fetchAll();
        echo '<div class="table"><table><tr><th>IA</th><th>Permiso</th><th>Teléfonos de</th><th>Token</th><th></th></tr>';
        foreach ($toks as $t) {
            $cfg = json_encode(['mcpServers' => ['nexus-firewall' => ['type' => 'http', 'url' => self_url() . '?mcp=1', 'headers' => ['Authorization' => 'Bearer ' . $t['token']]]]], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            echo '<tr><td><b>' . h($t['name']) . '</b><br><span class="muted small">usado ' . ($t['last_used'] ? gmdate('d/m H:i', (int)$t['last_used']) : 'nunca') . '</span></td><td>' . h($t['scope']) . '</td><td>' . h($t['email'] ?: ($t['scope'] === 'admin' ? 'todos' : '-')) . '</td><td><code class="tok">' . h($t['token']) . '</code><details><summary>Config JSON</summary><pre>' . h($cfg) . '</pre></details></td><td>' . form_open('deltoken', 'mcp') . '<input type="hidden" name="id" value="' . $t['id'] . '"><button class="btn ghost sm">Borrar</button></form></td></tr>';
        }
        echo '</table></div>';
        $users = q("SELECT id,email FROM nfw_users ORDER BY email")->fetchAll();
        echo '<h3>Nuevo token</h3>' . form_open('newtoken', 'mcp') . '<div class="grid2"><input name="name" placeholder="Nombre de la IA (Claude, Gemini…)"><select name="scope"><option value="full">Total (controla firewall)</option><option value="read">Solo lectura</option><option value="admin">Admin (todo el proyecto)</option></select><select name="user_id"><option value="0">— Todos (solo admin) —</option>';
        foreach ($users as $u) echo '<option value="' . $u['id'] . '">' . h($u['email']) . '</option>';
        echo '</select></div><button class="btn">Crear token</button></form></div>';
    }

    if ($tab === 'settings') {
        $pf = premium_features();
        echo '<div class="card">' . form_open('settings', 'settings') . '<h2>Gratis / Premium</h2><p class="muted">Marca qué funciones son Premium. Las que no marques son gratis para todos.</p><div class="grid2">';
        foreach (NFW_FEATURES as $k => $l) echo '<label class="chk"><input type="checkbox" name="features[]" value="' . $k . '" ' . (in_array($k, $pf, true) ? 'checked' : '') . '> ' . h($l) . '</label>';
        echo '</div><label>Días de prueba premium al registrarse (0 = sin prueba)</label><input name="trial_days" type="number" min="0" value="' . h(setting('trial_days', '0')) . '">
        <h2>PayPal</h2><p class="muted">Crea una app en developer.paypal.com (cuenta ' . h(setting('paypal_email', 'larchss21@gmail.com')) . '), copia Client ID y Secret. El secreto nunca sale del servidor.</p>
        <label>Correo PayPal que recibe los pagos</label><input name="paypal_email" value="' . h(setting('paypal_email', 'larchss21@gmail.com')) . '">
        <label>Client ID</label><input name="paypal_client_id" value="' . h(setting('paypal_client_id')) . '">
        <label>Secret ' . (setting('paypal_secret') ? '(guardado — déjalo vacío para conservarlo)' : '') . '</label><input name="paypal_secret" type="password">
        <label>Modo</label><select name="paypal_mode"><option value="live" ' . (setting('paypal_mode') === 'live' ? 'selected' : '') . '>Real (live)</option><option value="sandbox" ' . (setting('paypal_mode') === 'sandbox' ? 'selected' : '') . '>Pruebas (sandbox)</option></select>
        <h2>IA (Gemini)</h2>
        <label>Clave API de Gemini ' . (setting('gemini_key') ? '(guardada — vacío para conservarla)' : '') . '</label><input name="gemini_key" type="password">
        <label>Modelo</label><div class="row"><select name="gemini_model" id="gm"><option value="' . h(setting('gemini_model')) . '">' . h(setting('gemini_model') ?: '— carga los modelos —') . '</option></select><button type="button" class="btn ghost sm" onclick="loadModels()">Cargar modelos de mi cuenta</button></div><div id="gmmsg" class="muted small"></div>
        <h2>Seguridad</h2><label>Nueva contraseña de administrador (vacío = no cambiar)</label><input name="newadmin" type="password">
        <button class="btn">Guardar ajustes</button></form></div>
        <script>async function loadModels(){const m=document.getElementById("gmmsg");m.textContent="Cargando…";try{const r=await fetch("?page=admin&ajax=models");const j=await r.json();if(!j.ok)throw new Error(j.error);const s=document.getElementById("gm"),cur=s.value;s.innerHTML="";j.models.forEach(x=>{const o=document.createElement("option");o.value=x.name;o.textContent=x.label+" ("+x.name+")";if(x.name===cur)o.selected=true;s.appendChild(o)});m.textContent=j.models.length+" modelos. Guarda para aplicar."}catch(e){m.textContent="Error: "+e.message}}</script>';
    }
    echo '</div>';
    page_foot();
}

/* ============================================================ estilos */
function page_head(string $t): void {
    echo '<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' . h($t) . '</title><style>
    :root{--bg:#0a0a0a;--card:#161616;--red:#e10600;--txt:#f5f5f5;--mut:#9a9a9a;--line:#2a2a2a}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
    .wrap{max-width:1150px;margin:0 auto;padding:16px}.narrow{max-width:480px}
    .card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;margin:12px 0}
    h1{font-size:22px;margin:0 0 12px}h2{font-size:18px;color:var(--red);margin:18px 0 8px}h3{margin:16px 0 8px}
    .r{color:var(--red)}.muted{color:var(--mut)}.small{font-size:12px}.big{font-size:28px;font-weight:800}
    input,select{width:100%;background:#0d0d0d;color:var(--txt);border:1px solid var(--line);border-radius:10px;padding:10px;margin:4px 0 8px;font-size:14px}
    label{display:block;margin-top:6px;color:var(--mut);font-size:13px}.chk{display:flex;gap:8px;align-items:center;color:var(--txt)}.chk input{width:auto;margin:0}
    .btn{background:var(--red);color:#fff;border:0;border-radius:10px;padding:10px 16px;font-weight:700;cursor:pointer;margin:4px 4px 4px 0}
    .btn.ghost{background:transparent;border:1px solid var(--red);color:var(--red)}.btn.sm{padding:6px 10px;font-size:12px}
    .alert{background:#3a0a0a;border:1px solid var(--red);padding:10px;border-radius:10px;margin:8px 0}.ok{background:#0a2a12;border:1px solid #1db954;padding:10px;border-radius:10px;margin:8px 0}
    .badge{background:var(--red);color:#fff;border-radius:999px;padding:2px 8px;font-size:11px;font-weight:700}.badge.red{background:#600}
    .top{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg);z-index:5}
    .logo{font-weight:900;font-size:20px}nav{display:flex;flex-wrap:wrap;gap:6px}nav a{color:var(--mut);text-decoration:none;padding:6px 12px;border-radius:999px;background:var(--card);font-size:13px}nav a.on{background:var(--red);color:#fff}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px}
    .stat{margin:0}.table{overflow-x:auto}table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top;font-size:13px}
    form.inline{display:inline-block;margin:2px 0}.xs{width:70px;display:inline-block}.xs2{width:140px;display:inline-block}.xs3{width:220px;display:inline-block}
    .row{display:flex;gap:8px;align-items:center}.plan{border:1px solid var(--line);border-radius:12px;padding:12px;margin:8px 0}
    code{background:#0d0d0d;padding:2px 6px;border-radius:6px;word-break:break-all}.tok{font-size:11px}pre{white-space:pre-wrap;font-size:11px;background:#0d0d0d;padding:8px;border-radius:8px}
    #pp{margin-top:16px}@media(max-width:640px){.xs3{width:100%}.top{position:static}}
    </style></head><body>';
}
function page_foot(): void { echo '<p class="muted small" style="text-align:center;padding:20px">Nexus Firewall Server ' . NFW_VERSION . '</p></body></html>'; }
