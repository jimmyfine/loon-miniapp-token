/*
 * Loon http-response 脚本：提取小程序接口中的 token。
 * 只读取响应，始终 $done({})，不改写任何流量。
 * 目标域名在插件 [Mitm] 中配置；行为在 CONFIG 中调整。
 */

var CONFIG = {
  webhook: "",
  extraKeys: [],
  minTokenLength: 16,
  maxTokenLength: 4096,
  notifyAll: false,
  notifyOnChangeOnly: true,
  captureRequestHeaders: true,
  showFullToken: false,
  storeKey: "miniapp_token_store",
  maxRecords: 80,
  debug: false
};

var EXCLUDED_KEYS = {
  tokentype: 1, tokenexpire: 1, tokenexpires: 1, tokenexpiresin: 1, tokenexpireat: 1,
  tokenttl: 1, tokenvalidity: 1, tokenurl: 1, tokenuri: 1, tokenprefix: 1,
  tokenheader: 1, tokenname: 1, tokenlength: 1, tokenlen: 1, tokencount: 1,
  tokenscount: 1, tokenlimit: 1, tokenamount: 1, tokenbalance: 1, tokenpolicy: 1,
  tokenpermissions: 1
};

var TOKEN_HEADERS = [
  "authorization", "token", "access-token", "access_token",
  "x-token", "x-auth-token", "x-access-token", "jwt"
];

var finished = false;

function finish() {
  if (finished) return;
  finished = true;
  $done({});
}

function debugLog() {
  if (!CONFIG.debug || typeof console === "undefined") return;
  var parts = [];
  for (var i = 0; i < arguments.length; i++) {
    var item = arguments[i];
    parts.push(typeof item === "string" ? item : JSON.stringify(item));
  }
  console.log("[miniapp-token] " + parts.join(" "));
}

function nowMs() {
  return Date.now();
}

function getHost(url) {
  var match = /^https?:\/\/([^\/:?#]+)/i.exec(url || "");
  return match ? match[1].toLowerCase() : "";
}

function normalizeKey(key) {
  return String(key).toLowerCase().replace(/[^a-z0-9]/g, "");
}

function isWantedKey(key) {
  var name = normalizeKey(key);
  if (!name || EXCLUDED_KEYS[name]) return false;
  if (name === "jwt") return true;
  for (var i = 0; i < CONFIG.extraKeys.length; i++) {
    if (normalizeKey(CONFIG.extraKeys[i]) === name) return true;
  }
  return name.indexOf("token") >= 0;
}

function cleanToken(value) {
  var text = String(value).trim();
  var match = /^bearer\s+(.+)$/i.exec(text);
  if (match) text = match[1].trim();
  return text;
}

function looksLikeToken(value) {
  if (typeof value !== "string") return false;
  var text = value.trim();
  if (text.length < CONFIG.minTokenLength || text.length > CONFIG.maxTokenLength) return false;
  if (/[\s"'<>]/.test(text)) return false;
  if (/^https?:\/\//i.test(text)) return false;
  if (!/^[A-Za-z0-9\-._~+\/=%:@!#$^]+$/.test(text)) return false;
  var lower = text.toLowerCase();
  if (lower === "undefined" || lower === "null" || lower === "true" ||
      lower === "false" || lower === "none" || lower === "bearer" ||
      lower === "your_token") return false;
  return true;
}

function isJwt(value) {
  return /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}$/.test(value);
}

function getHeader(headers, name) {
  if (!headers) return "";
  for (var key in headers) {
    if (Object.prototype.hasOwnProperty.call(headers, key) && key.toLowerCase() === name) {
      return headers[key];
    }
  }
  return "";
}

function addHit(hits, key, value, source) {
  hits.push({ key: String(key), value: value, source: source });
}

function collectHeaders(headers, label, hits) {
  if (!headers || typeof headers !== "object") return;
  for (var name in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, name)) continue;
    if (TOKEN_HEADERS.indexOf(name.toLowerCase()) < 0) continue;
    var raw = headers[name];
    if (raw === null || typeof raw === "undefined") continue;
    var value = cleanToken(raw);
    if (looksLikeToken(value)) addHit(hits, name, value, label);
  }
}

function collectUrl(url, hits) {
  var index = url.indexOf("?");
  if (index < 0) return;
  var pairs = url.slice(index + 1).split("&");
  for (var i = 0; i < pairs.length; i++) {
    var eq = pairs[i].indexOf("=");
    if (eq < 0) continue;
    var key = pairs[i].slice(0, eq);
    var raw = pairs[i].slice(eq + 1);
    try { key = decodeURIComponent(key); } catch (e) {}
    try { raw = decodeURIComponent(raw); } catch (e2) {}
    if (!isWantedKey(key)) continue;
    var value = cleanToken(raw);
    if (looksLikeToken(value)) addHit(hits, key, value, "URL 参数");
  }
}

function collectForm(body, hits) {
  var pairs = body.split("&");
  for (var i = 0; i < pairs.length; i++) {
    var eq = pairs[i].indexOf("=");
    if (eq < 0) continue;
    var key = pairs[i].slice(0, eq);
    var raw = pairs[i].slice(eq + 1);
    try { key = decodeURIComponent(key.replace(/\+/g, " ")); } catch (e) {}
    try { raw = decodeURIComponent(raw.replace(/\+/g, " ")); } catch (e2) {}
    if (!isWantedKey(key)) continue;
    var value = cleanToken(raw);
    if (looksLikeToken(value)) addHit(hits, key, value, "响应体");
  }
}

function collectJson(node, hits, depth, counter) {
  if (depth > 8 || counter.count > 20000) return;
  counter.count++;
  if (Array.isArray(node)) {
    for (var i = 0; i < node.length; i++) collectJson(node[i], hits, depth + 1, counter);
    return;
  }
  if (!node || typeof node !== "object") return;
  for (var key in node) {
    if (!Object.prototype.hasOwnProperty.call(node, key)) continue;
    var value = node[key];
    if (typeof value === "string") {
      if (!isWantedKey(key)) continue;
      var token = cleanToken(value);
      if (looksLikeToken(token)) addHit(hits, key, token, "响应体");
    } else if (value && typeof value === "object") {
      collectJson(value, hits, depth + 1, counter);
    }
  }
}

function collectBody(response, hits) {
  var body = response.body;
  if (typeof body !== "string" || !body) return;
  if (body.length > 1048576) body = body.slice(0, 1048576);
  var text = body.trim();
  if (!text) return;
  var data = null;
  try { data = JSON.parse(text); } catch (e) {}
  if (!data || typeof data !== "object") {
    var jsonp = /^[\w$.]+\s*\(([\s\S]*)\)\s*;?$/.exec(text);
    if (jsonp) {
      try { data = JSON.parse(jsonp[1]); } catch (e2) {}
    }
  }
  if (data && typeof data === "object") {
    collectJson(data, hits, 0, { count: 0 });
    return;
  }
  var contentType = String(getHeader(response.headers, "content-type") || "").toLowerCase();
  if (contentType.indexOf("x-www-form-urlencoded") >= 0) collectForm(text, hits);
}

function uniqueHits(hits) {
  var seen = {};
  var result = [];
  for (var i = 0; i < hits.length; i++) {
    var id = normalizeKey(hits[i].key) + "|" + hits[i].value;
    if (seen[id]) continue;
    seen[id] = 1;
    result.push(hits[i]);
  }
  return result;
}

function scoreHit(hit) {
  var key = normalizeKey(hit.key);
  var score = 0;
  if (key === "accesstoken") score += 30;
  else if (key === "token") score += 25;
  else if (key === "authtoken" || key === "idtoken") score += 24;
  else if (key === "jwt") score += 22;
  else if (key === "refreshtoken") score += 10;
  else if (key.indexOf("token") >= 0) score += 15;
  if (isJwt(hit.value)) score += 12;
  if (hit.source === "请求头" || hit.source === "响应头") score += 5;
  return score;
}

function loadStore() {
  try {
    var raw = $persistentStore.read(CONFIG.storeKey);
    if (raw) {
      var parsed = JSON.parse(raw);
      if (parsed && parsed.items && typeof parsed.items === "object") return parsed;
    }
  } catch (e) {}
  return { v: 1, items: {} };
}

function saveStore(store) {
  try {
    var keys = Object.keys(store.items);
    if (keys.length > CONFIG.maxRecords) {
      keys.sort(function (a, b) { return store.items[a].ts - store.items[b].ts; });
      for (var i = 0; i < keys.length - CONFIG.maxRecords; i++) delete store.items[keys[i]];
    }
    $persistentStore.write(JSON.stringify(store), CONFIG.storeKey);
  } catch (e) {
    debugLog("store failed", String(e));
  }
}

function maskToken(value) {
  if (value.length <= 24) return value.slice(0, 4) + "…";
  return value.slice(0, 8) + "…" + value.slice(-6);
}

function notifyHits(host, fresh, picked) {
  for (var i = 0; i < picked.length; i++) {
    var hit = picked[i];
    var text = CONFIG.showFullToken ? hit.value : maskToken(hit.value);
    text += " · " + hit.value.length + " 字符";
    if (i === 0 && fresh.length > picked.length) {
      text += " · 另 " + (fresh.length - picked.length) + " 项";
    }
    if (!CONFIG.showFullToken) text += " · 点按复制";
    $notification.post("小程序 Token", host + " · " + hit.key, text, { clipboard: hit.value });
  }
}

function postWebhook(host, url, response, fresh) {
  if (!CONFIG.webhook) {
    finish();
    return;
  }
  var tokens = [];
  for (var i = 0; i < fresh.length; i++) {
    tokens.push({ field: fresh[i].key, value: fresh[i].value, source: fresh[i].source });
  }
  var payload = {
    source: "loon-miniapp-token",
    time: new Date().toISOString(),
    host: host,
    url: url,
    status: response && typeof response.status !== "undefined" ? response.status : null,
    tokens: tokens
  };
  try {
    $httpClient.post({
      url: CONFIG.webhook,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      timeout: 3000
    }, function (error, res) {
      if (error) {
        $notification.post("小程序 Token", "Webhook 发送失败", String(error));
      } else if (!res || res.status < 200 || res.status >= 300) {
        $notification.post("小程序 Token", "Webhook 发送失败", "HTTP " + (res ? res.status : "?"));
      }
      finish();
    });
  } catch (e) {
    debugLog("webhook failed", String(e));
    finish();
  }
}

function main() {
  var request = $request || {};
  var response = typeof $response !== "undefined" && $response ? $response : null;
  var url = request.url || "";
  var host = getHost(url);
  if (!host) {
    finish();
    return;
  }

  var hits = [];
  collectUrl(url, hits);
  if (CONFIG.captureRequestHeaders) collectHeaders(request.headers, "请求头", hits);
  if (response) {
    collectHeaders(response.headers, "响应头", hits);
    collectBody(response, hits);
  }

  hits = uniqueHits(hits);
  if (!hits.length) {
    finish();
    return;
  }
  hits.sort(function (a, b) { return scoreHit(b) - scoreHit(a); });
  debugLog("hits", hits.map(function (hit) { return hit.key; }));

  var store = loadStore();
  var fresh = [];
  for (var i = 0; i < hits.length; i++) {
    var hit = hits[i];
    var id = host + "|" + normalizeKey(hit.key);
    var previous = store.items[id];
    store.items[id] = {
      value: hit.value,
      field: hit.key,
      host: host,
      url: url,
      source: hit.source,
      ts: nowMs()
    };
    if (!previous || previous.value !== hit.value) fresh.push(hit);
  }
  saveStore(store);

  if (!fresh.length && CONFIG.notifyOnChangeOnly) {
    finish();
    return;
  }
  if (!fresh.length) fresh = hits.slice(0, 1);

  var picked = fresh.slice(0, CONFIG.notifyAll ? 3 : 1);
  notifyHits(host, fresh, picked);
  postWebhook(host, url, response, fresh);
}

try {
  main();
} catch (error) {
  debugLog("script error", String(error));
  finish();
}
