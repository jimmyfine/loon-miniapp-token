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
  hostAllowlist: [],
  debug: false
};

var STATIC_URL_RE = /\.(?:png|jpe?g|gif|webp|svg|ico|css|woff2?|ttf|otf|eot|mp4|m4a|mp3|wav|ogg|webm|zip|gz|rar|7z|pdf|apk|ipa|dmg)(?:[?#]|$)/i;

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

function hostAllowed(host) {
  if (!CONFIG.hostAllowlist.length) return true;
  for (var i = 0; i < CONFIG.hostAllowlist.length; i++) {
    var pattern = String(CONFIG.hostAllowlist[i]).toLowerCase();
    if (!pattern) continue;
    if (pattern === "*" || pattern === host) return true;
    if (pattern.indexOf("*.") === 0) {
      var suffix = pattern.slice(1);
      if (host.length > suffix.length && host.slice(-suffix.length) === suffix) return true;
    }
  }
  return false;
}

function isInternalHost(host) {
  return /(^|\.)(?:weixin\.qq\.com|wxs\.qq\.com)$/.test(host);
}

function isStaticUrl(url) {
  return STATIC_URL_RE.test(url);
}

function parsePlainArguments(text) {
  var result = {};
  var pairs = String(text).split("&");
  for (var i = 0; i < pairs.length; i++) {
    var eq = pairs[i].indexOf("=");
    if (eq < 0) {
      if (pairs[i]) result[pairs[i]] = "";
      continue;
    }
    var key = pairs[i].slice(0, eq);
    var value = pairs[i].slice(eq + 1);
    try { key = decodeURIComponent(key); } catch (e) {}
    try { value = decodeURIComponent(value); } catch (e2) {}
    if (key) result[key] = value;
  }
  return result;
}

function applyArguments() {
  var args = typeof $argument !== "undefined" ? $argument : null;
  if (!args) return;
  if (typeof args === "string") {
    var text = args.trim();
    if (text.charAt(0) === "{") {
      try { args = JSON.parse(text); } catch (e) { return; }
    } else {
      args = parsePlainArguments(text);
    }
  }
  if (!args || typeof args !== "object") return;
  if (typeof args.hostAllowlist !== "undefined") {
    var raw = String(args.hostAllowlist).trim();
    var list = [];
    if (raw && raw !== "*") {
      var parts = raw.split(/[\s,;]+/);
      for (var i = 0; i < parts.length; i++) {
        if (parts[i]) list.push(parts[i].toLowerCase());
      }
    }
    CONFIG.hostAllowlist = list;
  }
  if (typeof args.debug !== "undefined") {
    CONFIG.debug = String(args.debug).toLowerCase() === "true";
  }
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

function isByteArray(value) {
  if (!value || typeof value !== "object") return false;
  if (typeof Uint8Array !== "undefined" && value instanceof Uint8Array) return true;
  if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) return true;
  return typeof value.byteLength === "number" && typeof value.length === "number" && !Array.isArray(value);
}

function toBytes(value) {
  if (!value || typeof value !== "object") return null;
  if (typeof Uint8Array !== "undefined" && value instanceof Uint8Array) return value;
  if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) return new Uint8Array(value);
  return typeof value.length === "number" ? value : null;
}

function sliceBytes(bytes, limit) {
  if (typeof bytes.subarray === "function") return bytes.subarray(0, limit);
  if (typeof bytes.slice === "function") return bytes.slice(0, limit);
  var result = [];
  for (var i = 0; i < limit && i < bytes.length; i++) result.push(bytes[i]);
  return result;
}

function isTextualContentType(contentType) {
  var text = String(contentType || "").toLowerCase();
  if (!text) return false;
  return text.indexOf("json") >= 0 || text.indexOf("text/") >= 0 ||
    text.indexOf("javascript") >= 0 || text.indexOf("xml") >= 0 ||
    text.indexOf("x-www-form-urlencoded") >= 0 || text.indexOf("graphql") >= 0;
}

function isBinaryContentType(contentType) {
  var text = String(contentType || "").toLowerCase();
  if (!text) return false;
  return /^(?:image|audio|video|font)\//.test(text) ||
    text.indexOf("octet-stream") >= 0 || text.indexOf("protobuf") >= 0 ||
    text.indexOf("msgpack") >= 0 || text.indexOf("pdf") >= 0 ||
    text.indexOf("zip") >= 0;
}

function bodyLooksTextual(bytes, contentType) {
  if (isBinaryContentType(contentType)) return false;
  var scan = Math.min(bytes.length, 64);
  var index = 0;
  while (index < scan) {
    var b = bytes[index] & 255;
    if (b === 0) return false;
    if (b === 9 || b === 10 || b === 13 || b === 32) {
      index++;
      continue;
    }
    break;
  }
  if (index >= bytes.length) return false;
  if (isTextualContentType(contentType)) return true;
  var head = bytes[index] & 255;
  return head === 0x7b || head === 0x5b || head === 0x22;
}

function codePointsToString(points) {
  var out = "";
  var chunk = [];
  for (var i = 0; i < points.length; i++) {
    var cp = points[i];
    if (cp > 0xffff) {
      cp -= 0x10000;
      chunk.push(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
    } else {
      chunk.push(cp);
    }
    if (chunk.length >= 2048) {
      out += String.fromCharCode.apply(null, chunk);
      chunk = [];
    }
  }
  if (chunk.length) out += String.fromCharCode.apply(null, chunk);
  return out;
}

function decodeUtf8(bytes) {
  var points = [];
  var length = bytes.length;
  var i = 0;
  while (i < length) {
    var b0 = bytes[i] & 255;
    if (b0 < 0x80) {
      points.push(b0);
      i++;
      continue;
    }
    if (b0 >= 0xc2 && b0 <= 0xdf) {
      var b1 = i + 1 < length ? bytes[i + 1] & 255 : -1;
      if (b1 >= 0x80 && b1 <= 0xbf) {
        points.push(((b0 & 0x1f) << 6) | (b1 & 0x3f));
        i += 2;
        continue;
      }
    } else if (b0 >= 0xe0 && b0 <= 0xef) {
      var b2 = i + 1 < length ? bytes[i + 1] & 255 : -1;
      var b3 = i + 2 < length ? bytes[i + 2] & 255 : -1;
      if (b2 >= 0x80 && b2 <= 0xbf && b3 >= 0x80 && b3 <= 0xbf) {
        var cp3 = ((b0 & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f);
        if (cp3 >= 0x800) {
          points.push(cp3);
          i += 3;
          continue;
        }
      }
    } else if (b0 >= 0xf0 && b0 <= 0xf4) {
      var b4 = i + 1 < length ? bytes[i + 1] & 255 : -1;
      var b5 = i + 2 < length ? bytes[i + 2] & 255 : -1;
      var b6 = i + 3 < length ? bytes[i + 3] & 255 : -1;
      if (b4 >= 0x80 && b4 <= 0xbf && b5 >= 0x80 && b5 <= 0xbf && b6 >= 0x80 && b6 <= 0xbf) {
        var cp4 = ((b0 & 0x07) << 18) | ((b4 & 0x3f) << 12) | ((b5 & 0x3f) << 6) | (b6 & 0x3f);
        if (cp4 >= 0x10000 && cp4 <= 0x10ffff) {
          points.push(cp4);
          i += 4;
          continue;
        }
      }
    }
    points.push(0xfffd);
    i++;
  }
  return codePointsToString(points);
}

function collectBody(response, hits) {
  var body = response.body;
  if (body === null || typeof body === "undefined") return;
  var contentType = String(getHeader(response.headers, "content-type") || "");
  if (isByteArray(body)) {
    var bytes = toBytes(body);
    if (!bytes || !bytes.length) return;
    if (bytes.length > 1048576) bytes = sliceBytes(bytes, 1048576);
    if (!bodyLooksTextual(bytes, contentType)) return;
    body = decodeUtf8(bytes);
  }
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
  if (contentType.toLowerCase().indexOf("x-www-form-urlencoded") >= 0) collectForm(text, hits);
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
  applyArguments();
  var request = $request || {};
  var response = typeof $response !== "undefined" && $response ? $response : null;
  var url = request.url || "";
  var host = getHost(url);
  if (!host) {
    finish();
    return;
  }
  if (!hostAllowed(host) || isInternalHost(host) || isStaticUrl(url) || /\/mmtls(?:\/|$)/i.test(url)) {
    debugLog("skip", host, url);
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
