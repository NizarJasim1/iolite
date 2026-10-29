/*
 * IOLITE LIVE hook — passive, real-time surface+response recorder for `iolite watch`.
 *
 * Loads into YOUR OWN browser session while you use a target as YOUR OWN account, in scope.
 * It records each call's request + response your client already makes, and streams it to your
 * LOCAL collector (127.0.0.1) so IOLITE can build the authorization-intent model and confirm
 * cross-account exposure the instant it appears. It crafts, injects, or replays NOTHING.
 *
 * v1.19: also forwards response bodies, a few safe response HEADERS, and — crucially — the
 * JWT CLAIMS (sub / role / tenant) decoded IN THE BROWSER from your own Authorization header.
 * Only the claims are sent, never the token itself. These claims let IOLITE read ownership
 * (owner_id == your sub) and learn the policy by contrast, precisely.
 *
 * LEGAL / QL: passive-first, own-accounts-only, your own session, in scope. Loopback only.
 */
(function () {
  if (window.__IOLITE_live_hooked) { console.log("IOLITE live hook already armed"); return; }
  window.__IOLITE_live_hooked = true;
  var COLLECTOR = window.__IOLITE_collector || "__IOLITE_COLLECTOR__";
  var PRINCIPAL = window.__IOLITE_principal || "A";
  var MAXB = 200000;
  var _fetch = window.fetch;
  var RESP_HDRS = ["content-type", "location", "www-authenticate", "x-ratelimit-remaining",
    "retry-after", "server", "cf-ray", "cf-mitigated", "x-iinfo", "x-cdn", "x-sucuri-id",
    "x-datadome", "x-amzn-requestid", "x-akamai-transformed", "via"];

  function post(rec) {
    try { if (_fetch) _fetch(COLLECTOR + "/ingest", { method: "POST", mode: "cors", keepalive: true,
      headers: { "content-type": "application/json" }, body: JSON.stringify(rec) }).catch(function(){}); } catch (e) {}
  }
  function isCollector(u) { try { return String(u).indexOf(COLLECTOR) === 0; } catch (e) { return false; } }
  function clip(s) { s = String(s == null ? "" : s); return s.length > MAXB ? s.slice(0, MAXB) : s; }

  function b64urlJson(seg) {
    try {
      seg = seg.replace(/-/g, "+").replace(/_/g, "/");
      while (seg.length % 4) seg += "=";
      return JSON.parse(decodeURIComponent(escape(atob(seg))));
    } catch (e) { return null; }
  }
  function claimsFrom(authz) {
    if (!authz) return null;
    var tok = String(authz).split(" ").pop();
    var parts = tok.split(".");
    if (parts.length !== 3) return null;
    var p = b64urlJson(parts[1]);
    if (!p || typeof p !== "object") return null;
    var out = {};
    ["sub", "user_id", "uid", "id", "email", "preferred_username"].some(function (k){ if (p[k]!=null){out.sub=String(p[k]);return true;} });
    ["role", "roles", "scope", "scp", "permissions", "authorities", "groups"].some(function (k){ if (p[k]!=null){out.role=Array.isArray(p[k])?p[k].join(","):String(p[k]);return true;} });
    ["tenant","tenant_id","org","org_id","account","aud"].some(function (k){ if (p[k]!=null){out.tenant=Array.isArray(p[k])?p[k].join(","):String(p[k]);return true;} });
    return out;
  }
  function authzFromInit(init) {
    try {
      var h = init && init.headers; if (!h) return "";
      if (typeof h.get === "function") return h.get("authorization") || h.get("Authorization") || "";
      for (var k in h) if (String(k).toLowerCase() === "authorization") return h[k];
    } catch (e) {}
    return "";
  }
  function respHeaders(r) {
    var o = {}; try { RESP_HDRS.forEach(function (k){ var v=r.headers&&r.headers.get&&r.headers.get(k); if(v)o[k]=v; }); } catch(e){}
    return o;
  }

  // fetch
  if (_fetch) {
    window.fetch = function (input, init) {
      var url = (typeof input === "string") ? input : (input && input.url) || "";
      var method = (init && init.method) || (input && input.method) || "GET";
      var reqBody = (init && init.body) ? clip(init.body) : "";
      var claims = claimsFrom(authzFromInit(init));
      if (isCollector(url)) return _fetch.apply(this, arguments);
      var p = _fetch.apply(this, arguments);
      p.then(function (r) {
        try { var c = r.clone(); c.text().then(function (t) {
          post({ principal: PRINCIPAL, method: method, url: url, reqBody: reqBody,
                 status: r.status, respBody: clip(t), respHeaders: respHeaders(r), claims: claims });
        }).catch(function(){ post({ principal: PRINCIPAL, method: method, url: url, reqBody: reqBody, status: r.status, claims: claims }); }); } catch (e) {}
      }).catch(function(){});
      return p;
    };
  }

  // XMLHttpRequest (hook setRequestHeader to read the Authorization claims)
  var _open = XMLHttpRequest.prototype.open;
  var _send = XMLHttpRequest.prototype.send;
  var _setH = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.open = function (method, url) { this.__io = { method: method, url: url, authz: "" }; return _open.apply(this, arguments); };
  XMLHttpRequest.prototype.setRequestHeader = function (k, v) {
    try { if (this.__io && String(k).toLowerCase() === "authorization") this.__io.authz = v; } catch (e) {}
    return _setH.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    var self = this;
    try {
      if (self.__io && !isCollector(self.__io.url)) {
        self.addEventListener("loadend", function () {
          var rt = ""; try { rt = self.responseText || ""; } catch (e) {}
          var rh = {}; try { RESP_HDRS.forEach(function(k){ var v=self.getResponseHeader(k); if(v)rh[k]=v; }); } catch(e){}
          post({ principal: PRINCIPAL, method: self.__io.method, url: self.__io.url, reqBody: clip(body),
                 status: self.status, respBody: clip(rt), respHeaders: rh, claims: claimsFrom(self.__io.authz) });
        });
      }
    } catch (e) {}
    return _send.apply(this, arguments);
  };

  console.log("IOLITE live hook v1.19 armed as '" + PRINCIPAL + "' → " + COLLECTOR +
              " (browse normally; live confirmations + learned policy in your watch terminal)");
})();
