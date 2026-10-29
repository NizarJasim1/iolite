/*
 * IOLITE surface hook — PASSIVE runtime self-disclosure recorder (Point 2, Tier 2).
 *
 * WHAT IT IS. A read-only observer you paste into YOUR OWN browser DevTools console
 * while using a target as YOUR OWN authenticated principal, in scope. It records the
 * requests YOUR client already constructs and sends for legitimate use — nothing is
 * crafted, injected, replayed, or sent by this script. The client deobfuscates
 * itself by running; this captures the concrete (method, url, GraphQL) surface that
 * static mining cannot see and obfuscation cannot hide.
 *
 * LEGAL / QL: passive-first (crafts no request), own-principal only, in your own
 * session. It is the exact surface you would see by clicking around by hand, just
 * recorded. Do NOT use it in an account or scope that is not yours.
 *
 * USE.
 *   1. Log in to the target as your own account. Open DevTools → Console.
 *   2. Paste this whole file and press Enter. You'll see: "IOLITE hook armed".
 *   3. Use the app normally (visit your pages, your orders, your settings).
 *   4. Run  __IOLITE_dump()  to download  iolite-runtime.json
 *   5. Feed it:  iolite reason --dir ./captures --deep --runtime iolite-runtime.json
 *
 * It records ONLY: method, url (path kept; query dropped), status, and a GraphQL
 * operation string when present. No request/response BODIES, no tokens, no headers.
 */
(function () {
  if (window.__IOLITE_hooked) { console.log("IOLITE hook already armed"); return; }
  window.__IOLITE_hooked = true;
  var calls = [];
  var MAX = 5000;
  var principal = (window.__IOLITE_principal || "");   // optionally set to tag account

  function record(method, url, status, gql) {
    if (calls.length >= MAX) return;
    var u = String(url || "");
    try { u = u.split("?")[0].split("#")[0]; } catch (e) {}
    var rec = { method: String(method || "GET").toUpperCase(), url: u };
    if (status) rec.status = status;
    if (gql) rec.gql = String(gql).slice(0, 4000);
    if (principal) rec.principal = principal;
    calls.push(rec);
  }

  function sniffGraphQL(body) {
    try {
      if (typeof body !== "string") return null;
      if (body.indexOf("query") < 0 && body.indexOf("mutation") < 0) return null;
      var o = JSON.parse(body);
      if (o && typeof o.query === "string") return o.query;
    } catch (e) {}
    return null;
  }

  // fetch
  var _fetch = window.fetch;
  if (_fetch) {
    window.fetch = function (input, init) {
      try {
        var url = (typeof input === "string") ? input : (input && input.url) || "";
        var method = (init && init.method) || (input && input.method) || "GET";
        var gql = init && init.body ? sniffGraphQL(init.body) : null;
        var p = _fetch.apply(this, arguments);
        p.then(function (r) { record(method, url, r && r.status, gql); })
         .catch(function () { record(method, url, 0, gql); });
        return p;
      } catch (e) { return _fetch.apply(this, arguments); }
    };
  }

  // XMLHttpRequest
  var _open = XMLHttpRequest.prototype.open;
  var _send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__iolite = { method: method, url: url };
    return _open.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    var self = this;
    try {
      var gql = sniffGraphQL(body);
      this.addEventListener("loadend", function () {
        if (self.__iolite) record(self.__iolite.method, self.__iolite.url, self.status, gql);
      });
    } catch (e) {}
    return _send.apply(this, arguments);
  };

  // WebSocket (endpoint only)
  var _WS = window.WebSocket;
  if (_WS) {
    window.WebSocket = function (url, protocols) {
      try { record("WS", url, 0, null); } catch (e) {}
      return protocols ? new _WS(url, protocols) : new _WS(url);
    };
    window.WebSocket.prototype = _WS.prototype;
  }

  window.__IOLITE_calls = calls;
  window.__IOLITE_dump = function () {
    var data = JSON.stringify({ calls: calls }, null, 2);
    try {
      var blob = new Blob([data], { type: "application/json" });
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "iolite-runtime.json";
      document.body.appendChild(a); a.click(); a.remove();
      console.log("IOLITE: wrote iolite-runtime.json (" + calls.length + " calls)");
    } catch (e) {
      console.log("IOLITE calls (copy manually):\n" + data);
    }
    return calls.length;
  };

  console.log("IOLITE hook armed — use the app as yourself, then run __IOLITE_dump()");
})();
