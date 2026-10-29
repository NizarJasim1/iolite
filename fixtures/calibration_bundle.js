/* calibration_bundle.js — labeled fixture exercising REAL-WORLD path patterns.
   Ground truth is in quarry/calibrate.py :: BUNDLE_TRUTH (6 endpoints).
   The asset/CDN paths are decoys and MUST NOT be emitted. */
"use strict";
const API = "/api/v2";
function wire(orderId, id, userId, n) {
  // 1) template literal
  fetch(`/api/v1/orders/${orderId}`);
  // 2) multi-part string concatenation (both sides dynamic)
  http.post("/api/v1/orders/" + id + "/refund", {});
  // 3) concatenation with a trailing sub-resource
  axios.get("/api/v1/users/" + userId + "/profile");
  // 4) const-prefixed composition
  fetch(API + "/invoices/" + n);
  // 5) ajax config object with method field, admin surface
  $.ajax({ url: "/api/v1/admin/users", method: "DELETE" });
  // 6) graphql endpoint via options object
  fetch("/api/graphql", { method: "POST", body: query });

  // ---- decoys: assets/CDN — must be ignored ----
  var css = "/static/app.4f3c19.css";
  var img = "/assets/img/logo.png";
  loadScript("https://cdn.example.com/vendor/lib.min.js");
  var chunk = "/static/js/main.9ab.js";
}
export default wire;
