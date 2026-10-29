/* shop.demo.test — ARCHIVED SPA bundle (fixture) captured from web.archive.org.
   Contains legacy routes that were removed from the current UI but may still be
   live on the backend (ghost endpoints). */
"use strict";
var legacy = {
  getOrderV0: function (id) { return http.get("/api/v0/orders/:orderId"); },
  exportReport: function (rid) { return http.get("/api/v1/internal/export/:reportId"); },
  getProfile: function (uid) { return http.get("/api/v1/users/:uid/profile"); },
  listOrders: function () { return http.get("/api/v1/orders"); }
};
export default legacy;
