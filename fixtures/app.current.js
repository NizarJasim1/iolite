/* shop.demo.test — current SPA bundle (fixture, self-authored). */
"use strict";
var api = {
  getOrder: function (id) { return http.get("/api/v1/orders/:orderId".replace(":orderId", id)); },
  getProfile: function (uid) { return http.get("/api/v1/users/:uid/profile"); },
  getVehicleLocation: function (vid) { return http.get("/api/v1/vehicles/:vehicleId/location"); },
  listOrders: function () { return http.get("/api/v1/orders"); },
  redeemCoupon: function (code) { return http.post("/api/v1/coupons/:code/redeem"); },
  graphql: function (q) { return http.post("/api/graphql", { method: "POST", body: q }); },
  updateProfile: function (uid, body) { return http.put("/api/v1/users/:uid/profile", body); }
};
export default api;
