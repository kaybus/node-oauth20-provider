var clients = require('./../../data.js').clients;

module.exports.getId = function(client) {
    return client.id;
};

module.exports.getRedirectUri = function(client) {
    return client.redirectUri;
};

module.exports.fetchById = function(clientId, cb) {
    for (var i in clients) {
        if (clientId == clients[i].id) return cb(null, clients[i]);
    }
    cb();
};

module.exports.checkSecret = function(client, secret) {
    return (client.secret == secret);
};

exports.checkTenantUrl = function(req, obj) {
  return [req.hostname, "all"].indexOf(obj.tenant_url) > -1;
};

module.exports.needDecisionConfirmation = function(client, secret) {
  return true;
};