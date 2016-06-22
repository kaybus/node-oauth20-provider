var refreshTokens = require('./../../data.js').refreshTokens;

module.exports.getUserId = function(refreshToken) {
    return refreshToken.userId;
};

module.exports.fetchByToken = function(token, cb) {
    for (var i in refreshTokens) {
        if (refreshTokens[i].token == token) return cb(null, refreshTokens[i]);
    }
    cb(null, null);
};

module.exports.save = function(req, token, userId, clientId, scope, cb) {
    var obj = {token: token, userId: userId, clientId: clientId, scope: scope};
    refreshTokens.push(obj);
    cb(null, obj);
};

module.exports.getScope = function(refreshToken) {
    return [];
};

module.exports.refresh = function(req, refreshToken, userId, clientId, cb) {
    cb(null);
};