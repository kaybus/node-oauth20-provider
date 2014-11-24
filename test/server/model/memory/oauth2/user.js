var users = require('./../../data.js').users;

module.exports.getId = function(user) {
    return user.id;
};

module.exports.fetchById = function(req, id, cb) {
    for (var i in users) {
        if (id == users[i].id) return cb(null, users[i]);
    };
    cb();
};

module.exports.fetchByUsername = function(req, username, cb) {
    for (var i in users) {
        if (username == users[i].username) return cb(null, users[i]);
    };
    cb();
};

module.exports.checkPassword = function(req, user, password) {
    return (user.password == password);
};

module.exports.fetchFromRequest = function(req) {
    return req.session.user;
};