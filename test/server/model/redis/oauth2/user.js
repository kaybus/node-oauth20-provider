var
    util = require('util'),
    redis = require('./../redis.js');

var KEY = {
    USER         : 'user:id:%s',
    USER_USERNAME: 'user:username:%s'
};

module.exports.KEY = KEY;

module.exports.getId = function(user) {
    return user.id;
};

var fetchById = function(req, id, cb) {
    redis.get(util.format(KEY.USER, id), function(err, stringified) {
        if (err) cb(err);
        else if (!stringified) cb();
        else {
            try {
                var obj = JSON.parse(stringified);
                cb(null, obj);
            } catch (e) {
                cb();
            }
        }
    });
};

module.exports.fetchById = fetchById;

module.exports.fetchByUsername = function(req, username, cb) {
    redis.get(util.format(KEY.USER_USERNAME, username), function(err, userId) {
        if (err) cb(err);
        else if (!userId) cb();
        else {
            fetchById(req, userId, cb);
        }
    });
};

module.exports.checkPassword = function(req, user, password, cb) {
    cb((user.password == password));
};

module.exports.fetchFromRequest = function(req) {
    cb(null, req.session.user);
};