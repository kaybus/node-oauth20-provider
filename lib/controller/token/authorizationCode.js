var
    async = require('async'),
    error = require('./../../error');

module.exports = function(req, oauth2, client, sCode, redirectUri, pCb) {

    // Define variables
    var code,
        refreshTokenValue,
        accessTokenValue,
        accessTokenTtl;

    async.waterfall([
        // Fetch code
        function(cb) {
            oauth2.model.code.fetchByCode(sCode, function(err, obj) {
                if (err)
                    cb(new error.serverError('Failed to call code::fetchByCode method'));
                else if (!obj)
                    cb(new error.invalidGrant('Code not found'))
                else if (oauth2.model.code.getClientId(obj) != oauth2.model.client.getId(client))
                    cb(new error.invalidGrant('Code is issued by another client'));
                else if (!oauth2.model.code.checkTTL(obj))
                    cb(new error.invalidGrant('Code is already expired'));
                else {
                    oauth2.logger.debug('Code fetched: ', obj);
                    code = obj;
                    cb();
                }
            });
        },
        // Generate new refreshToken and save it
        function(cb) {
            refreshTokenValue = oauth2.model.refreshToken.generateToken();
            oauth2.model.refreshToken.save(req, refreshTokenValue, oauth2.model.code.getUserId(code), oauth2.model.code.getClientId(code), oauth2.model.code.getScope(code), function(err) {
                if (err)
                    cb(new error.serverError('Failed to call refreshToken::save method'));
                else {
                    oauth2.logger.debug('Refresh token saved: ', refreshTokenValue);
                    cb();
                }
            });
        },
        //Get accessToken ttl based on the req and the client
        function(cb) {
            oauth2.model.user.fetchById(req, oauth2.model.code.getUserId(code), function(err, user) {
                if (err)
                    cb(new error.serverError('Failed to get user from code value'));
                else {
                    oauth2.model.accessToken.getTTL(req, user, client, function (err, ttl) {
                        if (err)
                            cb(new error.serverError('Failed to call accessToken::getTTL method'));
                        else {
                            accessTokenTtl = ttl;
                            cb();
                        }
                    });
                }
            });
        },
        // Generate new accessToken and save it
        function(cb) {
            accessTokenValue = oauth2.model.accessToken.generateToken();
            oauth2.model.accessToken.save(req, accessTokenValue, oauth2.model.code.getUserId(code), oauth2.model.code.getClientId(code), oauth2.model.code.getScope(code), accessTokenTtl, function(err) {
                if (err)
                    cb(new error.serverError('Failed to call accessToken::save method'));
                else {
                    oauth2.logger.debug('Access token saved: ', accessTokenValue);
                    cb();
                }
            });
        },
        // Remove used code
        function(cb) {
            oauth2.model.code.removeByCode(sCode, function(err) {
                if (err)
                    cb(new error.serverError('Failed to call code::removeByCode method'));
                else {
                    oauth2.logger.debug('Code removed');
                    cb();
                }
            });
        }
    ], function(err) {
        if (err) pCb(err);
        else {
            var token = {
                refresh_token: refreshTokenValue,
                token_type: "bearer",
                access_token: accessTokenValue
            };
            if(accessTokenTtl > 0)
                token.expires_in = accessTokenTtl;
            pCb(null, token);
        }
    });

};