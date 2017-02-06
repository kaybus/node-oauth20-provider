var
    async = require('async'),
    response = require('./../../util/response.js'),
    error = require('./../../error');

module.exports = function(req, oauth2, client, username, password, scope, pCb) {

    // Define variables
    var tokenHash,
        scope,
        refreshTokenValue,
        accessTokenValue,
        accessTokenTtl;

    async.waterfall([
        // Check username and password parameters
        function(cb) {
            if (!username)
                return cb(new error.invalidRequest('Username is mandatory for password grant type'));
            oauth2.logger.debug('Username parameter check passed: ', username);

            if (!password)
                return cb(new error.invalidRequest('Password is mandatory for password grant type'));
            oauth2.logger.debug('Password parameter check passed: ', password);

            cb();
        },
        // Parse and check scope against supported and client available scopes
        function(cb) {
            scope = oauth2.model.client.transformScope(scope);
            scope = oauth2.model.client.checkScope(client, scope);
            if (!scope)
                cb(new error.invalidScope('Invalid scope for the client'));
            else {
                oauth2.logger.debug('Scope check passed: ', scope);
                cb();
            }
        },
        // Fetch user
        function(cb) {
            oauth2.model.user.checkPassword(req, username, password, function(result){
                if(result.ResultCode == "Success" || result.ResultCode == "PasswordWillExpire") {
                    oauth2.logger.debug('Object fetched: ', result);
                    tokenHash = result;
                    cb();
                } else {
                    var errorMessage = new error.invalidClient('Wrong user password provided');
                    errorMessage.result_code = result.ResultCode;
                    cb(errorMessage);
                }
            });
        },
        // Generate new refreshToken and save it
        function(cb) {
            refreshTokenValue = oauth2.model.refreshToken.generateToken();
            oauth2.model.refreshToken.save(req, refreshTokenValue, tokenHash, oauth2.model.client.getId(client), scope, function(err) {
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
            oauth2.model.accessToken.getTTL(req, null, client, function(err, ttl) {
                if(err)
                    cb(new error.serverError('Failed to call accessToken::getTTL method'));
                else {
                    accessTokenTtl = ttl;
                    cb();
                }
            });
        },
        // Generate new accessToken and save it
        function(cb) {
            accessTokenValue = oauth2.model.accessToken.generateToken();
            oauth2.model.accessToken.save(req, accessTokenValue, tokenHash, oauth2.model.client.getId(client), scope, accessTokenTtl, function(err) {
                if (err)
                    cb(new error.serverError('Failed to call accessToken::save method'));
                else {
                    oauth2.logger.debug('Access token saved: ', accessTokenValue);
                    cb();
                }
            });
        }
    ],
    function(err) {
        if (err) pCb(err);
        else {
            var token = {
                refresh_token: refreshTokenValue,
                token_type: "bearer",
                access_token: accessTokenValue,
                user_id: tokenHash.UserID,
                account_id: tokenHash.AccountID,
                result_code: tokenHash.ResultCode
            };
            if(accessTokenTtl > 0)
                token.expires_in = accessTokenTtl;
            pCb(null, token);
        }
    });
};