var OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError
  , url = require('url')
  , util = require('util');

/**
 * `Strategy` constructor.
 *
 * HubSpot uses the OAuth 2.0 protocol for authentication.
 *
 * Applications using this must supply a callback to verify the credentials which
 * accepts an `accessToken`, `refreshToken`, and a `profile`. After verifying the
 * credentials it should call `done` with the user object and any error that may
 * have occured as the first parameter.
 *
 * Options:
 *   - `clientID`	your HubSpot application's App ID
 *   - `clientSecret`	your HubSpot application's App Secret
 *   - `callbackURL`	URL to which HubSpot will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new HubSpotStrategy({
 *         clientID: 'HUBSPOT_APP_ID',
 *         clientSecret: 'SECRET_SAUCE',
 *         callbackURL: 'https://www.example.net/auth/hubspot/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://app.hubspot.com/auth/authenticate/';
  options.tokenURL = options.tokenURL || 'https://app.hubspot.com/auth/token';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'hubspot';
  this._oauth2._useAuthorizationHeaderForGET = true;
  this._oauth2._skipUserProfile = true;
}

util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.authorizationParams = function(options) {
  var params = {};

  if (options.portalId) {
    params.portalId = options.portalId;
  }

  return params;
}

/**
 * Reconstructs the original URL of the request.
 *
 * This function builds a URL that corresponds the original URL requested by the
 * client, including the protocol (http or https) and host.
 *
 * If the request passed through any proxies that terminate SSL, the
 * `X-Forwarded-Proto` header is used to detect if the request was encrypted to
 * the proxy.
 *
 * @return {String}
 * @api private
 */
function originalURL (req) {
  var headers = req.headers
    , protocol = (req.connection.encrypted || req.headers['x-forwarded-proto'] == 'https')
               ? 'https'
               : 'http'
    , host = headers.host
    , path = req.url || '';
  return protocol + '://' + host + path;
}

/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
    //       query parameters, and should be propagated to the application.
    return this.fail();
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(originalURL(req), callbackURL);
    }
  }

  function loadProfile (accessToken, refreshToken) {
    self._loadUserProfile(accessToken, function(err, profile) {
      if (err) { return self.error(err); }

      function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        self.success(user, info);
      }

      if (self._passReqToCallback) {
        var arity = self._verify.length;
        if (arity == 6) {
          self._verify(req, accessToken, refreshToken, params, profile, verified);
        } else { // arity == 5
          self._verify(req, accessToken, refreshToken, profile, verified);
        }
      } else {
        var arity = self._verify.length;
        if (arity == 5) {
          self._verify(accessToken, refreshToken, params, profile, verified);
        } else { // arity == 4
          self._verify(accessToken, refreshToken, profile, verified);
        }
      }
    });
  }

  if (req.query && req.query.access_token && req.query.refresh_token) {
    return loadProfile(req.query.access_token, req.query.refresh_token);
  }

  if (req.query && req.query.code) {
    var code = req.query.code;

    // NOTE: The module oauth (0.9.5), which is a dependency, automatically adds
    //       a 'type=web_server' parameter to the percent-encoded data sent in
    //       the body of the access token request.  This appears to be an
    //       artifact from an earlier draft of OAuth 2.0 (draft 22, as of the
    //       time of this writing).  This parameter is not necessary, but its
    //       presence does not appear to cause any issues.
    this._oauth2.getOAuthAccessToken(code, { grant_type: 'authorization_code', redirect_uri: callbackURL },
      function(err, accessToken, refreshToken, params) {
        if (err) { return self.error(new InternalOAuthError('failed to obtain access token', err)); }

        loadProfile(accessToken, refreshToken);
        /* self._loadUserProfile(accessToken, function(err, profile) {
          if (err) { return self.error(err); };

          function verified(err, user, info) {
            if (err) { return self.error(err); }
            if (!user) { return self.fail(info); }
            self.success(user, info);
          }

          if (self._passReqToCallback) {
            var arity = self._verify.length;
            if (arity == 6) {
              self._verify(req, accessToken, refreshToken, params, profile, verified);
            } else { // arity == 5
              self._verify(req, accessToken, refreshToken, profile, verified);
            }
          } else {
            var arity = self._verify.length;
            if (arity == 5) {
              self._verify(accessToken, refreshToken, params, profile, verified);
            } else { // arity == 4
              self._verify(accessToken, refreshToken, profile, verified);
            }
          }
        }); */
      }
    );
  } else {
    // NOTE: The module oauth (0.9.5), which is a dependency, automatically adds
    //       a 'type=web_server' parameter to the query portion of the URL.
    //       This appears to be an artifact from an earlier draft of OAuth 2.0
    //       (draft 22, as of the time of this writing).  This parameter is not
    //       necessary, but its presence does not appear to cause any issues.

    var params = this.authorizationParams(options);
    params['response_type'] = 'code';
    params['redirect_uri'] = callbackURL;
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }
    var state = options.state;
    if (state) { params.state = state; }

    var location = this._oauth2.getAuthorizeUrl(params);
    this.redirect(location);
  }
}


module.exports = Strategy;
