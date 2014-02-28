var OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError
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

module.exports = Strategy;
