# Passport-Hubspot

[Passport](http://passportjs.org/) strategy for authenticating with [HubSpot](http://www.hubspot.com/)
using the OAuth 2.0 API.

This module lets you authenticate using HubSpot in your Node.js applications.
By plugging into Passport, HubSpot authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Usage

#### Configure Strategy

The HubSpot authentication strategy authenticates users using a HubSpot
account and OAuth 2.0 tokens.  The strategy requires a `verify` callback, which
accepts these credentials and calls `done` providing a user, as well as
`options` specifying a app ID, app secret, and callback URL.

    passport.use(new HubSpotStrategy({
        clientID: HUBSPOT_APP_ID,
        clientSecret: HUBSPOT_APP_SECRET,
        callbackURL: "http://localhost:3000/auth/hubspot/callback"
      }, function (accessToken, refreshToken, profile, done) {
        User.findOrCreate({ hubspotId: profile.id }, function(err, user) {
          return done(err, user);
        });
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'hubspot'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/hubspot', passport.authenticate('hubspot'));

    app.get('/auth/hubspot/callback',
      passport.authenticate('hubspot', { failureRedirect: '/login' }),
      function(req, res) {
        // Successul authentication, redirect home.
        res.redirect('/');
      });

## Credits

Created by [Brian Falk](http://github.com/brainflake)

Code based on passport-facebook by [Jared Hanson](http://github.com/jaredhanson)

## License

[The MIT License](http://opensource.org/licenses/MIT)
