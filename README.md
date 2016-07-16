# Passport-Nylas

[Passport](http://passportjs.org) strategy for authenticating with [Nylas](https://nylas.com) using the OAuth 2.0 protocol API

This module lets you authenticate using Pocket in your Node.js applications.
By plugging into Passport. Twitter authentication can be easily and unobstusively integrated into any aplication or framework that supports [Express](http://expressjs.com).

## Installation

`npm install passport-nylas`


## Usage

#### Configure Strategy

The Nylas authentication strategy authenticates users using an email account from mail providers like `gmail`, `yahoo`, `outlook` and more.
The strategy requires a `verify` callback, which receives the access token and username as arguments. The `verify` callback must call `done` providing a user to complete authentication.

In order to identify your application to Nylas, provide a clientID and clientSecret and callbackURI within options.
You can obtain your clientID and clientSecret by [Creating an Application](https://nylas.com/developers) at Nylas's developers site.

```js
	

passport.use(new NylasStrategy({
	clientID: process.env.CLIENT_ID,
	clientSecret: process.env.CLIENT_SECRET,
	callbackURL: process.env.callbackURI
	},
	function(email, accessToken, profile, done) {
		User.findOne({nylasId: profile.id}, function(err, user) {
			return done(err, user)
			});
		}
));

```


#### Authenticate Requests

Use `passport.authenticate()`, specifying the strategy to authenticate requests.

E.g

```js
	
app.get('/auth/nylas', passport.authenticate('nylas'));

app.get('/auth/nylas/cb/', function(req, res, next) {
	passport.authenticate('nylas',
		function(err, user, info) {
			if (err) {
				res.redirect('/login');
			}
			req.login(user, function(err) {
				if (err) {
					console.log('Internal Error, Do try again later');
				}
				res.redirect('/');
			})
		}
	)(req, res, next);
});

```


#### Scope

Permission can be requested via the `scope` option to `passport.authenticate()`

For example:
```js
app.get('/auth/nylas', passport.authenticate('nylas', {scope: 'email'}));

```

## Credits


## License

[The MIT License](http;//opensource,org/licenses/MIT)
