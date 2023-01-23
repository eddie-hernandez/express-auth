/*

Passport – Express-compatible authentication middleware for Node.js
	- Passport is designed to authenticate requests using a set of strategies/plugins
		- Strategy implements a strategy for selecting the correct transport 
		based on a given set of restrictions.
	- First, you give Passport a request to authenticate, and in return, it provides
	you hooks for controlling what occurs when authentication succeeds or fails
bcrypt – a library to help you hash passwords
	- The input to the bcrypt function is:
		- password string (up to 72 bytes),
		- a numeric cost,
		- and a 16-byte (128-bit) salt value.
	- The salt is typically a random value.
	- The bcrypt function uses these inputs to 
	compute a 24-byte (192-bit) hash.
	- The final output of the bcrypt function is a string 
	of the form:

		$2<a/b/x/y>$[cost]$[22 character salt][31 character hash]

	- For example, with input password abc123xyz, 
	- cost 12, and a random salt, the output of bcrypt is the string

		$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
		\__/\/ \____________________/\_____________________________/
		Alg Cost      Salt                        Hash

jwt (jsonwebtoken) - an implementation of JSON Web Tokens
	- JWT is a compact, URL-safe means of representing claims to 
	be transferred between two parties

secret - is literally a secret! it is something only your app knows
	- this is the token that is being saved in a variable
	// process.env.JWT_SECRET => undefined
	- process.env file is going to store JWT_SECRET
	- JWT_SECRET should hold a value!
	- if process.env.JWT_SECRET is undefined (which it is),
	and since undefined is considered falsey, it'll resort to
	'some string value'

*/

// Require the needed npm packages
const passport = require('passport')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

// Create a secret to be used to encrypt/decrypt the token
// This can be any string value you want -- even gibberish.
const secret = process.env.JWT_SECRET || 'some string value only your app knows'

// Require the specific `strategy` we'll use to authenticate
// Require the method that will handle extracting the token
// from each of the requests sent by clients
const { Strategy, ExtractJwt } = require('passport-jwt')

// Minimum required options for passport-jwt

/* 

the minimum required options are making sure we're both
1. extract the 'bearer' token when we make front-end requests
2. have a secret key that will encrypt the token we've extracted


secretOrKey – is a string or buffer containing the secret 
(symmetric) or PEM-encoded public key (asymmetric) for verifying 
the token's signature.

*/

const opts = {
	// How passport should find and extract the token from
	// the request.  We'll be sending it as a `bearer` token
	// when we make requests from our front end.
	// headers: {
	// 	'Accept': 'app/json',
	// 	'Authorization': 'Bearer aweijaowefhaisdhgakfasdkflaldiga'
	// }

	jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),

	// Any secret string to use that is unique to your app
	// We should store this in an environment variable so it
	// isn't ever pushed to GitHub!
	secretOrKey: secret,
}

// Require the user model
const User = require('../models/user')

/*

we're using the constructor method to make a new Strategy, which passport is
already built off a set of.

Essentially, here, we are building the restrictions that we want our passport
to recognize to authenticate every user

jwt_payload – an object literal containing the decoded JWT payload!
	- in our case, the payload is the user's id!

*/

// We're configuring the strategy using the constructor from passport
// so we call new and pass in the options we set in the `opts` variable.
// Then we pass it a callback function that passport will use when we call
// this as middleware.  The callback will be passed the data that was
// extracted and decrypted by passport from the token that we get from
// the client request!  This data (jwt_payload) will include the user's id!
const strategy = new Strategy(opts, function (jwt_payload, done) {
	// In the callback we run our custom code. With the data extracted from
	// the token that we're passed as jwt_payload we'll have the user's id.
	// Using Mongoose's `.findOneById()` method, we find the user in our database
	User.findById(jwt_payload.id)
		// To pass the user on to our route, we use the `done` method that
		// that was passed as part of the callback.  The first parameter of
		// done is an error, so we'll pass null for that argument and then
		// pass the user doc from Mongoose. This adds the user to the request object
		// as request.user!
		// req.body
		// req.params
		// req.user
		.then((user) => done(null, user))
		// If there was an error, we pass it to done so it is eventually handled
		// by our error handlers in Express
		.catch((err) => done(err))
})

// Now that we've constructed the strategy, we 'register' it so that
// passport uses it when we call the `passport.authenticate()`
// method later in our routes
passport.use(strategy)

/*

very similar to initializing a game

*/

// Initialize the passport middleware based on the above configuration
passport.initialize()

/*

as a user, I have to be signed in to use my create route

*/

// Create a variable that holds the authenticate method so we can
// export it for use in our routes
const requireToken = passport.authenticate('jwt', { session: false })


/* 

Error Code 422 – Unprocessable Entity response status code
	- essentially, the server understands the content type of the
	request entity, and the syntax of the request entity is correct,
	but it was unable to process the contained instructions
	- this means that, in our createUserToken, if there is no user, or if
	someone either provides a bad username or password (with 
	the fields being compared by the bcrypt.compareSync 
	(using decrypt functionality to make sure the username/password
	matches the user's ACTUAL username/password)), 
	the error status will show!

	- if no error was thrown in our createUserToken function,
	we will create the token using the user's ID and return it!

jwt.sign – is literally the process of digitally signing a JSON Web Token
		- jwts can be signed using a secret or public/private key pair (RSA/ECSDA)
	
	- jwt.sign has a couple of parameters:
		- jwt.sign(payload, secretOrPrivateKey, [options, callback])
		- our payload is our ID
		- we're using a secret key
		- and we want the token to expire in 36000 seconds / 1 hr
*/



// Create a function that takes the request and a user document
// and uses them to create a token to send back to the user
const createUserToken = (req, user) => {
	// Make sure that we have a user, if it's null that means we didn't
	// find the email in the database.  If there is a user, make sure
	// that the password is correct.  For security reason, we don't want
	// to tell the client whether the email was not found or that the
	// password was incorrect.  Instead we send the same message for both
	// making it much harder for hackers.
	if (
		!user ||
		!req.body.credentials.password ||
		!bcrypt.compareSync(req.body.credentials.password, user.password)
	) {
		const err = new Error('The provided username or password is incorrect')
		err.statusCode = 422
		throw err
	}
	// If no error was thrown, we create the token from user's id and
	// return the token
	return jwt.sign({ id: user._id }, secret, { expiresIn: 36000 })
}

module.exports = {
	requireToken,
	createUserToken,
}
