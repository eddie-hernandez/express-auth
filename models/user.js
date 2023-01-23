const mongoose = require('mongoose')

const userSchema = new mongoose.Schema(
	{
		// field - email unique: true
		email: {
			type: String,
			required: true,
			// if there is a document with this email, 
			// don't create it! it's already in use!
			unique: true,
		},
		// hashed password results
		password: {
			type: String,
			required: true,
		},
		// notice how it's not required
		// start off without a token then save one later
		token: String,
	},
	{
		timestamps: true,
		toJSON: {
			transform: (_doc, user) => {
				delete user.password
				return user
			},
		},
	}
)

module.exports = mongoose.model('User', userSchema)


