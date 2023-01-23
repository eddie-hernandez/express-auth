const mongoose = require ('mongoose')

const Schema = mongoose.Schema

// schemas take two params:
// 1st param is the field
// 2nd param is the list of options (timestamps, etc.)
const noteSchema = new Schema(
	{
		title: {
			type: String,
			required: true,
		},
		content: {
			type: String,
			required: true,
		},
        owner: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        }
	},
	{
		timestamps: true,
	}
)

module.exports = noteSchema