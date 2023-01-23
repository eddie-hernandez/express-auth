// require Express
const express = require('express')
const { requireToken } = require('../config/auth') 
const { handle404 } = require('../lib/custom-errors')

// require the Model we just created
const Campaign = require('../models/campaign')

// Creating a router for us to make paths on
const router = express.Router()

// INDEX
// GET /campaigns
router.get('/campaigns', requireToken, (req, res, next) => {
	Campaign.find()
		.then((campaigns) => {
			return campaigns.map((campaign) => campaign)
		})
		.then((campaigns) => res.status(200).json({ campaigns: campaigns }))
		.catch(next)
})

// SHOW
// GET /campaigns/5a7db6c74d55bc51bdf39793
router.get('/campaigns/:id', (req, res, next) => {
	// req.params.id will be set based on the `:id` in the route
	Campaign.findById(req.params.id)
		.then(handle404)
		.then((campaign) => res.status(200).json({ campaign: campaign }))
		.catch(next)
})

// CREATE
// POST /campaigns
router.post('/campaigns', (req, res, next) => {
	Campaign.create(req.body.campaign)
		.then((campaign) => {
			res.status(201).json({ campaign: campaign })
		})
		.catch(next)
})

// UPDATE
// PATCH /campaigns/5a7db6c74d55bc51bdf39793
router.patch('/campaigns/:id', (req, res, next) => {
	Campaign.findById(req.params.id)
		.then(handle404)
		.then((campaign) => {
			return campaign.updateOne(req.body.campaign)
		})
		.then(() => res.sendStatus(204))
		.catch(next)
})

// DESTROY
// DELETE /campaigns/5a7db6c74d55bc51bdf39793
router.delete('/campaigns/:id', (req, res, next) => {
	Campaign.findById(req.params.id)
		.then(handle404)
		.then((campaign) => {
			campaign.deleteOne()
		})
		.then(() => res.sendStatus(204))
		.catch(next)
})

// exporting the router to use elsewhere
module.exports = router