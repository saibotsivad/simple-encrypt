'use strict'

var ursa = require('ursa')

module.exports = function(public_key) {

	if (typeof public_key === 'string') {
		public_key = ursa.createPublicKey(public_key, 'base64')
	}

	var verifier = ursa.createVerifier('sha256')

	this.verifySignature = function(message, signature) {
		if (typeof message !== 'string') {
			throw 'message must already be a string to verify signature'
		}
		verifier.update(message, 'utf8')
		return verifier.verify(public_key, signature, 'base64')
	}

	this.encrypt = function(message) {
		if (typeof message !== 'string') {
			message = JSON.stringify(message)
		}
		return public_key.encrypt(message, 'utf8', 'base64')
	}

	this.toString = function() {
		return public_key.toPublicPem('base64')
	}

}
