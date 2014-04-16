'use strict'

var ursa = require('ursa')
var crypto = require('crypto')

module.exports = function(private_key, password) {

	if (typeof password === 'string') {
		var decipher = crypto.createDecipher('aes256', password)
		private_key = decipher.update(private_key, 'base64', 'utf8') + decipher.final('utf8')
	}

	if (typeof private_key === 'string') {
		private_key = ursa.createPrivateKey(private_key, undefined, 'base64')
	}

	var signer = ursa.createSigner('sha256')

	this.sign = function(message) {
		if (typeof message !== 'string') {
			throw 'messages must already be strings to sign them'
		}
		signer.update(message, 'utf8')
		return signer.sign(private_key, 'base64')
	}

	this.decrypt = function(message) {
		return private_key.decrypt(message, 'base64', 'utf8')
	}

	this.toString = function(password) {
		if (typeof password !== 'string') {
			throw 'private key should always be encrypted to a password'
		}
		var cipher = crypto.createCipher('aes256', password)
		return cipher.update(private_key.toPrivatePem('base64'), 'utf8', 'base64') + cipher.final('base64')
	}

}
