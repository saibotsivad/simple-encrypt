'use strict'

var ursa = require('ursa')
var PublicKey = require('./public-key.js')
var PrivateKey = require('./private-key.js')

module.exports = function(configs) {

	if (configs === undefined) {
		var key = ursa.generatePrivateKey(2048, 65537)
		this.privateKey = new PrivateKey(key.toPrivatePem('base64'))
		this.publicKey = new PublicKey(key.toPublicPem('base64'))
	} else {
		if (configs.pair) {
			var keypair_text_array = configs.pair.split('\r\n')
			if (keypair_text_array.length !== 2) {
				throw 'invalid keypair input'
			}
			configs.privateKey = keypair_text_array[0]
			configs.publicKey = keypair_text_array[1]
		}
		if (configs.privateKey) {
			this.privateKey = new PrivateKey(configs.privateKey, configs.password)
		}
		if (configs.publicKey) {
			this.publicKey = new PublicKey(configs.publicKey)
		}
	}

	var self = this
	this.toString = function(password) {
		return self.privateKey.toString(password) + '\r\n' + self.publicKey.toString()
	}

}
