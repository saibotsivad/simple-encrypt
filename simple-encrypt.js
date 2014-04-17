'use strict'

var ursa = require('ursa')
var crypto = require('crypto')

module.exports = function(configs) {
	var keys, password

	if (!configs) {
		keys = ursa.generatePrivateKey(2048, 65537)
	} else {
		if (configs.publicKey && !configs.privateKey) {
			keys = ursa.createPublicKey(configs.publicKey, 'base64')
		} else if (configs.privateKey) {
			password = configs.password
			if (typeof password !== 'string') {
				throw 'password is required for private keys'
			}
			var decipher = crypto.createDecipher('aes256', password)
			var decrypted = decipher.update(configs.privateKey, 'base64', 'utf8') + decipher.final('utf8')
			keys = ursa.createPrivateKey(decrypted, undefined, 'base64')
		}
	}

	ursa.assertKey(keys)

	return {
		sign: function(message) {
			if (typeof message !== 'string') {
				throw 'message must already be string to sign'
			}
			if (!ursa.isPrivateKey(keys)) {
				throw 'private key not initialized correctly'
			}
			var signer = ursa.createSigner('sha256')
			signer.update(message, 'utf8')
			return signer.sign(keys, 'base64')
		},
		verify: function(message, signature) {
			if (typeof message !== 'string') {
				throw 'message must already be a string to verify signature'
			}
			if (!ursa.isKey(keys)) {
				throw 'public key not initialized correctly'
			}
			var verifier = ursa.createVerifier('sha256')
			verifier.update(message, 'utf8')
			return verifier.verify(keys, signature, 'base64')
		},
		decrypt: function(message) {
			if (!ursa.isPrivateKey(keys)) {
				throw 'private key not initialized correctly'
			}
			return keys.decrypt(message, 'base64', 'utf8')
		},
		encrypt: function(message) {
			if (typeof message !== 'string') {
				throw 'message must already be a string to encrypt'
			}
			if (!ursa.isKey(keys)) {
				throw 'public key not initialized correctly'
			}
			return keys.encrypt(message, 'utf8', 'base64')
		},
		exportPrivateKey: function(secret) {
			if (typeof secret !== 'string') {
				secret = password
			}
			if (typeof secret !== 'string') {
				throw 'private key cannot be extracted unencrypted'
			}
			var cipher = crypto.createCipher('aes256', secret)
			return cipher.update(keys.toPrivatePem('base64'), 'utf8', 'base64') + cipher.final('base64')
		},
		exportPublicKey: function() {
			return keys.toPublicPem('base64')
		}
	}

}
