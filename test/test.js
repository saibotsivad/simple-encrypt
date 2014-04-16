'use strict'

var test = require('tap').test
var fs = require('fs')
var SimpleEncrypt = require('../')

test('message signing', function(t) {
	var simple = new SimpleEncrypt()
	var message = 'dogecoins are hilarious'
	var signature = simple.privateKey.sign(message)
	t.true(simple.publicKey.verifySignature(message, signature))
	t.end()
})

test('message encryption', function(t) {
	var simple = new SimpleEncrypt()
	var message = 'dogecoins are hilarious'
	var encrypted_message = simple.publicKey.encrypt(message)
	t.equal(simple.privateKey.decrypt(encrypted_message), message)
	t.end()
})

test('saving the encrypted private/public key', function(t) {
	var simple = new SimpleEncrypt()
	var message = 'dogecoins are hilarious'
	var password = 'mysupersecretpassword'

	var encrypted_message = simple.publicKey.encrypt(message)
	var stringified_secret_key = simple.privateKey.toString(password)

	var new_simple = new SimpleEncrypt({ privateKey: stringified_secret_key, password: password })
	var decrypted_message = new_simple.privateKey.decrypt(encrypted_message)

	t.true(message === decrypted_message)
	t.end()
})

test('testing a private/public key saved to disk', function(t) {
	var public_key_file = fs.readFileSync('./test-key.pub')
	var private_key_file = fs.readFileSync('./test-key.sec')
	var password = 'mysupersecretpassword'
	var message = 'dogecoins are hilarious'

	var simple = new SimpleEncrypt({
		publicKey: public_key_file.toString(),
		privateKey: private_key_file.toString(),
		password: password
	})

	var signature = simple.privateKey.sign(message)
	t.true(simple.publicKey.verifySignature(message, signature))

	var encrypted_message = simple.publicKey.encrypt(message)
	t.equal(simple.privateKey.decrypt(encrypted_message), message)

	t.end()
})

test('testing a private/public key saved to disk as single file', function(t) {
	var key_file = fs.readFileSync('./test-key.pair')
	var password = 'mysupersecretpassword'
	var message = 'dogecoins are hilarious'

	var simple = new SimpleEncrypt({
		pair: key_file.toString(),
		password: password
	})

	var signature = simple.privateKey.sign(message)
	t.true(simple.publicKey.verifySignature(message, signature))

	var encrypted_message = simple.publicKey.encrypt(message)
	t.equal(simple.privateKey.decrypt(encrypted_message), message)

	t.end()
})
