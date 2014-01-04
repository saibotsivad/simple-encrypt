var pgp = require('../')
var test = require('tap').test

var key_pair = pgp.generate()
var public_key = pgp.publicKey(key_pair.public_key)
var private_key = pgp.privateKey(key_pair.private_key)

var message = 'dogecoins are hilarious'

test('message signing', function(t) {
	var signed_message = private_key.sign(message)
	t.true(public_key.verifySignature(message, signed_message))
	t.end()
})

test('message encryption', function(t) {
	var encrypted_message = public_key.encrypt(message)
	t.equal(private_key.decrypt(encrypted_message), message)
	t.end()
})
