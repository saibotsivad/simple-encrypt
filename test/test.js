'use strict'

var test = require('tap').test
var fs = require('fs')
var SimpleEncrypt = require('../')

test('message signing', function(t) {
	var simple = new SimpleEncrypt()
	var message = 'dogecoins are hilarious'
	var signature = simple.sign(message)
	t.true(simple.verify(message, signature))
	t.end()
})

test('message encryption', function(t) {
	var simple = new SimpleEncrypt()
	var message = 'dogecoins are hilarious'
	var encrypted_message = simple.encrypt(message)
	t.equal(simple.decrypt(encrypted_message), message)
	t.end()
})

test('saving the encrypted private/public key', function(t) {
	var simple = new SimpleEncrypt()
	var message = 'dogecoins are hilarious'
	var password = 'mysupersecretpassword'

	var encrypted_message = simple.encrypt(message)
	var stringified_secret_key = simple.exportPrivateKey(password)

	var new_simple = new SimpleEncrypt({ privateKey: stringified_secret_key, password: password })
	var decrypted_message = new_simple.decrypt(encrypted_message)

	t.true(message === decrypted_message)
	t.end()
})

test('testing a private/public key saved to disk', function(t) {
	var public_key_file = fs.readFileSync('./test-key.pub')
	var private_key_file = fs.readFileSync('./test-key.sec')
	var password = 'mysupersecretpassword'
	var message = 'dogecoins are hilarious'

	var simple_secret = new SimpleEncrypt({
		privateKey: private_key_file.toString(),
		password: password
	})
	var signature = simple_secret.sign(message)

	var simple_public = new SimpleEncrypt({
		publicKey: public_key_file.toString()
	})
	t.true(simple_public.verify(message, signature))

	var encrypted_message = simple_public.encrypt(message)
	t.equal(simple_secret.decrypt(encrypted_message), message)

	t.end()
})

test('private key without password fails', function(t) {
	var private_key_file = fs.readFileSync('./test-key.sec')

	t.plan(1)
	try {
		new SimpleEncrypt({ privateKey: private_key_file.toString() })
	} catch (e) {
		t.ok(true, 'should throw exception')
	}
	t.end()
})

test('private key with wrong password fails', function(t) {
	var private_key_file = fs.readFileSync('./test-key.sec')

	t.plan(1)
	try {
		new SimpleEncrypt({ privateKey: private_key_file.toString(), password: 'the wrong password' })
	} catch (e) {
		t.ok(true, 'should throw exception')
	}
	t.end()
})

test('bad private key fails', function(t) {
	t.plan(1)
	try {
		new SimpleEncrypt({ privateKey: 'not a real key', password: 'not a real password' })
	} catch (e) {
		t.ok(true, 'should throw exception')
	}
	t.end()
})
