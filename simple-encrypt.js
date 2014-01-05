'use strict'

var ursa = require('ursa')

function generate() {
  var key = ursa.generatePrivateKey(2048, 65537)
  return {
    public_key: key.toPublicPem('base64'),
    private_key: key.toPrivatePem('base64')
  }
}

function privateKey(private_key, password) {
  if (password === undefined) {
    password = ''
  }

  if (typeof private_key === 'string') {
    private_key = ursa.createPrivateKey(private_key, password, 'base64')
  }

  var signer = ursa.createSigner('sha256')

  function sign(message) {
    if (typeof message === 'Object') {
      message = JSON.stringify(message)
    }

    signer.update(message, 'utf8')
    return signer.sign(private_key, 'base64')
  }

  function decrypt(message) {
    return private_key.decrypt(message, 'base64', 'utf8')
  }

  return {
    sign: sign,
    decrypt: decrypt
  }
}

function publicKey(public_key) {
  if (typeof public_key === 'string') {
    public_key = ursa.createPublicKey(public_key, 'base64')
  }

  var verifier = ursa.createVerifier('sha256')

  function verifySignature(message, signature) {
    if (typeof message === 'Object') {
      message = JSON.stringify(message)
    }

    verifier.update(message, 'utf8')
    return verifier.verify(public_key, signature, 'base64')
  }

  function encrypt(message) {
    if (typeof message === 'Object') {
      message = JSON.stringify(message)
    }

    return public_key.encrypt(message, 'utf8', 'base64')
  }

  return {
    verifySignature: verifySignature,
    encrypt: encrypt
  }
}

module.exports = {
  privateKey: privateKey,
  publicKey: publicKey,
  generate: generate
}