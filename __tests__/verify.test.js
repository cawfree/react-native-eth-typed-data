import { verify, verifyRawSignatureFromAddress } from '../src/verify'
import { ethers } from 'ethers';

function wallet() {
  return ethers.Wallet.createRandom();
}

describe('verifyRawSignatureFromAddress', () => {
  it('verifies an arbitrary signature from a signature object', async () => {
    const w = wallet();
    const hash = Buffer.from('deadbeef', 'hex')
    const sig = await w.signMessage(hash)
    expect(verifyRawSignatureFromAddress(hash, sig, w.address)).toBe(true)
  })

  it('verifies a concatenated buffer signature', async () => {
    // TODO: use 100 for extra certainty
    for (let i = 0; i < 1; i++) {
      const w = wallet();
      const hash = Buffer.from('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', 'hex')
      const sig = await w.signMessage(hash);
      const buf = ethers.utils.joinSignature(sig);
      expect(verifyRawSignatureFromAddress(hash, buf, w.address)).toBe
    }
  })
})

describe('verify', () => {
  const MailExample = require('./data/Mail.json')

  it('verifies a request', async () => {
    const w = wallet();
    const signHash = Buffer.from(MailExample.results.Mail.signHash.slice(2), 'hex')
    const sig = await w.signMessage(signHash)
    expect(() => verify(MailExample.request, sig, w.address)).not.toThrow()
  })

  it('throws an error for an invalid signature', async () => {
    const w = wallet();
    const signHash = Buffer.from(MailExample.results.Mail.signHash.slice(2), 'hex')
    const sig = await w.signMessage(signHash)
    const { address } = wallet();
    expect(() => verify(MailExample.request, sig, address)).toThrow()
  })
})
