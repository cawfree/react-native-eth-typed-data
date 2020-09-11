import { ethers } from 'ethers';
import { Buffer } from 'buffer';

import EIP712Domain from './Domain'

/**
 * Verify that a particular object was signed by a given
 */
export function verify(request, signature, address) {
  const { domain, message } = EIP712Domain.fromSignatureRequest(request)

  if (!message.verifySignature(signature, address)) {
    throw new Error('Invalid signature for address over this object')
  }

  return { domain, message }
}

/**
 * Verify a signed hash made by the owner of a particular ethereum address
 * returning true if the signature is valid, and false otherwise
 * @param   {Buffer}  data qq
 * @param   {Object}  signature 
 * @param   {String}  address 
 * @returns {Boolean} indicator of the signature's validity
 */
export function verifyRawSignatureFromAddress(data, signature, address) {
  const normalizedAddress = ethers.utils.getAddress(address);
  return ethers.utils.verifyMessage(ethers.utils.arrayify(data), signature) === normalizedAddress;
};
