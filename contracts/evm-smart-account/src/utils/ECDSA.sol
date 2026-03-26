// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

library ECDSA {
  uint256 private constant _SECP256K1N_DIV_2 =
    0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

  function recover(bytes32 hash, bytes memory signature) internal pure returns (address signer) {
    if (signature.length != 65) return address(0);

    bytes32 r;
    bytes32 s;
    uint8 v;

    assembly {
      r := mload(add(signature, 0x20))
      s := mload(add(signature, 0x40))
      v := byte(0, mload(add(signature, 0x60)))
    }

    if (uint256(s) > _SECP256K1N_DIV_2) return address(0);
    if (v != 27 && v != 28) return address(0);

    signer = ecrecover(hash, v, r, s);
  }
}
