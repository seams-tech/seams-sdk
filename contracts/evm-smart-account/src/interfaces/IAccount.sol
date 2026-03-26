// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

struct PackedUserOperation {
  address sender;
  uint256 nonce;
  bytes initCode;
  bytes callData;
  bytes32 accountGasLimits;
  uint256 preVerificationGas;
  bytes32 gasFees;
  bytes paymasterAndData;
  bytes signature;
}

interface IAccount {
  function validateUserOp(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingAccountFunds
  ) external returns (uint256 validationData);
}
