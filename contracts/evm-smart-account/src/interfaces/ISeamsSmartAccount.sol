// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { IAccount } from "./IAccount.sol";
import { IERC1271 } from "./IERC1271.sol";

struct SmartAccountInit {
  bytes32 nearAccountIdHash;
  address recoveryAuthority;
  address entryPoint;
  address[] owners;
}

interface ISeamsSmartAccountView {
  function accountVersion() external pure returns (uint256);
  function nearAccountIdHash() external view returns (bytes32);
  function recoveryAuthority() external view returns (address);
  function entryPoint() external view returns (address);
  function isOwner(address owner) external view returns (bool);
  function getOwners() external view returns (address[] memory);
  function ownerCount() external view returns (uint256);
  function isRecoveryNonceUsed(bytes32 nonce) external view returns (bool);
}

interface ISeamsSmartAccountOwners {
  function addOwner(address owner) external;
  function removeOwner(address owner) external;
}

interface ISeamsSmartAccountRecovery {
  function verifyAndRecover(
    bytes32 nearAccountIdHash,
    bytes32 newNearKeyHash,
    address newOwner,
    bytes32 recoverySessionHash,
    uint256 nonce,
    uint256 deadline,
    bytes calldata authoritySignature
  ) external;

  function recoverAddOwner(
    bytes32 nearAccountIdHash,
    bytes32 newNearKeyHash,
    address newOwner,
    bytes32 recoverySessionHash,
    uint256 nonce,
    uint256 deadline,
    bytes calldata authoritySignature
  ) external;
}

interface ISeamsSmartAccountExecution {
  function execute(address target, uint256 value, bytes calldata data)
    external
    payable
    returns (bytes memory);

  function executeBatch(
    address[] calldata targets,
    uint256[] calldata values,
    bytes[] calldata data
  ) external payable returns (bytes[] memory);
}

interface ISeamsSmartAccount is
  ISeamsSmartAccountView,
  ISeamsSmartAccountOwners,
  ISeamsSmartAccountRecovery,
  ISeamsSmartAccountExecution,
  IAccount,
  IERC1271
{}

interface ISeamsSmartAccountFactory {
  function createAccount(bytes32 salt, bytes calldata initData) external returns (address account);
  function getAddress(bytes32 salt, bytes calldata initData) external view returns (address account);
  function computeDeploymentSalt(bytes32 salt, bytes calldata initData)
    external
    pure
    returns (bytes32 deploymentSalt);
  function accountCreationCodeHash() external pure returns (bytes32 codeHash);
}
