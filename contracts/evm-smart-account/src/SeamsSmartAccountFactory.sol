// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { ISeamsSmartAccountFactory, SmartAccountInit } from "./interfaces/ISeamsSmartAccount.sol";
import { SeamsSmartAccount } from "./SeamsSmartAccount.sol";

contract SeamsSmartAccountFactory is ISeamsSmartAccountFactory {
  event AccountCreated(address indexed account, bytes32 indexed salt, bytes32 indexed initDataHash);

  function accountCreationCodeHash() public pure returns (bytes32 codeHash) {
    return keccak256(type(SeamsSmartAccount).creationCode);
  }

  function createAccount(bytes32 salt, bytes calldata initData) external returns (address account) {
    account = getAddress(salt, initData);
    if (account.code.length > 0) return account;

    SeamsSmartAccount deployed =
      new SeamsSmartAccount{ salt: computeDeploymentSalt(salt, initData) }();
    SmartAccountInit memory init = abi.decode(initData, (SmartAccountInit));
    deployed.initialize(init);

    account = address(deployed);
    emit AccountCreated(account, salt, keccak256(initData));
  }

  function getAddress(bytes32 salt, bytes calldata initData) public view returns (address account) {
    bytes32 deployedHash = keccak256(
      abi.encodePacked(
        bytes1(0xff), address(this), computeDeploymentSalt(salt, initData), accountCreationCodeHash()
      )
    );
    return address(uint160(uint256(deployedHash)));
  }

  function computeDeploymentSalt(bytes32 salt, bytes calldata initData)
    public
    pure
    returns (bytes32 deploymentSalt)
  {
    return keccak256(abi.encode(salt, keccak256(initData)));
  }
}
