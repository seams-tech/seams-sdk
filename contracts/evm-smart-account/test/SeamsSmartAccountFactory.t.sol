// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { SmartAccountInit } from "../src/interfaces/ISeamsSmartAccount.sol";
import { SeamsSmartAccount } from "../src/SeamsSmartAccount.sol";
import { SeamsSmartAccountFactory } from "../src/SeamsSmartAccountFactory.sol";
import { TestBase } from "./TestBase.sol";

contract SeamsSmartAccountFactoryTest is TestBase {
  uint256 private constant OWNER_ONE_PK = 0xA11CE;
  uint256 private constant OWNER_TWO_PK = 0xB0B;
  uint256 private constant OWNER_THREE_PK = 0xCAFE;
  uint256 private constant AUTHORITY_PK = 0xD00D;

  SeamsSmartAccountFactory private factory;
  address private ownerOne;
  address private ownerTwo;
  address private ownerThree;
  address private authority;
  address private entryPoint;

  function setUp() public {
    factory = new SeamsSmartAccountFactory();
    ownerOne = vm.addr(OWNER_ONE_PK);
    ownerTwo = vm.addr(OWNER_TWO_PK);
    ownerThree = vm.addr(OWNER_THREE_PK);
    authority = vm.addr(AUTHORITY_PK);
    entryPoint = address(0xEE01);
  }

  function testCreateAccountMatchesPredictedAddressAndInitializesState() public {
    bytes32 salt = keccak256(bytes("alice"));
    bytes memory initData = _encodeInitData(keccak256(bytes("alice.testnet")));

    address predicted = factory.getAddress(salt, initData);
    address deployed = factory.createAccount(salt, initData);

    assertEq(deployed, predicted, "predicted address matches");

    SeamsSmartAccount account = SeamsSmartAccount(payable(deployed));
    assertEq(account.recoveryAuthority(), authority, "factory authority");
    assertEq(account.entryPoint(), entryPoint, "factory entry point");
    assertEq(account.ownerCount(), 2, "factory owner count");

    address redeployed = factory.createAccount(salt, initData);
    assertEq(redeployed, deployed, "idempotent create");
  }

  function testGetAddressDependsOnInitDataHash() public view {
    bytes32 salt = keccak256(bytes("shared-salt"));
    bytes memory aliceInit = _encodeInitData(keccak256(bytes("alice.testnet")));
    bytes memory bobInit = _encodeInitData(keccak256(bytes("bob.testnet")));

    address aliceAddress = factory.getAddress(salt, aliceInit);
    address bobAddress = factory.getAddress(salt, bobInit);

    assertTrue(aliceAddress != bobAddress, "different init data produces different address");
  }

  function testFactoryHelpersMatchCreate2Derivation() public view {
    bytes32 salt = keccak256(bytes("helper-salt"));
    bytes memory initData = _encodeInitData(keccak256(bytes("alice.testnet")));

    bytes32 deploymentSalt = factory.computeDeploymentSalt(salt, initData);
    bytes32 codeHash = factory.accountCreationCodeHash();
    address predicted = factory.getAddress(salt, initData);
    address manual = address(
      uint160(
        uint256(
          keccak256(abi.encodePacked(bytes1(0xff), address(factory), deploymentSalt, codeHash))
        )
      )
    );

    assertEq(predicted, manual, "manual create2 derivation");
  }

  function testCreateAccountBubblesInitializerFailure() public {
    bytes32 salt = keccak256(bytes("duplicate-owner-init"));
    address[] memory owners = new address[](2);
    owners[0] = ownerOne;
    owners[1] = ownerOne;

    bytes memory invalidInitData = abi.encode(
      SmartAccountInit({
        nearAccountIdHash: keccak256(bytes("alice.testnet")),
        recoveryAuthority: authority,
        entryPoint: entryPoint,
        owners: owners
      })
    );

    vm.expectRevert(
      abi.encodeWithSelector(SeamsSmartAccount.OwnerAlreadyExists.selector, ownerOne)
    );
    factory.createAccount(salt, invalidInitData);
  }

  function testCreateAccountPreservesCanonicalOwnerOrderingAcrossUndeployedContinuations() public {
    bytes32 salt = keccak256(bytes("owner-ordering"));
    address[] memory owners = new address[](3);
    owners[0] = ownerTwo;
    owners[1] = ownerOne;
    owners[2] = ownerThree;

    bytes memory initData = abi.encode(
      SmartAccountInit({
        nearAccountIdHash: keccak256(bytes("alice.testnet")),
        recoveryAuthority: authority,
        entryPoint: entryPoint,
        owners: owners
      })
    );

    address deployed = factory.createAccount(salt, initData);
    SeamsSmartAccount account = SeamsSmartAccount(payable(deployed));

    address[] memory deployedOwners = account.getOwners();
    assertEq(deployedOwners.length, 3, "continuity owner count");
    assertEq(deployedOwners[0], ownerTwo, "preserves canonical owner ordering #1");
    assertEq(deployedOwners[1], ownerOne, "preserves canonical owner ordering #2");
    assertEq(deployedOwners[2], ownerThree, "preserves canonical owner ordering #3");
    assertTrue(account.isOwner(ownerOne), "owner one active after deploy");
    assertTrue(account.isOwner(ownerTwo), "owner two active after deploy");
    assertTrue(account.isOwner(ownerThree), "owner three active after deploy");
  }

  function _encodeInitData(bytes32 nearAccountIdHash_) internal view returns (bytes memory) {
    address[] memory owners = new address[](2);
    owners[0] = ownerOne;
    owners[1] = ownerTwo;

    return abi.encode(
      SmartAccountInit({
        nearAccountIdHash: nearAccountIdHash_,
        recoveryAuthority: authority,
        entryPoint: entryPoint,
        owners: owners
      })
    );
  }
}
