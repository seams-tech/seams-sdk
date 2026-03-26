// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { PackedUserOperation } from "../src/interfaces/IAccount.sol";
import { SmartAccountInit } from "../src/interfaces/ITatchiSmartAccount.sol";
import { TatchiSmartAccount } from "../src/TatchiSmartAccount.sol";
import { TestBase } from "./TestBase.sol";

contract CallReceiver {
  uint256 public value;
  uint256 public calls;

  function setValue(uint256 newValue) external payable returns (bytes32) {
    value = newValue;
    calls += 1;
    return keccak256(abi.encode(newValue, msg.value, calls));
  }

  function failWith(bytes memory revertData) external pure {
    assembly {
      revert(add(revertData, 0x20), mload(revertData))
    }
  }
}

contract TatchiSmartAccountTest is TestBase {
  bytes32 private constant DOMAIN_TYPEHASH =
    keccak256(
      "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
  bytes32 private constant RECOVERY_TYPEHASH =
    keccak256(
      "RecoverAddOwner(bytes32 nearAccountIdHash,bytes32 newNearKeyHash,address newOwner,bytes32 recoverySessionHash,uint256 nonce,uint256 deadline)"
    );
  bytes32 private constant RECOVERY_NAME_HASH = keccak256("TatchiSmartAccountRecovery");
  bytes32 private constant RECOVERY_VERSION_HASH = keccak256("1");

  uint256 private constant OWNER_ONE_PK = 0xA11CE;
  uint256 private constant OWNER_TWO_PK = 0xB0B;
  uint256 private constant OWNER_THREE_PK = 0xCAFE;
  uint256 private constant AUTHORITY_PK = 0xD00D;

  TatchiSmartAccount private account;
  address private ownerOne;
  address private ownerTwo;
  address private ownerThree;
  address private authority;
  address private entryPoint;

  function setUp() public {
    ownerOne = vm.addr(OWNER_ONE_PK);
    ownerTwo = vm.addr(OWNER_TWO_PK);
    ownerThree = vm.addr(OWNER_THREE_PK);
    authority = vm.addr(AUTHORITY_PK);
    entryPoint = address(0xEE01);

    account = new TatchiSmartAccount();

    address[] memory owners = new address[](2);
    owners[0] = ownerOne;
    owners[1] = ownerTwo;

    account.initialize(
      SmartAccountInit({
        nearAccountIdHash: keccak256(bytes("alice.testnet")),
        recoveryAuthority: authority,
        entryPoint: entryPoint,
        owners: owners
      })
    );
  }

  function testInitializeSetsStateAndRejectsSecondRun() public {
    assertEq(account.nearAccountIdHash(), keccak256(bytes("alice.testnet")), "near binding");
    assertEq(account.recoveryAuthority(), authority, "authority");
    assertEq(account.entryPoint(), entryPoint, "entry point");
    assertEq(account.ownerCount(), 2, "owner count");
    assertTrue(account.isOwner(ownerOne), "owner one active");
    assertTrue(account.isOwner(ownerTwo), "owner two active");

    address[] memory owners = account.getOwners();
    assertEq(owners.length, 2, "owners length");
    assertEq(owners[0], ownerOne, "owner one order");
    assertEq(owners[1], ownerTwo, "owner two order");

    address[] memory replacementOwners = new address[](1);
    replacementOwners[0] = ownerThree;

    vm.expectRevert(abi.encodeWithSelector(TatchiSmartAccount.AlreadyInitialized.selector));
    account.initialize(
      SmartAccountInit({
        nearAccountIdHash: keccak256(bytes("bob.testnet")),
        recoveryAuthority: authority,
        entryPoint: entryPoint,
        owners: replacementOwners
      })
    );
  }

  function testInitializeRejectsInvalidInputs() public {
    TatchiSmartAccount invalidNearAccount = new TatchiSmartAccount();
    address[] memory owners = new address[](1);
    owners[0] = ownerOne;

    vm.expectRevert(
      abi.encodeWithSelector(TatchiSmartAccount.InvalidNearAccountBinding.selector)
    );
    invalidNearAccount.initialize(
      SmartAccountInit({
        nearAccountIdHash: bytes32(0),
        recoveryAuthority: authority,
        entryPoint: entryPoint,
        owners: owners
      })
    );

    TatchiSmartAccount invalidAuthorityAccount = new TatchiSmartAccount();
    vm.expectRevert(
      abi.encodeWithSelector(TatchiSmartAccount.InvalidRecoveryAuthority.selector)
    );
    invalidAuthorityAccount.initialize(
      SmartAccountInit({
        nearAccountIdHash: keccak256(bytes("alice.testnet")),
        recoveryAuthority: address(0),
        entryPoint: entryPoint,
        owners: owners
      })
    );

    TatchiSmartAccount emptyOwnersAccount = new TatchiSmartAccount();
    address[] memory noOwners = new address[](0);
    vm.expectRevert(abi.encodeWithSelector(TatchiSmartAccount.InvalidOwner.selector));
    emptyOwnersAccount.initialize(
      SmartAccountInit({
        nearAccountIdHash: keccak256(bytes("alice.testnet")),
        recoveryAuthority: authority,
        entryPoint: entryPoint,
        owners: noOwners
      })
    );

    TatchiSmartAccount zeroOwnerAccount = new TatchiSmartAccount();
    address[] memory zeroOwnerList = new address[](1);
    zeroOwnerList[0] = address(0);
    vm.expectRevert(abi.encodeWithSelector(TatchiSmartAccount.InvalidOwner.selector));
    zeroOwnerAccount.initialize(
      SmartAccountInit({
        nearAccountIdHash: keccak256(bytes("alice.testnet")),
        recoveryAuthority: authority,
        entryPoint: entryPoint,
        owners: zeroOwnerList
      })
    );

    TatchiSmartAccount duplicateOwnerAccount = new TatchiSmartAccount();
    address[] memory duplicateOwners = new address[](2);
    duplicateOwners[0] = ownerOne;
    duplicateOwners[1] = ownerOne;
    vm.expectRevert(
      abi.encodeWithSelector(TatchiSmartAccount.OwnerAlreadyExists.selector, ownerOne)
    );
    duplicateOwnerAccount.initialize(
      SmartAccountInit({
        nearAccountIdHash: keccak256(bytes("alice.testnet")),
        recoveryAuthority: authority,
        entryPoint: entryPoint,
        owners: duplicateOwners
      })
    );
  }

  function testOwnerManagementAllowsOwnerAndEntryPoint() public {
    vm.prank(ownerOne);
    account.addOwner(ownerThree);

    assertTrue(account.isOwner(ownerThree), "owner added");
    assertEq(account.ownerCount(), 3, "owner count after add");

    vm.prank(entryPoint);
    account.removeOwner(ownerThree);

    assertFalse(account.isOwner(ownerThree), "owner removed");
    assertEq(account.ownerCount(), 2, "owner count after remove");

    vm.expectRevert(abi.encodeWithSelector(TatchiSmartAccount.NotOwner.selector));
    vm.prank(address(0x1234));
    account.addOwner(address(0x9999));
  }

  function testRemoveOwnerProtectsLastOwner() public {
    vm.prank(ownerOne);
    account.removeOwner(ownerTwo);

    vm.expectRevert(
      abi.encodeWithSelector(TatchiSmartAccount.LastOwnerRemovalForbidden.selector)
    );
    vm.prank(ownerOne);
    account.removeOwner(ownerOne);
  }

  function testExecuteAndBatchExecution() public {
    CallReceiver receiver = new CallReceiver();

    vm.prank(ownerOne);
    bytes memory result =
      account.execute(address(receiver), 0, abi.encodeCall(CallReceiver.setValue, (41)));

    assertEq(receiver.value(), 41, "single execute value");
    assertEq(receiver.calls(), 1, "single execute calls");
    assertEq(result.length, 32, "single execute return length");

    address[] memory targets = new address[](2);
    uint256[] memory values = new uint256[](2);
    bytes[] memory data = new bytes[](2);

    targets[0] = address(receiver);
    targets[1] = address(receiver);
    values[0] = 0;
    values[1] = 0;
    data[0] = abi.encodeCall(CallReceiver.setValue, (42));
    data[1] = abi.encodeCall(CallReceiver.setValue, (43));

    vm.prank(entryPoint);
    bytes[] memory responses = account.executeBatch(targets, values, data);

    assertEq(receiver.value(), 43, "batch final value");
    assertEq(receiver.calls(), 3, "batch calls");
    assertEq(responses.length, 2, "batch response length");

    bytes[] memory shortData = new bytes[](1);
    shortData[0] = abi.encodeCall(CallReceiver.setValue, (99));

    vm.expectRevert(abi.encodeWithSelector(TatchiSmartAccount.ArrayLengthMismatch.selector));
    vm.prank(ownerOne);
    account.executeBatch(targets, values, shortData);
  }

  function testExecutionRejectsZeroAddressTargets() public {
    vm.expectRevert(abi.encodeWithSelector(TatchiSmartAccount.InvalidExecutionTarget.selector));
    vm.prank(ownerOne);
    account.execute(address(0), 0, "");

    address[] memory targets = new address[](1);
    uint256[] memory values = new uint256[](1);
    bytes[] memory data = new bytes[](1);
    targets[0] = address(0);
    values[0] = 0;
    data[0] = "";

    vm.expectRevert(abi.encodeWithSelector(TatchiSmartAccount.InvalidExecutionTarget.selector));
    vm.prank(ownerOne);
    account.executeBatch(targets, values, data);
  }

  function testExecuteBubblesRevertData() public {
    CallReceiver receiver = new CallReceiver();
    bytes memory revertData = abi.encodeWithSignature("Error(string)", "receiver-failed");

    vm.expectRevert(revertData);
    vm.prank(ownerOne);
    account.execute(address(receiver), 0, abi.encodeCall(CallReceiver.failWith, (revertData)));
  }

  function testVerifyAndRecoverIsPublicAndSharesReplayStore() public {
    bytes32 nearHash = keccak256(bytes("alice.testnet"));
    bytes32 newNearKeyHash = keccak256(bytes("ed25519:recovery-key"));
    bytes32 sessionHash = keccak256(bytes("session-123"));
    uint256 nonce = uint256(keccak256(bytes("shared-recovery-nonce")));
    uint256 deadline = block.timestamp + 1 days;

    bytes32 digest =
      _recoveryDigest(nearHash, newNearKeyHash, ownerThree, sessionHash, nonce, deadline);
    bytes memory authoritySignature = _signDigest(AUTHORITY_PK, digest);

    vm.prank(address(0xBEEF));
    account.verifyAndRecover(
      nearHash,
      newNearKeyHash,
      ownerThree,
      sessionHash,
      nonce,
      deadline,
      authoritySignature
    );

    assertTrue(account.isOwner(ownerThree), "recovered owner active");
    assertTrue(account.isRecoveryNonceUsed(bytes32(nonce)), "nonce consumed");
    assertEq(account.ownerCount(), 3, "owner count after recovery");

    vm.expectRevert(
      abi.encodeWithSelector(
        TatchiSmartAccount.RecoveryNonceAlreadyUsed.selector, bytes32(nonce)
      )
    );
    vm.prank(address(0xCA11));
    account.recoverAddOwner(
      nearHash,
      newNearKeyHash,
      address(0x4444),
      sessionHash,
      nonce,
      deadline,
      authoritySignature
    );
  }

  function testRecoveryRejectsBadBindingAndExpiredAuthorization() public {
    bytes32 correctNearHash = keccak256(bytes("alice.testnet"));
    bytes32 wrongNearHash = keccak256(bytes("wrong.testnet"));
    bytes32 newNearKeyHash = keccak256(bytes("ed25519:new-key"));
    bytes32 sessionHash = keccak256(bytes("session-expired"));
    uint256 nonce = 77;
    uint256 deadline = block.timestamp + 1 hours;

    bytes memory validSignature = _signDigest(
      AUTHORITY_PK,
      _recoveryDigest(correctNearHash, newNearKeyHash, ownerThree, sessionHash, nonce, deadline)
    );

    vm.expectRevert(abi.encodeWithSelector(TatchiSmartAccount.InvalidNearAccountBinding.selector));
    account.verifyAndRecover(
      wrongNearHash,
      newNearKeyHash,
      ownerThree,
      sessionHash,
      nonce,
      deadline,
      validSignature
    );

    vm.expectRevert(
      abi.encodeWithSelector(
        TatchiSmartAccount.RecoveryAuthorizationExpired.selector,
        block.timestamp - 1,
        block.timestamp
      )
    );
    account.verifyAndRecover(
      correctNearHash,
      newNearKeyHash,
      ownerThree,
      sessionHash,
      88,
      block.timestamp - 1,
      validSignature
    );
  }

  function testRecoveryRejectsBadSignerAndDuplicateOwner() public {
    bytes32 nearHash = keccak256(bytes("alice.testnet"));
    bytes32 newNearKeyHash = keccak256(bytes("ed25519:new-key"));
    bytes32 sessionHash = keccak256(bytes("session-bad-signer"));
    uint256 nonce = 111;
    uint256 deadline = block.timestamp + 1 days;
    bytes32 digest =
      _recoveryDigest(nearHash, newNearKeyHash, ownerThree, sessionHash, nonce, deadline);

    bytes memory invalidSignature = _signDigest(OWNER_ONE_PK, digest);

    vm.expectRevert(abi.encodeWithSelector(TatchiSmartAccount.InvalidRecoverySignature.selector));
    account.verifyAndRecover(
      nearHash,
      newNearKeyHash,
      ownerThree,
      sessionHash,
      nonce,
      deadline,
      invalidSignature
    );

    bytes memory duplicateOwnerSignature = _signDigest(
      AUTHORITY_PK,
      _recoveryDigest(nearHash, newNearKeyHash, ownerTwo, sessionHash, nonce + 1, deadline)
    );

    vm.expectRevert(
      abi.encodeWithSelector(TatchiSmartAccount.OwnerAlreadyExists.selector, ownerTwo)
    );
    account.verifyAndRecover(
      nearHash,
      newNearKeyHash,
      ownerTwo,
      sessionHash,
      nonce + 1,
      deadline,
      duplicateOwnerSignature
    );
  }

  function testRecoveryAuthorizationCannotReplayAcrossDifferentAccounts() public {
    TatchiSmartAccount secondAccount = new TatchiSmartAccount();
    address[] memory owners = new address[](2);
    owners[0] = ownerOne;
    owners[1] = ownerTwo;
    secondAccount.initialize(
      SmartAccountInit({
        nearAccountIdHash: keccak256(bytes("alice.testnet")),
        recoveryAuthority: authority,
        entryPoint: entryPoint,
        owners: owners
      })
    );

    bytes32 nearHash = keccak256(bytes("alice.testnet"));
    bytes32 newNearKeyHash = keccak256(bytes("ed25519:recovery-key"));
    bytes32 sessionHash = keccak256(bytes("session-target-bound"));
    uint256 nonce = 222;
    uint256 deadline = block.timestamp + 1 days;
    bytes32 digest =
      _recoveryDigest(address(account), nearHash, newNearKeyHash, ownerThree, sessionHash, nonce, deadline);
    bytes memory authoritySignature = _signDigest(AUTHORITY_PK, digest);

    vm.expectRevert(abi.encodeWithSelector(TatchiSmartAccount.InvalidRecoverySignature.selector));
    secondAccount.verifyAndRecover(
      nearHash,
      newNearKeyHash,
      ownerThree,
      sessionHash,
      nonce,
      deadline,
      authoritySignature
    );

    account.verifyAndRecover(
      nearHash,
      newNearKeyHash,
      ownerThree,
      sessionHash,
      nonce,
      deadline,
      authoritySignature
    );

    assertTrue(account.isOwner(ownerThree), "signature stays valid for the bound account only");
    assertFalse(secondAccount.isOwner(ownerThree), "replay target did not gain recovered owner");
  }

  function testRecoveredOwnerCannotBeRemovedByLegacyOwners() public {
    bytes32 nearHash = keccak256(bytes("alice.testnet"));
    bytes32 newNearKeyHash = keccak256(bytes("ed25519:recovery-key"));
    bytes32 sessionHash = keccak256(bytes("session-race-protection"));
    uint256 nonce = 333;
    uint256 deadline = block.timestamp + 1 days;
    bytes32 digest =
      _recoveryDigest(nearHash, newNearKeyHash, ownerThree, sessionHash, nonce, deadline);
    bytes memory authoritySignature = _signDigest(AUTHORITY_PK, digest);

    account.verifyAndRecover(
      nearHash,
      newNearKeyHash,
      ownerThree,
      sessionHash,
      nonce,
      deadline,
      authoritySignature
    );

    vm.expectRevert(
      abi.encodeWithSelector(TatchiSmartAccount.RecoveredOwnerProtected.selector, ownerThree)
    );
    vm.prank(ownerOne);
    account.removeOwner(ownerThree);

    vm.prank(ownerThree);
    account.removeOwner(ownerOne);

    assertTrue(account.isOwner(ownerThree), "recovered owner stays active");
    assertFalse(account.isOwner(ownerOne), "recovered owner can remove stale legacy owner");
  }

  function testIsValidSignatureRecognizesActiveOwner() public {
    bytes32 digest = keccak256(bytes("owner-signature-test"));
    bytes memory ownerSignature = _signDigest(OWNER_ONE_PK, digest);
    bytes memory outsiderSignature = _signDigest(AUTHORITY_PK, digest);
    bytes4 ownerResult = account.isValidSignature(digest, ownerSignature);
    bytes4 outsiderResult = account.isValidSignature(digest, outsiderSignature);

    assertTrue(ownerResult == bytes4(0x1626ba7e), "owner signature valid");
    assertTrue(outsiderResult == bytes4(0xffffffff), "outsider signature invalid");
  }

  function testValidateUserOpAllowsConfiguredEntryPointAndPaysPrefund() public {
    PackedUserOperation memory userOp = PackedUserOperation({
      sender: address(account),
      nonce: 1,
      initCode: "",
      callData: abi.encodeCall(CallReceiver.setValue, (55)),
      accountGasLimits: bytes32(0),
      preVerificationGas: 0,
      gasFees: bytes32(0),
      paymasterAndData: "",
      signature: ""
    });
    bytes32 userOpHash = keccak256(bytes("user-op-hash"));
    userOp.signature = _signDigest(OWNER_ONE_PK, userOpHash);

    vm.deal(address(account), 1 ether);
    uint256 entryPointBalanceBefore = entryPoint.balance;

    vm.prank(entryPoint);
    uint256 validationData = account.validateUserOp(userOp, userOpHash, 0.1 ether);

    assertEq(validationData, 0, "validation success");
    assertEq(entryPoint.balance, entryPointBalanceBefore + 0.1 ether, "prefund paid");
  }

  function testValidateUserOpRejectsUnexpectedCallerAndBadSignature() public {
    PackedUserOperation memory userOp = PackedUserOperation({
      sender: address(account),
      nonce: 2,
      initCode: "",
      callData: "",
      accountGasLimits: bytes32(0),
      preVerificationGas: 0,
      gasFees: bytes32(0),
      paymasterAndData: "",
      signature: ""
    });
    bytes32 userOpHash = keccak256(bytes("invalid-user-op-hash"));
    userOp.signature = _signDigest(AUTHORITY_PK, userOpHash);

    vm.expectRevert(abi.encodeWithSelector(TatchiSmartAccount.InvalidEntryPoint.selector));
    account.validateUserOp(userOp, userOpHash, 0);

    vm.prank(entryPoint);
    uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
    assertEq(validationData, 1, "signature failure");
  }

  function testValidateUserOpRejectsSenderMismatch() public {
    PackedUserOperation memory userOp = PackedUserOperation({
      sender: address(0x1234),
      nonce: 3,
      initCode: "",
      callData: "",
      accountGasLimits: bytes32(0),
      preVerificationGas: 0,
      gasFees: bytes32(0),
      paymasterAndData: "",
      signature: ""
    });
    bytes32 userOpHash = keccak256(bytes("sender-mismatch-user-op"));
    userOp.signature = _signDigest(OWNER_ONE_PK, userOpHash);

    vm.expectRevert(
      abi.encodeWithSelector(TatchiSmartAccount.InvalidUserOpSender.selector, userOp.sender)
    );
    vm.prank(entryPoint);
    account.validateUserOp(userOp, userOpHash, 0);
  }

  function _recoveryDigest(
    address verifyingAccount,
    bytes32 nearAccountIdHash,
    bytes32 newNearKeyHash,
    address newOwner,
    bytes32 recoverySessionHash,
    uint256 nonce,
    uint256 deadline
  ) internal view returns (bytes32) {
    bytes32 domainSeparator = keccak256(
      abi.encode(
        DOMAIN_TYPEHASH,
        RECOVERY_NAME_HASH,
        RECOVERY_VERSION_HASH,
        block.chainid,
        verifyingAccount
      )
    );
    bytes32 structHash = keccak256(
      abi.encode(
        RECOVERY_TYPEHASH,
        nearAccountIdHash,
        newNearKeyHash,
        newOwner,
        recoverySessionHash,
        nonce,
        deadline
      )
    );
    return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
  }

  function _recoveryDigest(
    bytes32 nearAccountIdHash,
    bytes32 newNearKeyHash,
    address newOwner,
    bytes32 recoverySessionHash,
    uint256 nonce,
    uint256 deadline
  ) internal view returns (bytes32) {
    return _recoveryDigest(
      address(account),
      nearAccountIdHash,
      newNearKeyHash,
      newOwner,
      recoverySessionHash,
      nonce,
      deadline
    );
  }
}
