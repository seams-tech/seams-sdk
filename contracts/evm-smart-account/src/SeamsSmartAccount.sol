// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import { ISeamsSmartAccount, SmartAccountInit } from "./interfaces/ISeamsSmartAccount.sol";
import { PackedUserOperation } from "./interfaces/IAccount.sol";
import { ECDSA } from "./utils/ECDSA.sol";

contract SeamsSmartAccount is ISeamsSmartAccount {
  bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
  bytes4 internal constant ERC1271_INVALID_VALUE = 0xffffffff;
  uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
  uint256 internal constant SIG_VALIDATION_FAILED = 1;
  bytes32 internal constant DOMAIN_TYPEHASH =
    keccak256(
      "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
  bytes32 internal constant RECOVERY_TYPEHASH =
    keccak256(
      "RecoverAddOwner(bytes32 nearAccountIdHash,bytes32 newNearKeyHash,address newOwner,bytes32 recoverySessionHash,uint256 nonce,uint256 deadline)"
    );
  bytes32 internal constant RECOVERY_NAME_HASH = keccak256("SeamsSmartAccountRecovery");
  bytes32 internal constant RECOVERY_VERSION_HASH = keccak256("1");

  error AlreadyInitialized();
  error NotOwner();
  error InvalidOwner();
  error OwnerAlreadyExists(address owner);
  error OwnerDoesNotExist(address owner);
  error LastOwnerRemovalForbidden();
  error InvalidRecoveryAuthority();
  error InvalidNearAccountBinding();
  error RecoveryNonceAlreadyUsed(bytes32 nonce);
  error RecoveryAuthorizationExpired(uint256 deadline, uint256 nowTs);
  error InvalidRecoverySignature();
  error RecoveredOwnerProtected(address owner);
  error InvalidEntryPoint();
  error InvalidUserOpSender(address sender);
  error InvalidExecutionTarget();
  error ArrayLengthMismatch();
  error ExecutionFailed(bytes data);

  event OwnerAdded(address indexed owner, address indexed actor);
  event OwnerRemoved(address indexed owner, address indexed actor);
  event RecoveryOwnerAdded(
    bytes32 indexed recoverySessionHash,
    bytes32 indexed nonce,
    address indexed owner,
    bytes32 nearAccountIdHash,
    bytes32 newNearKeyHash,
    address authority
  );
  event RecoveryAuthorityUpdated(address indexed oldAuthority, address indexed newAuthority);

  bytes32 private _nearAccountIdHash;
  address private _recoveryAuthority;
  address private _entryPoint;
  mapping(address owner => bool) private _isOwner;
  mapping(address owner => uint256) private _ownerIndexPlusOne;
  address[] private _owners;
  mapping(bytes32 nonce => bool) private _usedRecoveryNonces;
  address private _latestRecoveredOwner;
  bool private _initialized;

  receive() external payable {}

  function accountVersion() external pure returns (uint256) {
    return 1;
  }

  function nearAccountIdHash() external view returns (bytes32) {
    return _nearAccountIdHash;
  }

  function recoveryAuthority() external view returns (address) {
    return _recoveryAuthority;
  }

  function entryPoint() external view returns (address) {
    return _entryPoint;
  }

  function isOwner(address owner) external view returns (bool) {
    return _isOwner[owner];
  }

  function getOwners() external view returns (address[] memory) {
    return _owners;
  }

  function ownerCount() external view returns (uint256) {
    return _owners.length;
  }

  function isRecoveryNonceUsed(bytes32 nonce) external view returns (bool) {
    return _usedRecoveryNonces[nonce];
  }

  function initialize(SmartAccountInit calldata init) external {
    if (_initialized) revert AlreadyInitialized();
    if (init.nearAccountIdHash == bytes32(0)) revert InvalidNearAccountBinding();
    if (init.recoveryAuthority == address(0)) revert InvalidRecoveryAuthority();
    if (init.owners.length == 0) revert InvalidOwner();

    _initialized = true;
    _nearAccountIdHash = init.nearAccountIdHash;
    _recoveryAuthority = init.recoveryAuthority;
    _entryPoint = init.entryPoint;

    uint256 ownersLength = init.owners.length;
    for (uint256 index = 0; index < ownersLength; ++index) {
      _addOwner(init.owners[index]);
    }
  }

  function addOwner(address owner) external {
    _requireOwnerOrEntryPoint();
    _addOwner(owner);
  }

  function removeOwner(address owner) external {
    _requireOwnerOrEntryPoint();
    _removeOwner(owner);
  }

  function verifyAndRecover(
    bytes32 nearAccountIdHash_,
    bytes32 newNearKeyHash,
    address newOwner,
    bytes32 recoverySessionHash,
    uint256 nonce,
    uint256 deadline,
    bytes calldata authoritySignature
  ) external {
    _recoverAddOwner(
      nearAccountIdHash_,
      newNearKeyHash,
      newOwner,
      recoverySessionHash,
      nonce,
      deadline,
      authoritySignature
    );
  }

  function recoverAddOwner(
    bytes32 nearAccountIdHash_,
    bytes32 newNearKeyHash,
    address newOwner,
    bytes32 recoverySessionHash,
    uint256 nonce,
    uint256 deadline,
    bytes calldata authoritySignature
  ) external {
    _recoverAddOwner(
      nearAccountIdHash_,
      newNearKeyHash,
      newOwner,
      recoverySessionHash,
      nonce,
      deadline,
      authoritySignature
    );
  }

  function execute(address target, uint256 value, bytes calldata data)
    external
    payable
    returns (bytes memory result)
  {
    _requireOwnerOrEntryPoint();
    if (target == address(0)) revert InvalidExecutionTarget();
    (bool ok, bytes memory response) = target.call{ value: value }(data);
    if (!ok) _revertWithData(response);
    return response;
  }

  function executeBatch(
    address[] calldata targets,
    uint256[] calldata values,
    bytes[] calldata data
  ) external payable returns (bytes[] memory results) {
    _requireOwnerOrEntryPoint();
    if (targets.length != values.length || targets.length != data.length) {
      revert ArrayLengthMismatch();
    }

    uint256 length = targets.length;
    results = new bytes[](length);
    for (uint256 index = 0; index < length; ++index) {
      if (targets[index] == address(0)) revert InvalidExecutionTarget();
      (bool ok, bytes memory response) = targets[index].call{ value: values[index] }(data[index]);
      if (!ok) _revertWithData(response);
      results[index] = response;
    }
  }

  function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
    return _isOwnerSignature(hash, signature) ? ERC1271_MAGIC_VALUE : ERC1271_INVALID_VALUE;
  }

  function validateUserOp(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 missingAccountFunds
  ) external returns (uint256 validationData) {
    if (msg.sender != _entryPoint) revert InvalidEntryPoint();
    if (userOp.sender != address(this)) revert InvalidUserOpSender(userOp.sender);

    validationData =
      _isOwnerSignature(userOpHash, userOp.signature)
        ? SIG_VALIDATION_SUCCESS
        : SIG_VALIDATION_FAILED;

    if (missingAccountFunds > 0) {
      (bool success,) = payable(msg.sender).call{ value: missingAccountFunds }("");
      success;
    }

    userOp;
  }

  function _recoverAddOwner(
    bytes32 nearAccountIdHash_,
    bytes32 newNearKeyHash,
    address newOwner,
    bytes32 recoverySessionHash,
    uint256 nonce,
    uint256 deadline,
    bytes calldata authoritySignature
  ) internal {
    if (nearAccountIdHash_ != _nearAccountIdHash) revert InvalidNearAccountBinding();
    if (newOwner == address(0)) revert InvalidOwner();
    if (deadline < block.timestamp) {
      revert RecoveryAuthorizationExpired(deadline, block.timestamp);
    }

    bytes32 nonceKey = bytes32(nonce);
    if (_usedRecoveryNonces[nonceKey]) revert RecoveryNonceAlreadyUsed(nonceKey);
    if (_isOwner[newOwner]) revert OwnerAlreadyExists(newOwner);

    bytes32 digest = _recoverDigest(
      nearAccountIdHash_,
      newNearKeyHash,
      newOwner,
      recoverySessionHash,
      nonce,
      deadline
    );
    address signer = ECDSA.recover(digest, authoritySignature);
    if (signer != _recoveryAuthority) revert InvalidRecoverySignature();

    _usedRecoveryNonces[nonceKey] = true;
    _addOwner(newOwner);
    _latestRecoveredOwner = newOwner;

    emit RecoveryOwnerAdded(
      recoverySessionHash,
      nonceKey,
      newOwner,
      nearAccountIdHash_,
      newNearKeyHash,
      _recoveryAuthority
    );
  }

  function _addOwner(address owner) internal {
    if (owner == address(0)) revert InvalidOwner();
    if (_isOwner[owner]) revert OwnerAlreadyExists(owner);

    _isOwner[owner] = true;
    _owners.push(owner);
    _ownerIndexPlusOne[owner] = _owners.length;

    emit OwnerAdded(owner, msg.sender);
  }

  function _removeOwner(address owner) internal {
    if (!_isOwner[owner]) revert OwnerDoesNotExist(owner);
    if (_owners.length == 1) revert LastOwnerRemovalForbidden();
    if (owner == _latestRecoveredOwner && msg.sender != owner) {
      revert RecoveredOwnerProtected(owner);
    }

    uint256 ownerIndex = _ownerIndexPlusOne[owner] - 1;
    uint256 lastIndex = _owners.length - 1;
    if (ownerIndex != lastIndex) {
      address lastOwner = _owners[lastIndex];
      _owners[ownerIndex] = lastOwner;
      _ownerIndexPlusOne[lastOwner] = ownerIndex + 1;
    }

    _owners.pop();
    delete _ownerIndexPlusOne[owner];
    delete _isOwner[owner];

    emit OwnerRemoved(owner, msg.sender);
  }

  function _recoverDigest(
    bytes32 nearAccountIdHash_,
    bytes32 newNearKeyHash,
    address newOwner,
    bytes32 recoverySessionHash,
    uint256 nonce,
    uint256 deadline
  ) internal view returns (bytes32) {
    bytes32 structHash = keccak256(
      abi.encode(
        RECOVERY_TYPEHASH,
        nearAccountIdHash_,
        newNearKeyHash,
        newOwner,
        recoverySessionHash,
        nonce,
        deadline
      )
    );

    return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
  }

  function _domainSeparator() internal view returns (bytes32) {
    return keccak256(
      abi.encode(
        DOMAIN_TYPEHASH,
        RECOVERY_NAME_HASH,
        RECOVERY_VERSION_HASH,
        block.chainid,
        address(this)
      )
    );
  }

  function _requireOwnerOrEntryPoint() internal view {
    if (_isOwner[msg.sender]) return;
    if (_entryPoint != address(0) && msg.sender == _entryPoint) return;
    revert NotOwner();
  }

  function _isOwnerSignature(bytes32 hash, bytes calldata signature) internal view returns (bool) {
    address signer = ECDSA.recover(hash, signature);
    return signer != address(0) && _isOwner[signer];
  }

  function _revertWithData(bytes memory revertData) internal pure {
    if (revertData.length == 0) revert ExecutionFailed(revertData);

    assembly {
      revert(add(revertData, 0x20), mload(revertData))
    }
  }
}
