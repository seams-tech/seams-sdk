// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface Vm {
  function prank(address caller) external;
  function expectRevert(bytes calldata revertData) external;
  function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
  function addr(uint256 privateKey) external returns (address addr);
  function deal(address who, uint256 newBalance) external;
}

abstract contract TestBase {
  Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

  function assertTrue(bool condition, string memory message) internal pure {
    if (!condition) revert(message);
  }

  function assertFalse(bool condition, string memory message) internal pure {
    if (condition) revert(message);
  }

  function assertEq(uint256 left, uint256 right, string memory message) internal pure {
    if (left != right) revert(message);
  }

  function assertEq(address left, address right, string memory message) internal pure {
    if (left != right) revert(message);
  }

  function assertEq(bytes32 left, bytes32 right, string memory message) internal pure {
    if (left != right) revert(message);
  }

  function assertEq(bytes4 left, bytes4 right, string memory message) internal pure {
    if (left != right) revert(message);
  }

  function assertEq(bool left, bool right, string memory message) internal pure {
    if (left != right) revert(message);
  }

  function assertEq(bytes memory left, bytes memory right, string memory message) internal pure {
    if (keccak256(left) != keccak256(right)) revert(message);
  }

  function _signDigest(uint256 privateKey, bytes32 digest) internal returns (bytes memory signature) {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
    return abi.encodePacked(r, s, v);
  }
}
