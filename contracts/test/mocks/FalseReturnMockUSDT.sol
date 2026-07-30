// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Adversarial ERC20 that returns false from transfer/transferFrom.
/// NEVER mainnet.
contract FalseReturnMockUSDT {
    string public name = "FalseReturn Mock USDT";
    string public symbol = "xUSDT";
    uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 private immutable _DOMAIN_SEPARATOR;

    constructor() {
        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _DOMAIN_SEPARATOR;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }

    function transferFrom(address, address, uint256) external pure returns (bool) {
        return false;
    }

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8, bytes32, bytes32)
        external
    {
        require(block.timestamp <= deadline, "expired");
        allowance[owner][spender] = value;
        nonces[owner] += 1;
    }
}
