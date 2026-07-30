// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Deterministic Base GasPriceOracle stand-in for Anvil Stream G fee tests.
/// Etch to 0x420000000000000000000000000000000000000F in tests.
///
/// ABI parity is load-bearing: `tools/goat-attestor/src/stream_g/base_fee.rs`
/// hand-encodes calldata against the REAL OP-Stack predeploy selectors, so any
/// signature drift here makes Anvil integration tests fail to decode rather
/// than surfacing as a compile error. The three selectors are pinned by
/// `StreamGMocksTest.test_gas_price_oracle_selectors_match_op_stack_predeploy`:
///   getL1Fee(bytes)              = 0x49948e0e   (Bedrock)
///   getL1FeeUpperBound(uint256)  = 0xf1c7a58b   (Fjord — takes the UNSIGNED TX
///                                                SIZE IN BYTES, not calldata)
///   getOperatorFee(uint256)      = 0x275aedd2   (Isthmus)
contract MockGasPriceOracle {
    uint256 public l1Fee;
    uint256 public l1FeeUpperBound;
    uint256 public operatorFee;

    function setFees(uint256 l1Fee_, uint256 l1FeeUpperBound_, uint256 operatorFee_) external {
        l1Fee = l1Fee_;
        l1FeeUpperBound = l1FeeUpperBound_;
        operatorFee = operatorFee_;
    }

    function getL1Fee(bytes memory) external view returns (uint256) {
        return l1Fee;
    }

    /// Real Fjord predeploy takes the unsigned tx size in bytes (uint256), NOT
    /// the calldata itself. Do not "fix" this back to `bytes`.
    function getL1FeeUpperBound(uint256 _unsignedTxSize) external view returns (uint256) {
        _unsignedTxSize;
        return l1FeeUpperBound;
    }

    function getOperatorFee(uint256) external view returns (uint256) {
        return operatorFee;
    }
}
