// SPDX-License-Identifier: MIT pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol"; import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract EnclaveService is Ownable { 
    using ECDSA for bytes32; // The trusted TEE signer address (public key used to verify SGX attestation signatures)
    address private _teeSigner;

    // Configuration parameters for attestation verification
    struct AttestationConfig {
        uint256 maxAttestationAge; // Maximum allowed age (in seconds) for a valid attestation
        uint256 expectedNonce;     // Expected nonce value (to prevent replay attacks)
        bool requireNonce;         // If true, nonce checking is enabled
        bool verifyCodeHash;       // If true, the attestation must include a code hash matching expected value
    }

    AttestationConfig private _attestationConfig;

    // Trusted relayer management
    mapping(address => bool) private _trustedRelayers;

    // Events
    event AttestationConfigUpdated(uint256 maxAttestationAge, uint256 expectedNonce, bool requireNonce, bool verifyCodeHash);
    event TrustedRelayerAdded(address relayer);
    event TrustedRelayerRemoved(address relayer);
    event AttestationRecorded(bytes32 indexed attestationHash, bytes attestation);
    event OutputNFTCreated(uint256 indexed tokenId, address owner, string metadataURI);

    // Constructor: set the TEE signer and initial attestation configuration
    constructor(address teeSigner, AttestationConfig memory initialConfig) {
        require(teeSigner != address(0), "TEE signer address cannot be zero");
        _teeSigner = teeSigner;
        _attestationConfig = initialConfig;
    }

    // Attestation configuration functions
    function setAttestationConfig(AttestationConfig memory config) external onlyOwner {
        _attestationConfig = config;
        emit AttestationConfigUpdated(config.maxAttestationAge, config.expectedNonce, config.requireNonce, config.verifyCodeHash);
    }

    function getAttestationConfig() external view returns (AttestationConfig memory) {
        return _attestationConfig;
    }

    // Trusted relayer management functions
    function addTrustedRelayer(address relayer) external onlyOwner {
        require(relayer != address(0), "Relayer cannot be zero address");
        _trustedRelayers[relayer] = true;
        emit TrustedRelayerAdded(relayer);
    }

    function removeTrustedRelayer(address relayer) external onlyOwner {
        _trustedRelayers[relayer] = false;
        emit TrustedRelayerRemoved(relayer);
    }

    function isTrustedRelayer(address relayer) public view returns (bool) {
        return _trustedRelayers[relayer];
    }

    // Fixed cryptographic signature verification using ECDSA
    function verifySignature(bytes memory data, bytes memory signature, address expectedSigner) public pure returns (bool) {
        bytes32 hash = keccak256(data);
        bytes32 ethSignedHash = hash.toEthSignedMessageHash();
        return ethSignedHash.recover(signature) == expectedSigner;
    }

    // recordAttestation accepts an off‑chain produced attestation and its signature,
    // verifies that the signature was produced by the configured TEE signer,
    // parses critical parameters (timestamp, nonce, code hash),
    // and applies the configurable checks.
    // The attestation is assumed to be encoded as:
    // [timestamp (uint256)] [nonce (uint256)] [codeHash (bytes32)] [rest of data...]
    function recordAttestation(bytes calldata attestation, bytes calldata attestationSignature) internal returns (bytes32) {
        // Only accept submissions from a trusted relayer
        require(isTrustedRelayer(msg.sender), "Caller is not a trusted relayer");
        // Verify the attestation signature using the fixed TEE signer
        require(verifySignature(attestation, attestationSignature, _teeSigner), "Invalid attestation signature");
        // Ensure attestation is at least 96 bytes long (timestamp, nonce, codeHash)
        require(attestation.length >= 96, "Invalid attestation length");
        uint256 timestamp;
        uint256 nonce;
        bytes32 codeHash;
        (timestamp, nonce, codeHash) = abi.decode(attestation[:96], (uint256, uint256, bytes32));
        // Check that the attestation timestamp is within the allowed age
        require(block.timestamp <= timestamp + _attestationConfig.maxAttestationAge, "Attestation expired");
        // If nonce checking is enabled, verify the nonce matches the expected value
        if (_attestationConfig.requireNonce) {
            require(nonce == _attestationConfig.expectedNonce, "Attestation nonce mismatch");
        }
        // If code hash verification is enabled, check that the code hash matches the expected value.
        // The expected code hash is provided by getExpectedCodeHash(), which must be overridden by derived contracts.
        if (_attestationConfig.verifyCodeHash) {
            bytes32 expectedCodeHash = getExpectedCodeHash();
            require(codeHash == expectedCodeHash, "Attestation code hash mismatch");
        }
        // Compute and return the hash of the entire attestation
        bytes32 attestationHash = keccak256(attestation);
        emit AttestationRecorded(attestationHash, attestation);
        return attestationHash;
    }

    // Abstract function: expected code hash from the SGX attestation.
    // Derived contracts should override this function to return the expected value.
    function getExpectedCodeHash() internal view virtual returns (bytes32);

    // Abstract function for creating an output NFT.
    function createOutputNFT(address owner, string memory metadataURI, bytes32 attestationHash) internal virtual returns (uint256);

    // Abstract function for performing core computation.
    function compute(bytes memory inputData) external virtual returns (bytes memory);
}