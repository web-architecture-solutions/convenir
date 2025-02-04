// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title EnclaveService
 * @dev Abstract contract defining a confidential computing service on Oasis Sapphire.
 * Provides base functionality for verifying off-chain TEE attestations and external signatures.
 */
abstract contract EnclaveService is Ownable {
    using ECDSA for bytes32;

    // Address of the designated TEE signer (public key used to verify attestation signatures)
    address internal _teeSigner;

    // Events
    event AttestationGenerated(bytes32 indexed attestationHash, bytes attestation);
    event OutputNFTCreated(uint256 indexed tokenId, address owner, string metadataURI);

    /**
     * @dev Constructor.
     * @param teeSigner The address of the TEE signer (for attestation verification).
     */
    constructor(address teeSigner) {
        _teeSigner = teeSigner;
    }

    // Setter for TEE signer (admin-only)
    function setTEESigner(address newTEESigner) external onlyOwner {
        _teeSigner = newTEESigner;
    }

    // Getter for TEE signer
    function getTEESigner() external view returns (address) {
        return _teeSigner;
    }

    /**
     * @dev Verifies a signature over data.
     * @param data The original data that was signed.
     * @param signature The signature.
     * @param expectedSigner The expected signer address.
     * @return True if signature is valid.
     */
    function verifySignature(
        bytes memory data,
        bytes memory signature,
        address expectedSigner
    ) internal pure returns (bool) {
        bytes32 hash = keccak256(data);
        bytes32 ethSignedHash = hash.toEthSignedMessageHash();
        return ethSignedHash.recover(signature) == expectedSigner;
    }

    /**
     * @dev Records an attestation produced off–chain by the TEE.
     * The attestation must be accompanied by a signature produced by the TEE.
     * @param attestation The full attestation data from the TEE.
     * @param attestationSignature The signature over the attestation.
     * @return The hash of the attestation.
     */
    function recordAttestation(
        bytes calldata attestation,
        bytes calldata attestationSignature
    ) internal returns (bytes32) {
        // Verify that the attestation is signed by the known TEE signer.
        require(
            verifySignature(attestation, attestationSignature, _teeSigner),
            "EnclaveService: Invalid TEE attestation signature"
        );
        bytes32 attestationHash = keccak256(attestation);
        emit AttestationGenerated(attestationHash, attestation);
        return attestationHash;
    }

    /**
     * @dev Creates an output NFT for the Enclave Service.
     * Must be implemented by the derived contract.
     * @param owner The owner of the NFT.
     * @param metadataURI The URI pointing to the NFT metadata.
     * @param attestationHash The hash of the verified TEE attestation.
     * @return The new NFT’s ID.
     */
    function createOutputNFT(
        address owner,
        string memory metadataURI,
        bytes32 attestationHash
    ) internal virtual returns (uint256);

    /**
     * @dev Abstract function for the core computation logic.
     * @param inputData The input data (possibly encrypted).
     * @return The computation result.
     */
    function compute(bytes memory inputData) external virtual returns (bytes memory);
}
