// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./EnclaveService.sol";
import "./ICourier.sol";
import "@oceanprotocol/contracts/v0.8/interfaces/IDataNFT.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Custodian is EnclaveService, ERC721URIStorage, Ownable { // Inherit from Ownable
    using ECDSA for bytes32;
    IDataNFT public dataNFT;
    uint256 private _packageIdCounter;

    struct CertifiedPackage {
        uint256 packageId;
        address owner;
        uint256[] assetIds;
        bytes32 attestationHash;
        string metadataURI;
        bool verified;
    }

    mapping(uint256 => CertifiedPackage) public certifiedPackages;
    mapping(address => bool) public authorizedCouriers;

    // Configuration flag for requiring encryption
    bool public requireEncryption;

    event CertifiedPackageCreated(uint256 indexed packageId, address indexed owner, uint256[] assetIds, string metadataURI);
    event CourierAuthorizationChanged(address indexed courier, bool authorized);
    event EncryptionRequiredChanged(bool required);

   constructor(address _dataNFT, address teeSigner, AttestationConfig memory initialConfig, bool _requireEncryption)
        ERC721("CertifiedPackage", "CPKG")
        EnclaveService(teeSigner, initialConfig)
    {
        dataNFT = IDataNFT(_dataNFT);
        requireEncryption = _requireEncryption;
    }

    function setDataNFT(address _dataNFT) external onlyOwner {
        dataNFT = IDataNFT(_dataNFT);
    }

    function setCourierAuthorization(address courier, bool authorized) external onlyOwner {
        authorizedCouriers[courier] = authorized;
        emit CourierAuthorizationChanged(courier, authorized);
    }

    function isAuthorizedCourier(address courier) external view returns (bool) {
        return authorizedCouriers[courier];
    }
    // Allows the owner to set the requireEncryption flag
    function setRequireEncryption(bool _requireEncryption) external onlyOwner {
        requireEncryption = _requireEncryption;
        emit EncryptionRequiredChanged(_requireEncryption);
    }

    // createCertifiedPackage (modified)
    function createCertifiedPackage(
        address owner,
        uint256[] memory assetIds,
        string memory metadataURI,
        bytes memory preProcessingInstructions,
        bytes memory postProcessingInstructions,
        bytes calldata teeAttestation,
        bytes calldata teeAttestationSignature,
        bytes32 inputCommitmentHash // Added input commitment hash
    ) external returns (uint256) {

        // --- Input Commitment Verification and Decryption (if needed) ---
        bytes memory combinedInput = abi.encode(preProcessingInstructions, postProcessingInstructions, assetIds, metadataURI);
        bytes memory processedInput = combinedInput;

        if (requireEncryption) {
              // Attempt to decrypt (SIMULATED - replace with actual TEE decryption)
            //   processedInput = _decryptInTEE(combinedInput);
              processedInput = combinedInput;
              require(processedInput.length > 0, "Decryption failed"); // Basic check
        }

        require(keccak256(processedInput) == inputCommitmentHash, "Invalid input commitment hash");

        // --- (Rest of the function remains largely the same) ---

        // Simulate pre-processing in TEE
        bytes memory preProcessed = _executeInTEE(preProcessingInstructions); //now using processedInput

        for (uint256 i = 0; i < assetIds.length; i++) {
            // Check asset ownership for Data NFTs managed by this Custodian
            if (isDataNFT(assetIds[i])) {
                require(dataNFT.ownerOf(assetIds[i]) == address(this), "Not authorized to wrap this Data NFT");
            }
        }

        bytes memory postProcessed = _executeInTEE(postProcessingInstructions); //now using processedInput
        bytes memory combined = abi.encode(preProcessed, postProcessed, assetIds, metadataURI);

        // Record off-chain attestation
        bytes32 attestationHash = recordAttestation(teeAttestation, teeAttestationSignature);

        uint256 packageId = _packageIdCounter++;
        _safeMint(owner, packageId);
        _setTokenURI(packageId, metadataURI);
        certifiedPackages[packageId] = CertifiedPackage({
            packageId: packageId,
            owner: owner,
            assetIds: assetIds,
            attestationHash: attestationHash,
            metadataURI: metadataURI,
            verified: true
        });
        emit CertifiedPackageCreated(packageId, owner, assetIds, metadataURI);
        return packageId;
    }
    // Simulated TEE decryption function (replace with actual TEE integration)
    // function _decryptInTEE(bytes memory encryptedData) internal returns (bytes memory) {
    //      // Placeholder: Just return input, like above
    //     return encryptedData;
    // }

    // ... (rest of the Custodian contract, including isDataNFT, updateDataNFT, onlyAuthorizedCourier, _executeInTEE, createOutputNFT, getExpectedCodeHash, compute) ...
    // isDataNFT is a placeholder function. In production, implement proper logic.
    function isDataNFT(uint256 assetId) internal view returns (bool) {
        return true;
    }

    // Update Data NFT metadata; callable only by authorized couriers.
    function updateDataNFT(uint256 dataNFTId, string memory newMetadataURI) external onlyAuthorizedCourier {
        dataNFT.setMetaData(dataNFTId, newMetadataURI);
    }

    modifier onlyAuthorizedCourier() {
        require(authorizedCouriers[msg.sender], "Custodian: Caller is not an authorized Courier");
        _;
    }

    // Simulated TEE execution; in production, replace with secure off-chain processing integration.
    function _executeInTEE(bytes memory instructions) internal returns (bytes memory) {
        return instructions;
    }

    // Implementation of abstract createOutputNFT: mints a Certified Package NFT.
    function createOutputNFT(address owner, string memory metadataURI, bytes32 attestationHash) internal override returns (uint256) {
        uint256 pkgId = _packageIdCounter++;
        _safeMint(owner, pkgId);
        _setTokenURI(pkgId, metadataURI