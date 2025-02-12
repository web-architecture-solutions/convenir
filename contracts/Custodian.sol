// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./EnclaveService.sol";
import "@oceanprotocol/contracts/contracts/interfaces/IERC721Template.sol"; // Corrected import
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Custodian is EnclaveService, ERC721URIStorage, Ownable {
    using ECDSA for bytes32;

    // Use a mapping to track multiple Data NFTs
    mapping(uint256 => IERC721Template) public dataNFTs;
    // Track next Data NFT ID.
    uint public nextDataNFTId;

    uint256 private _packageIdCounter;

    struct CertifiedPackage {
        uint256 packageId;
        address owner;
        uint256[] assetIds; // Data NFT IDs (not token IDs within the Data NFT)
        bytes32 attestationHash;
        string metadataURI;
        bool verified;
    }

    mapping(uint256 => CertifiedPackage) public certifiedPackages;
    mapping(address => bool) public authorizedCouriers;

    bool public requireEncryption;

    event CertifiedPackageCreated(uint256 indexed packageId, address indexed owner, uint256[] assetIds, string metadataURI);
    event CourierAuthorizationChanged(address indexed courier, bool authorized);
    event EncryptionRequiredChanged(bool required);
    event DataNFTAdded(uint256 indexed dataNFTId, address indexed dataNFTAddress);

    constructor(address teeSigner, AttestationConfig memory initialConfig, bool _requireEncryption)
        ERC721("CertifiedPackage", "CPKG")
        EnclaveService(teeSigner, initialConfig)
    {
        requireEncryption = _requireEncryption;
        nextDataNFTId = 1;
    }

    // Add a Data NFT to be managed by this Custodian
    function addDataNFT(address _dataNFT) external onlyOwner returns (uint256) {
        uint256 dataNFTId = nextDataNFTId++;
        dataNFTs[dataNFTId] = IERC721Template(_dataNFT);
        emit DataNFTAdded(dataNFTId, _dataNFT);
        return dataNFTId;
    }
    // Better to remove, so dataNFT cannot be changed after initialization
    // function setDataNFT(address _dataNFT) external onlyOwner {
    //     dataNFT = IERC721Template(_dataNFT);
    // }

    function setCourierAuthorization(address courier, bool authorized) external onlyOwner {
        authorizedCouriers[courier] = authorized;
        emit CourierAuthorizationChanged(courier, authorized);
    }

    function isAuthorizedCourier(address courier) external view returns (bool) {
        return authorizedCouriers[courier];
    }

    function setRequireEncryption(bool _requireEncryption) external onlyOwner {
        requireEncryption = _requireEncryption;
        emit EncryptionRequiredChanged(_requireEncryption);
    }
    // Only authorized couriers can create packages
    function createCertifiedPackage(
        address owner,
        uint256[] memory assetIds,  // These should be Data NFT *IDs*, not token IDs within the Data NFT
        string memory metadataURI,
        bytes memory preProcessingInstructions,
        bytes memory postProcessingInstructions,
        bytes calldata teeAttestation,
        bytes calldata teeAttestationSignature,
        bytes32 inputCommitmentHash
    ) external onlyAuthorizedCourier returns (uint256) {

        bytes memory combinedInput = abi.encode(preProcessingInstructions, postProcessingInstructions, assetIds, metadataURI);
        bytes memory processedInput = combinedInput;

        if (requireEncryption) {
              processedInput = combinedInput; // Simulate successful decryption
              require(processedInput.length > 0, "Decryption failed");
        }

        require(keccak256(processedInput) == inputCommitmentHash, "Invalid input commitment hash");

        bytes memory preProcessed = _executeInTEE(preProcessingInstructions);

        // Verify that the provided assetIds are valid Data NFTs managed by *this* Custodian
        for (uint256 i = 0; i < assetIds.length; i++) {
            require(isDataNFT(assetIds[i]), "Invalid Data NFT ID");
            // Additional check: Ensure the caller (Courier) is authorized to use this Data NFT.
            // This requires a way to map Data NFT IDs to their allowed users/Couriers.
            // This is a placeholder; you'd need a more sophisticated access control mechanism here.
        }

        bytes memory postProcessed = _executeInTEE(postProcessingInstructions);

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

    // Correctly checks if a given asset ID is a valid Data NFT managed by this Custodian
    function isDataNFT(uint256 assetId) internal view returns (bool) {
        return address(dataNFTs[assetId]) != address(0);
    }

    function updateDataNFT(uint256 dataNFTId, string memory newMetadataURI) external onlyAuthorizedCourier {
          dataNFTs[dataNFTId].setMetaData(dataNFTId, 0, "", "", "", newMetadataURI, ""); // Use the correct Data NFT
    }

    modifier onlyAuthorizedCourier() {
        require(authorizedCouriers[msg.sender], "Custodian: Caller is not an authorized Courier");
        _;
    }

    function _executeInTEE(bytes memory instructions) internal returns (bytes memory) {
        return instructions;
    }

    function createOutputNFT(address owner, string memory metadataURI, bytes32 attestationHash) internal override returns (uint256) {
        uint256 pkgId = _packageIdCounter++;
        _safeMint(owner, pkgId);
        _setTokenURI(pkgId, metadataURI);
        return pkgId;
    }

    function getExpectedCodeHash() internal view override returns (bytes32) {
        return 0x0000000000000000000000000000000000000000000000000000000000000000; // Placeholder
    }
  // Removed compute
}