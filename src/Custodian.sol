// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./EnclaveService.sol";
import "./ICourier.sol";
import "@oceanprotocol/contracts/v0.8/interfaces/IDataNFT.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title Custodian
 * @dev Manages Data NFTs on Ocean Protocol and creates Certified Packages.
 * Acts as a secure orchestrator for confidential data packaging.
 */
contract Custodian is EnclaveService, ERC721URIStorage {
    using ECDSA for bytes32;

    // Interface for interacting with Ocean Protocol Data NFTs.
    IDataNFT public dataNFT;
    uint256 private _packageIdCounter;

    struct CertifiedPackage {
        uint256 packageId;
        address owner;
        uint256[] assetIds; // IDs of bundled assets (Data NFTs, Certified Payloads, etc.)
        bytes32 attestationHash; // Verified TEE attestation hash
        string metadataURI;
        bool verified;
    }

    mapping(uint256 => CertifiedPackage) public certifiedPackages;
    mapping(address => bool) public authorizedCouriers;

    // Events
    event CertifiedPackageCreated(uint256 indexed packageId, address indexed owner, uint256[] assetIds, string metadataURI);
    event CourierAuthorizationChanged(address indexed courier, bool authorized);

    /**
     * @dev Constructor.
     * @param _dataNFT Address of the Ocean Protocol Data NFT contract.
     * @param _teeSigner Address of the TEE signer.
     */
    constructor(address _dataNFT, address _teeSigner)
        ERC721("CertifiedPackage", "CPKG")
        EnclaveService(_teeSigner)
    {
        dataNFT = IDataNFT(_dataNFT);
    }

    /**
     * @dev Sets the Data NFT contract address.
     * @param _dataNFT The new Data NFT contract address.
     */
    function setDataNFT(address _dataNFT) external onlyOwner {
        dataNFT = IDataNFT(_dataNFT);
    }

    /**
     * @dev Authorizes or deauthorizes a Courier.
     * @param courier The Courier address.
     * @param authorized True to authorize, false to deauthorize.
     */
    function setCourierAuthorization(address courier, bool authorized) external onlyOwner {
        authorizedCouriers[courier] = authorized;
        emit CourierAuthorizationChanged(courier, authorized);
    }

    /**
     * @dev Checks if a Courier is authorized.
     * @param courier The Courier address.
     * @return True if authorized.
     */
    function isAuthorizedCourier(address courier) external view returns (bool) {
        return authorizedCouriers[courier];
    }

    /**
     * @dev Creates a Certified Package NFT by bundling assets.
     * @param owner The package owner.
     * @param assetIds Array of asset IDs to bundle.
     * @param metadataURI Metadata URI for the package.
     * @param preProcessingInstructions Instructions for pre-processing (simulated here).
     * @param postProcessingInstructions Instructions for post-processing (simulated here).
     * @param teeAttestation The TEE attestation produced off–chain.
     * @param teeAttestationSignature The signature over the TEE attestation.
     * @return The new package's ID.
     */
    function createCertifiedPackage(
        address owner,
        uint256[] memory assetIds,
        string memory metadataURI,
        bytes memory preProcessingInstructions,
        bytes memory postProcessingInstructions,
        bytes calldata teeAttestation,
        bytes calldata teeAttestationSignature
    ) external returns (uint256) {
        // Simulate pre-processing and post-processing.
        bytes memory preProcessedData = _executeInTEE(preProcessingInstructions);
        for (uint i = 0; i < assetIds.length; i++) {
            // Example check: if asset is a Data NFT managed by this Custodian.
            if (isDataNFT(assetIds[i])) {
                require(dataNFT.ownerOf(assetIds[i]) == address(this), "Not authorized to wrap this Data NFT");
            }
        }
        bytes memory postProcessedData = _executeInTEE(postProcessingInstructions);

        // Instead of simulating attestation, record the externally provided attestation.
        bytes32 attestationHash = recordAttestation(teeAttestation, teeAttestationSignature);

        // Mint the Certified Package NFT.
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

    /**
     * @dev Checks if an asset ID corresponds to a Data NFT.
     * For demonstration purposes, assume true.
     * @param assetId The asset ID.
     * @return True if it is a Data NFT.
     */
    function isDataNFT(uint256 assetId) internal view returns (bool) {
        return true;
    }

    /**
     * @dev Updates metadata for a Data NFT.
     * @param dataNFTId The Data NFT ID.
     * @param newMetadataURI The new metadata URI.
     */
    function updateDataNFT(uint256 dataNFTId, string memory newMetadataURI) external onlyAuthorizedCourier {
        dataNFT.setMetaData(dataNFTId, newMetadataURI);
    }

    /**
     * @dev Modifier to restrict calls to authorized Couriers.
     */
    modifier onlyAuthorizedCourier() {
        require(authorizedCouriers[msg.sender], "Custodian: Caller is not an authorized Courier");
        _;
    }

    /**
     * @dev Simulates execution within the TEE.
     * In production, this would be replaced by secure off–chain processing.
     * @param instructions The instructions.
     * @return The result.
     */
    function _executeInTEE(bytes memory instructions) internal returns (bytes memory) {
        return instructions;
    }

    /**
     * @dev Mints a Certified Package NFT.
     * @param owner The package owner.
     * @param metadataURI The metadata URI.
     * @param attestationHash The verified TEE attestation hash.
     * @return The new NFT's ID.
     */
    function createOutputNFT(
        address owner,
        string memory metadataURI,
        bytes32 attestationHash
    ) internal override returns (uint256) {
        uint256 newPackageId = _packageIdCounter++;
        _safeMint(owner, newPackageId);
        _setTokenURI(newPackageId, metadataURI);
        emit CertifiedPackageCreated(newPackageId, owner, new uint256[](0), metadataURI);
        return newPackageId;
    }

    /**
     * @dev Core computation logic (placeholder).
     * @param inputData The input data.
     * @return The computation result.
     */
    function compute(bytes memory inputData) external override returns (bytes memory) {
        return abi.encode(inputData);
    }
}
