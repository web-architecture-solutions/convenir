// SPDX-License-Identifier: MIT pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol"; import "@openzeppelin/contracts/access/Ownable.sol"; import "./EnclaveService.sol"; import "./ICourier.sol"; import "@oceanprotocol/contracts/v0.8/interfaces/IDataNFT.sol"; import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Custodian is EnclaveService, ERC721URIStorage { 
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

    event CertifiedPackageCreated(uint256 indexed packageId, address indexed owner, uint256[] assetIds, string metadataURI);
    event CourierAuthorizationChanged(address indexed courier, bool authorized);

    constructor(address _dataNFT, address teeSigner, AttestationConfig memory initialConfig)
        ERC721("CertifiedPackage", "CPKG")
        EnclaveService(teeSigner, initialConfig)
    {
        dataNFT = IDataNFT(_dataNFT);
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

    // createCertifiedPackage accepts asset IDs, off-chain processing instructions,
    // and off-chain produced TEE attestation data (with its signature).
    function createCertifiedPackage(
        address owner,
        uint256[] memory assetIds,
        string memory metadataURI,
        bytes memory preProcessingInstructions,
        bytes memory postProcessingInstructions,
        bytes calldata teeAttestation,
        bytes calldata teeAttestationSignature
    ) external returns (uint256) {
        // Simulate pre-processing in TEE
        bytes memory preProcessed = _executeInTEE(preProcessingInstructions);
        for (uint256 i = 0; i < assetIds.length; i++) {
            // Check asset ownership for Data NFTs managed by this Custodian
            if (isDataNFT(assetIds[i])) {
                require(dataNFT.ownerOf(assetIds[i]) == address(this), "Not authorized to wrap this Data NFT");
            }
        }
        bytes memory postProcessed = _executeInTEE(postProcessingInstructions);
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
        _setTokenURI(pkgId, metadataURI);
        return pkgId;
    }

    // Returns the expected code hash for verification. For production, set this appropriately.
    function getExpectedCodeHash() internal view override returns (bytes32) {
        return 0x0000000000000000000000000000000000000000000000000000000000000000;
    }

    // Core computation logic; here it simply returns the input data.
    function compute(bytes memory inputData) external override returns (bytes memory) {
        return inputData;
    }
}