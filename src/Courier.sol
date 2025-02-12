// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@api3/contracts/v0.8/interfaces/IRequestor.sol";
import "./EnclaveService.sol";
//import "./ICustodian.sol"; // Assuming you have this interface defined // Commented out for compilation
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";

contract Courier is EnclaveService, ERC721URIStorage, Ownable, IRequestor {
    using ECDSA for bytes32;

    struct Request {
        address requester;
        bytes inputData;  // Stores encrypted data, if encryption is enabled
        bytes32 inputCommitmentHash;
        bytes signedData;
        bool fulfilled;
        uint256 validUntil;
    }

    struct CertifiedPayload {
        uint256 payloadId;
        bytes32 requestId;
        bytes32 attestationHash;
        string metadataURI;
        bool verified;
    }

    mapping(bytes32 => Request) public requests;
    mapping(uint256 => CertifiedPayload) public certifiedPayloads;
    mapping(bytes32 => bool) public fulfilledRequestIds;

    address public immutable api3Proxy;
    uint256 public nextPayloadId;

    //ICustodian public custodian; // Commented out to compile

    uint256 public constant REQUEST_EXPIRATION_TIME = 5 minutes;

    bool public requireEncryption;

    event RequestMade(bytes32 indexed requestId, address indexed requester, bytes32 inputCommitmentHash, bytes inputData);
    event RequestFulfilled(bytes32 indexed requestId, uint256 indexed payloadId, bytes signedData);
    event CertifiedPayloadMinted(uint256 indexed payloadId, address owner, string metadataURI, bytes32 attestationHash);
    event EncryptionRequiredChanged(bool required);

    constructor(address _api3Proxy, address teeSigner, AttestationConfig memory initialConfig, bool _requireEncryption)
        ERC721("CertifiedPayload", "CPAY")
        EnclaveService(teeSigner, initialConfig)
    {
        require(_api3Proxy != address(0), "API3 proxy address cannot be zero");
        api3Proxy = _api3Proxy;
        nextPayloadId = 1;
        requireEncryption = _requireEncryption;
    }

    // function setCustodian(address _custodian) external onlyOwner { // Commented out to compile
    //     custodian = ICustodian(_custodian);
    // }

    function setRequireEncryption(bool _requireEncryption) external onlyOwner {
        requireEncryption = _requireEncryption;
        emit EncryptionRequiredChanged(_requireEncryption);
    }

    function makeRequest(
        address _airnode,
        bytes32 _endpointId,
        bytes calldata _encodedParameters,
        bytes calldata _inputData,
        bytes32 _inputCommitmentHash
    ) external payable override {
        require(keccak256(_inputData) == _inputCommitmentHash, "Invalid input commitment hash");

        bytes32 requestId = IRequestor(api3Proxy).makeRequest(
            _airnode,
            _endpointId,
            address(this),
            this.fulfill.selector,
            _encodedParameters
        );

        requests[requestId] = Request({
            requester: msg.sender,
            inputData: _inputData,
            inputCommitmentHash: _inputCommitmentHash,
            signedData: "",
            fulfilled: false,
            validUntil: block.timestamp + REQUEST_EXPIRATION_TIME
        });
        emit RequestMade(requestId, msg.sender, _inputCommitmentHash, _inputData);
    }

    function fulfill(
        bytes32 requestId,
        bytes calldata data,
        bytes calldata api3Signature,
        bytes calldata teeAttestation,
        bytes calldata teeAttestationSignature
    )
        external
        onlyAirnodeRrp
    {
        require(msg.sender == api3Proxy, "Fulfill: Caller must be API3 Proxy"); // Redundant
        require(!fulfilledRequestIds[requestId], "Request already fulfilled");
        fulfilledRequestIds[requestId] = true;
        Request storage req = requests[requestId];
        require(block.timestamp <= req.validUntil, "Request expired");

        require(verifySignature(data, api3Signature, api3Proxy), "Invalid API3 signature");

        req.fulfilled = true;
        req.signedData = data;

        // --- Input Commitment Check (No Decryption Here) ---
        require(keccak256(req.inputData) == req.inputCommitmentHash, "Invalid input commitment hash");

        // Process data via off-chain TEE computation (using req.inputData, which is already encrypted if necessary)
        bytes memory teeResult = processInTEE(data, req.inputData);
        string memory resultMetadata = string(teeResult);

        bytes32 attestationHash = recordAttestation(teeAttestation, teeAttestationSignature);

        uint256 payloadId = createOutputNFT(req.requester, resultMetadata, attestationHash);
        certifiedPayloads[payloadId] = CertifiedPayload({
            payloadId: payloadId,
            requestId: requestId,
            attestationHash: attestationHash,
            metadataURI: resultMetadata,
            verified: true
        });
        emit RequestFulfilled(requestId, payloadId, data);
        emit CertifiedPayloadMinted(payloadId, req.requester, resultMetadata, attestationHash);
    }

    // processInTEE now takes the *encrypted* inputData (if encryption is enabled)
    function processInTEE(bytes memory apiData, bytes memory inputData) internal returns (bytes memory) {
        // In the TEE, inputData would be decrypted *before* being used.
        // For the MVP, we're simulating the TEE, so we just combine the data.
        bytes memory combined = abi.encodePacked(apiData, inputData);
        return abi.encodePacked(keccak256(combined));
    }

    function createOutputNFT(
        address owner,
        string memory metadataURI,
        bytes32 attestationHash
    ) internal override returns (uint256) {
        uint256 payloadId = nextPayloadId++;
        _safeMint(owner, payloadId);
        _setTokenURI(payloadId, metadataURI);
        emit OutputNFTCreated(payloadId, owner, metadataURI);
        return payloadId;
    }

    function getExpectedCodeHash() internal view override returns (bytes32) {
        return 0x0000000000000000000000000000000000000000000000000000000000000000; // Placeholder
    }

    // The compute function is no longer needed, as the core logic is in processInTEE,
    // which is called by fulfill.
    // function compute(bytes memory inputData, bytes32 inputCommitmentHash) external override returns (bytes memory) {
    //     require(keccak256(inputData) == inputCommitmentHash);
    //     return inputData;
    // }
}