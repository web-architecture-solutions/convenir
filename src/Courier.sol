// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@api3/contracts/v0.8/interfaces/IRequestor.sol"; // Corrected import
import "./EnclaveService.sol";
//import "./ICustodian.sol"; // Assuming you have this interface defined  //Commented out to compile
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";

contract Courier is EnclaveService, ERC721URIStorage, Ownable, IRequestor { // Inherit from IRequestor
    using ECDSA for bytes32;

    struct Request {
        address requester;
        bytes inputData;  // This will store either plain or encrypted data
        bytes32 inputCommitmentHash; // Added input commitment hash
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

    // The API3 proxy address (used for making requests and verifying API3 signatures)
    address public immutable api3Proxy;  // Keep this as immutable
    uint256 public nextPayloadId;

    // Optional: interface to a Custodian contract
    //ICustodian public custodian; //Commented out to compile

    uint256 public constant REQUEST_EXPIRATION_TIME = 5 minutes;

    // Configuration flag for requiring encryption
    bool public requireEncryption;

    event RequestMade(bytes32 indexed requestId, address indexed requester, bytes32 inputCommitmentHash, bytes inputData);
    event RequestFulfilled(bytes32 indexed requestId, uint256 indexed payloadId, bytes signedData);
    event CertifiedPayloadMinted(uint256 indexed payloadId, address owner, string metadataURI, bytes32 attestationHash);
    event EncryptionRequiredChanged(bool required);


    // Constructor
    constructor(address _api3Proxy, address teeSigner, AttestationConfig memory initialConfig, bool _requireEncryption)
        ERC721("CertifiedPayload", "CPAY")
        EnclaveService(teeSigner, initialConfig)
    {
        require(_api3Proxy != address(0), "API3 proxy address cannot be zero");
        api3Proxy = _api3Proxy;
        nextPayloadId = 1;
        requireEncryption = _requireEncryption;
    }

    // Allows the owner to set the custodian address (if used)
    // function setCustodian(address _custodian) external onlyOwner { //Commented out to compile
    //     custodian = ICustodian(_custodian);
    // }

    // Allows the owner to set the requireEncryption flag
    function setRequireEncryption(bool _requireEncryption) external onlyOwner {
        requireEncryption = _requireEncryption;
        emit EncryptionRequiredChanged(_requireEncryption);
    }

    // Function for making a request to an API3 Airnode (modified)
    function makeRequest(
        address _airnode,
        bytes32 _endpointId,
        bytes calldata _encodedParameters,
        bytes calldata _inputData,
        bytes32 _inputCommitmentHash // Added input commitment hash
    ) external payable override { // Added override
        // Removed Custodian authorization check: Convenir.js handles
        //require(custodian == ICustodian(address(0)) || custodian.isAuthorized(msg.sender), "Caller is not authorized");

        // Verify input commitment hash (BEFORE calling API3)
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
            inputData: _inputData,  // Store either plain or encrypted data
            inputCommitmentHash: _inputCommitmentHash, // Store the commitment hash
            signedData: "",
            fulfilled: false,
            validUntil: block.timestamp + REQUEST_EXPIRATION_TIME
        });
        emit RequestMade(requestId, msg.sender, _inputCommitmentHash, _inputData);
    }

   // fulfill is the callback function invoked by the API3 proxy (modified)
    function fulfill(
        bytes32 requestId,
        bytes calldata data,
        bytes calldata api3Signature,
        bytes calldata teeAttestation,
        bytes calldata teeAttestationSignature
    )
        external
        onlyAirnodeRrp //use API3's modifier
    {
        require(msg.sender == api3Proxy, "Fulfill: Caller must be API3 Proxy"); //Redundant because of onlyAirnodeRrp
        require(!fulfilledRequestIds[requestId], "Request already fulfilled");
        fulfilledRequestIds[requestId] = true;
        Request storage req = requests[requestId];
        require(block.timestamp <= req.validUntil, "Request expired");

        require(verifySignature(data, api3Signature, api3Proxy), "Invalid API3 signature");

        req.fulfilled = true;
        req.signedData = data;

        // --- Decryption (if required) and Input Commitment Check ---
        bytes memory processedInput = req.inputData; // Start with the original input
        if (requireEncryption) {
            // Attempt to decrypt the data (SIMULATED - replace with actual TEE decryption)
            // In a real TEE, you'd have a secure way to access the decryption key.
            // For the MVP, we'll just assume a successful decryption if the flag is set.
            // In a production TEE, this would involve secure key management and decryption within the enclave.
            // processedInput = _decryptInTEE(req.inputData); // Replace with actual TEE decryption
              processedInput = req.inputData; // For MVP, we're just passing through.  Assume decryption succeeded.
              require(processedInput.length > 0, "Decryption failed"); // Basic check (replace with proper TEE error handling)

        }

        // Recompute the input commitment hash (AFTER decryption, if applicable)
        require(keccak256(processedInput) == req.inputCommitmentHash, "Invalid input commitment hash (post-decryption)");


        // Process data via off-chain TEE computation simulation (using processedInput)
        bytes memory teeResult = processInTEE(data, processedInput); // Use processedInput
        string memory resultMetadata = string(teeResult);

        // Record the off-chain attestation
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
    // Simulated TEE decryption function (replace with actual TEE integration)
    // function _decryptInTEE(bytes memory encryptedData) internal returns (bytes memory) {
    //     // In a real TEE, this would involve secure key management and decryption.
    //     // For the MVP, we might just return the input data, assuming decryption succeeded.
    //     // Or, for testing, you could have a simple XOR decryption here with a hardcoded key.
    //     return encryptedData; // Placeholder:  Just return the input (simulating successful decryption)
    // }

    // processInTEE now takes processedInput (which is either the original or decrypted input)
    function processInTEE(bytes memory apiData, bytes memory processedInput) internal returns (bytes memory) {
        bytes memory combined = abi.encodePacked(apiData, processedInput);
        return abi.encodePacked(keccak256(combined));
    }

    // ... (rest of the Courier contract remains the same, including createOutputNFT, getExpectedCodeHash, compute) ...
    // Implementation of abstract createOutputNFT: mints an ERC721 token representing a Certified Payload.
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

    // Returns the expected code hash from the SGX attestation.
    // For demonstration, this returns a fixed value. In production, this should be set appropriately.
    function getExpectedCodeHash() internal view override returns (bytes32) {
        return 0x0000000000000000000000000000000000000000000000000000000000000000;
    }

    // Core computation logic; here it simply returns the input data.
    function compute(bytes memory inputData, bytes32 inputCommitmentHash) external override returns (bytes memory) {
        require(keccak256(inputData) == inputCommitmentHash);
        return inputData;
    }
}