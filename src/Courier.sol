// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@api3/contracts/v0.8/interfaces/IProxy.sol";
import "./EnclaveService.sol";
import "./ICustodian.sol";

/**
 * @title Courier
 * @dev A specialized EnclaveService for fetching and processing external data using API3.
 */
contract Courier is EnclaveService, ERC721 {
    using Address for address;

    // Represents a request made to the API3 Airnode
    struct Request {
        address requester;        // Address of the requester
        bytes inputData;          // Input data for the computation
        bytes signedData;        // Signed data received from the API3 Airnode
        bool fulfilled;          // Flag indicating if the request has been fulfilled
        uint256 validUntil;       // Timestamp indicating when the request expires
    }

    // Represents a Certified Payload NFT
    struct CertifiedPayload {
        uint256 payloadId;       // Unique identifier for the payload
        bytes32 requestId;       // Identifier of the API3 request
        bytes32 attestationHash;   // Hash of the TEE attestation
        string metadataURI;      // URI pointing to the payload metadata
        bool verified;           // Flag indicating if the payload has been verified
    }

    mapping(bytes32 => Request) public requests;                  // Mapping of API3 request IDs to Request structs
    mapping(uint256 => CertifiedPayload) public certifiedPayloads; // Mapping of payload IDs to CertifiedPayload structs
    mapping(bytes32 => bool) public fulfilledRequestIds;         // Mapping of fulfilled request IDs
    address public immutable api3Proxy;                          // Address of the API3 proxy contract
    uint256 public nextPayloadId;                                // Counter for the next payload ID
    ICustodian public custodian;                                  // Interface to interact with the Custodian contract
    uint256 public constant REQUEST_EXPIRATION_TIME = 5 minutes;

    // Event emitted when a new request is made
    event RequestMade(bytes32 indexed requestId, address indexed requester, bytes inputData);
    // Event emitted when a request is fulfilled
    event RequestFulfilled(bytes32 indexed requestId, uint256 indexed payloadId, bytes signedData);
    // Event emitted when a Certified Payload NFT is minted
    event CertifiedPayloadMinted(uint256 indexed payloadId, address owner, string metadataURI, bytes32 attestationHash);

    /**
     * @dev Constructor for the Courier contract.
     * @param _api3Proxy Address of the API3 proxy contract.
     * @param _teeEnvironment Address of the TEE environment.
     * @param _teeSigner Address of the TEE signer.
     */
    constructor(address _api3Proxy, address _teeEnvironment, address _teeSigner)
        ERC721("CertifiedPayload", "CPAY")
        EnclaveService(_teeEnvironment, _teeSigner)
    {
        api3Proxy = _api3Proxy;
        nextPayloadId = 1;
    }

    /**
     * @dev Sets the Custodian contract address.
     * @param _custodian The address of the Custodian contract.
     */
    function setCustodian(address _custodian) external onlyOwner {
        custodian = ICustodian(_custodian);
    }

    /**
     * @dev Makes a request to the API3 Airnode.
     * @param _airnode Address of the API3 Airnode.
     * @param _endpointId Identifier of the endpoint to call.
     * @param _encodedParameters Encoded parameters for the request.
     * @param _inputData Additional input data for the computation.
     */
    function makeRequest(
        address _airnode,
        bytes32 _endpointId,
        bytes calldata _encodedParameters,
        bytes calldata _inputData
) external payable {
    require(custodian == address(0) || custodian.isAuthorized(msg.sender), "Caller is not authorized");

    // Make the request to the API3 Airnode
    (bool success, bytes memory returndata) = api3Proxy.call{value: msg.value}(
        abi.encodeWithSelector(
            IProxy(api3Proxy).makeRequest.selector,
            _airnode,
            _endpointId,
            address(this),
            this.fulfill.selector,
            _encodedParameters
        )
    );
    require(success, "API3 request failed");

    // Decode the response to get the request ID
    (bytes32 requestId) = abi.decode(returndata, (bytes32));

    // Store the request details
    requests[requestId] = Request({
        requester: msg.sender,
        inputData: _inputData,
        signedData: "",
        fulfilled: false,
        validUntil: block.timestamp + REQUEST_EXPIRATION_TIME
    });

    emit RequestMade(requestId, msg.sender, _inputData);
}


    /**
     * @dev Callback function to receive the API3 response.
     * @param requestId Identifier of the API3 request.
     * @param data Data returned by the API3 Airnode.
     * @param signature Signature for the returned data.
     */
    function fulfill(
        bytes32 requestId,
        bytes calldata data,
        bytes calldata signature
    ) external {
        require(msg.sender == api3Proxy, "Fulfill can only be called by API3 Proxy");
        require(!fulfilledRequestIds[requestId], "Request ID already fulfilled");
        fulfilledRequestIds[requestId] = true;

        // Get the request details and verify the signature
        Request storage request = requests[requestId];
        require(block.timestamp <= request.validUntil, "Request expired");

        (address recoveredSigner, ) = abi.decode(signature, (address, bytes32));
        require(recoveredSigner == address(api3Proxy), "Invalid API3 signature");

        // Mark the request as fulfilled and store the signed data
        request.fulfilled = true;
        request.signedData = data;

        // Process the data within the TEE and create a Certified Payload
        bytes memory teeResult = processInTEE(data, request.inputData);
        string memory result = string(teeResult); // Example: Convert result to string for metadata

        // Generate TEE attestation and store it off-chain
        bytes memory attestation = generateAttestation(teeResult);
        bytes32 attestationHash = keccak256(attestation);
        // (Implementation for storing attestation off-chain, e.g., IPFS)

        // Create the Certified Payload NFT
        uint256 payloadId = createOutputNFT(request.requester, result, attestationHash);
        certifiedPayloads[payloadId] = CertifiedPayload({
            payloadId: payloadId,
            requestId: requestId,
            attestationHash: attestationHash,
            metadataURI: result,
            verified: false // Initially not verified
        });

        emit RequestFulfilled(requestId, payloadId, data);
        emit CertifiedPayloadMinted(payloadId, request.requester, result, attestationHash);
    }

    /**
     * @dev Executes the computation within a TEE.
     * @param apiData Data received from the API3 Airnode.
     * @param inputData Additional input data for the computation.
     * @return The result of the computation.
     */
    function processInTEE(
        bytes memory apiData,
        bytes memory inputData
    ) internal returns (bytes memory) {
        require(_isExecutionPermitted(), "Execution not permitted");
        // This function simulates execution within a TEE
        // In a real implementation, this would involve secure data transfer to and from the TEE
        // along with the confidential computation logic

        // Combine API data and input data
        bytes memory combinedData = abi.encodePacked(apiData, inputData);

        // Placeholder for actual TEE computation
        bytes memory result = abi.encodePacked(keccak256(combinedData));

        return result;
    }

    /**
     * @dev Mints a Certified Payload NFT.
     * @param _owner Owner of the NFT.
     * @param _metadataURI Metadata URI for the NFT.
     * @param _attestationHash Hash of the TEE attestation.
     * @return The ID of the minted NFT.
     */
    function mintCertifiedPayload(
        address _owner,
        string memory _metadataURI,
        bytes32 _attestationHash
    ) external onlyOwner returns (uint256) {
        uint256 payloadId = nextPayloadId++;
        _safeMint(_owner, payloadId);
        _setTokenURI(payloadId, _metadataURI);
        certifiedPayloads[payloadId].verified = true;

        emit CertifiedPayloadMinted(payloadId, _owner, _metadataURI, _attestationHash);
        return payloadId;
    }

    /**
     * @dev Overrides the generateAttestation function from EnclaveService.
     * @param data The data to generate an attestation for.
     * @return The TEE attestation.
     */
    function generateAttestation(bytes memory data) internal override onlyTEE returns (bytes memory) {
        // Placeholder for TEE attestation generation logic
        // In a real implementation, this would involve interacting with the Oasis Sapphire TEE
        // to generate a signed attestation based on the provided data.
        bytes32 dataHash = keccak256(data);
        emit AttestationGenerated(dataHash);

        // Placeholder: Simulate the attestation process.
        // This is a simplified version for demonstration purposes.
        // In a real TEE, the attestation would be produced by the secure enclave and would include
        // cryptographic signatures that can be verified to ensure the integrity and authenticity
        // of the computation performed within the TEE.
        bytes memory attestation = abi.encodePacked(
            "Attestation:",
            "Timestamp:", block.timestamp,
            "Data Hash:", dataHash
        );

        return attestation;
    }

    /**
     * @dev Overrides the createOutputNFT function from EnclaveService.
     * @param owner The owner of the new NFT.
     * @param metadataURI The URI pointing to the NFT metadata.
     * @param attestationHash The TEE attestation hash for the computation result.
     * @return The ID of the newly minted NFT.
     */
    function createOutputNFT(
        address owner,
        string memory metadataURI,
        bytes32 attestationHash
) internal override returns (uint256) {
    uint256 payloadId = nextPayloadId++;
    _safeMint(owner, payloadId);
    _setTokenURI(payloadId, metadataURI);
    certifiedPayloads[payloadId] = CertifiedPayload({
        payloadId: payloadId,
        requestId: bytes32(0), // Placeholder, to be filled with actual request ID if applicable
        attestationHash: attestationHash,
        metadataURI: metadataURI,
        verified: true // Mark as verified upon creation
    });

    emit CertifiedPayloadMinted(payloadId, owner, metadataURI, attestationHash);
    return payloadId;
}


    /**
     * @dev Computes the core logic of the Courier. This function is designed to be called within the TEE.
     * @param inputData The input data for the computation, potentially including encrypted data and other parameters.
     * @return The result of the computation.
     */
    function compute(bytes memory inputData) external override onlyTEE returns (bytes memory) {
        // 1. Decrypt inputData if necessary, using keys obtained via Ocean Protocol's ACLs.
        //    This step assumes that the inputData includes information about the data source
        //    and any necessary identifiers to fetch the corresponding decryption keys from Ocean Protocol,
        //    if the data is encrypted and managed under Ocean's ACLs.

        // (Implementation for decrypting data using Ocean Protocol's ACLs and key retrieval)

        // 2. Perform the core computation based on the request.
        //    This is where the main logic of the Courier's computation is executed.
        //    It can involve processing the decrypted
        // 2. Perform the core computation based on the request.
        //    This is where the main logic of the Courier's computation is executed.
        //    It can involve processing the decrypted data, performing calculations, aggregating results, etc.

        // (Implementation for the core computation logic)
        bytes memory computationResult = abi.encode(inputData); // Placeholder: Replace with actual computation

        // 3. Optionally encrypt the output.
        //    If the output data needs to be kept confidential after it leaves the TEE,
        //    it should be encrypted here before being returned.

        // (Implementation for encrypting the output data, if necessary)

        // 4. Return the processed data.
        return computationResult;
    }

    // ... other Courier-specific functions (e.g., staking, slashing) ...
}