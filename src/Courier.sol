// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@api3/contracts/v0.8/interfaces/IProxy.sol";
import "./EnclaveService.sol";
import "./ICustodian.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title Courier
 * @dev A specialized EnclaveService for fetching and processing external data using API3.
 */
contract Courier is EnclaveService, ERC721URIStorage {
    using ECDSA for bytes32;

    struct Request {
        address requester;
        bytes inputData;
        bytes signedData;
        bool fulfilled;
        uint256 validUntil;
    }

    struct CertifiedPayload {
        uint256 payloadId;
        bytes32 requestId;
        bytes32 attestationHash; // Verified TEE attestation hash
        string metadataURI;
        bool verified;
    }

    mapping(bytes32 => Request) public requests;
    mapping(uint256 => CertifiedPayload) public certifiedPayloads;
    mapping(bytes32 => bool) public fulfilledRequestIds;

    // The API3 proxy contract address (also used as the expected signer for API3 responses)
    address public immutable api3Proxy;
    uint256 public nextPayloadId;
    ICustodian public custodian;
    uint256 public constant REQUEST_EXPIRATION_TIME = 5 minutes;

    // Events
    event RequestMade(bytes32 indexed requestId, address indexed requester, bytes inputData);
    event RequestFulfilled(bytes32 indexed requestId, uint256 indexed payloadId, bytes signedData);
    event CertifiedPayloadMinted(uint256 indexed payloadId, address owner, string metadataURI, bytes32 attestationHash);

    /**
     * @dev Constructor.
     * @param _api3Proxy Address of the API3 proxy contract.
     * @param _teeSigner Address of the TEE signer (used to verify attestation).
     */
    constructor(address _api3Proxy, address _teeSigner)
        ERC721("CertifiedPayload", "CPAY")
        EnclaveService(_teeSigner)
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
        // If a Custodian is used, ensure the caller is authorized.
        require(
            custodian == ICustodian(address(0)) || custodian.isAuthorized(msg.sender),
            "Caller is not authorized"
        );

        // Forward the request to the API3 proxy.
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

        // Decode the returned request ID.
        bytes32 requestId = abi.decode(returndata, (bytes32));

        // Store the request details.
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
     * @dev Callback to receive the API3 response and the TEE attestation.
     * @param requestId Identifier of the API3 request.
     * @param data Data returned by the API3 Airnode.
     * @param api3Signature Signature over the API3 data.
     * @param teeAttestation The attestation produced by the Oasis TEE.
     * @param teeAttestationSignature Signature over the TEE attestation.
     */
    function fulfill(
        bytes32 requestId,
        bytes calldata data,
        bytes calldata api3Signature,
        bytes calldata teeAttestation,
        bytes calldata teeAttestationSignature
    ) external {
        require(msg.sender == api3Proxy, "Fulfill: Caller must be API3 Proxy");
        require(!fulfilledRequestIds[requestId], "Request already fulfilled");
        fulfilledRequestIds[requestId] = true;

        Request storage request = requests[requestId];
        require(block.timestamp <= request.validUntil, "Request expired");

        // Verify the API3 signature explicitly.
        require(verifySignature(data, api3Signature, api3Proxy), "Invalid API3 signature");

        // Mark request as fulfilled.
        request.fulfilled = true;
        request.signedData = data;

        // (Optional) Process the data via TEE if needed.
        bytes memory teeResult = processInTEE(data, request.inputData);
        string memory result = string(teeResult); // For example, used as NFT metadata

        // **Key change:** Instead of simulating attestation, record the externally produced attestation.
        bytes32 attestationHash = recordAttestation(teeAttestation, teeAttestationSignature);

        // Create the Certified Payload NFT.
        uint256 payloadId = createOutputNFT(request.requester, result, attestationHash);
        certifiedPayloads[payloadId] = CertifiedPayload({
            payloadId: payloadId,
            requestId: requestId,
            attestationHash: attestationHash,
            metadataURI: result,
            verified: true // Mark as verified upon creation
        });

        emit RequestFulfilled(requestId, payloadId, data);
        emit CertifiedPayloadMinted(payloadId, request.requester, result, attestationHash);
    }

    /**
     * @dev Simulated confidential computation.
     * In a production system, the TEE would perform this off–chain.
     * @param apiData Data from API3.
     * @param inputData Additional input data.
     * @return The computation result.
     */
    function processInTEE(
        bytes memory apiData,
        bytes memory inputData
    ) internal returns (bytes memory) {
        // Here you would normally transfer data to/from the TEE.
        // For demonstration, we simply hash the combined data.
        bytes memory combinedData = abi.encodePacked(apiData, inputData);
        return abi.encodePacked(keccak256(combinedData));
    }

    /**
     * @dev Mints a Certified Payload NFT.
     * @param owner The NFT owner.
     * @param metadataURI The NFT metadata URI.
     * @param attestationHash The hash of the verified TEE attestation.
     * @return The new NFT's ID.
     */
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

    /**
     * @dev Core computation logic.
     * For demonstration, simply returns the input.
     * @param inputData The input data.
     * @return The computation result.
     */
    function compute(bytes memory inputData) external override returns (bytes memory) {
        return abi.encode(inputData);
    }
}
