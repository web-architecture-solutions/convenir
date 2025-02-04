// SPDX-License-Identifier: MIT pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol"; 
import "./EnclaveService.sol"; 
import "@api3/contracts/v0.8/interfaces/IProxy.sol"; 
import "./ICustodian.sol"; 
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

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
        bytes32 attestationHash;
        string metadataURI;
        bool verified;
    }

    mapping(bytes32 => Request) public requests;
    mapping(uint256 => CertifiedPayload) public certifiedPayloads;
    mapping(bytes32 => bool) public fulfilledRequestIds;

    // The API3 proxy address (used for making requests and verifying API3 signatures)
    address public immutable api3Proxy;
    uint256 public nextPayloadId;

    // Optional: interface to a Custodian contract
    ICustodian public custodian;

    uint256 public constant REQUEST_EXPIRATION_TIME = 5 minutes;

    event RequestMade(bytes32 indexed requestId, address indexed requester, bytes inputData);
    event RequestFulfilled(bytes32 indexed requestId, uint256 indexed payloadId, bytes signedData);
    event CertifiedPayloadMinted(uint256 indexed payloadId, address owner, string metadataURI, bytes32 attestationHash);

    // Constructor: sets the API3 proxy and passes the TEE signer and initial attestation config to the base contract
    constructor(address _api3Proxy, address teeSigner, AttestationConfig memory initialConfig)
        ERC721("CertifiedPayload", "CPAY")
        EnclaveService(teeSigner, initialConfig)
    {
        api3Proxy = _api3Proxy;
        nextPayloadId = 1;
    }

    // Allows the owner to set the custodian address (if used)
    function setCustodian(address _custodian) external onlyOwner {
        custodian = ICustodian(_custodian);
    }

    // Function for making a request to an API3 Airnode.
    // Forwards the request to the API3 proxy.
    function makeRequest(
        address _airnode,
        bytes32 _endpointId,
        bytes calldata _encodedParameters,
        bytes calldata _inputData
    ) external payable {
        require(custodian == ICustodian(address(0)) || custodian.isAuthorized(msg.sender), "Caller is not authorized");
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
        bytes32 requestId = abi.decode(returndata, (bytes32));
        requests[requestId] = Request({
            requester: msg.sender,
            inputData: _inputData,
            signedData: "",
            fulfilled: false,
            validUntil: block.timestamp + REQUEST_EXPIRATION_TIME
        });
        emit RequestMade(requestId, msg.sender, _inputData);
    }

    // fulfill is the callback function invoked by the API3 proxy.
    // It accepts:
    //   - API3 data and its signature,
    //   - The off-chain produced TEE attestation and its signature.
    // It verifies the API3 signature, then calls recordAttestation to verify the TEE attestation,
    // processes the data, and mints a Certified Payload NFT.
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
        Request storage req = requests[requestId];
        require(block.timestamp <= req.validUntil, "Request expired");
        require(verifySignature(data, api3Signature, api3Proxy), "Invalid API3 signature");
        req.fulfilled = true;
        req.signedData = data;
        // Process data via off-chain TEE computation simulation
        bytes memory teeResult = processInTEE(data, req.inputData);
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

    // processInTEE simulates confidential computation by combining API3 data with inputData.
    // In production, the off-chain TEE would perform the computation and return a result.
    function processInTEE(
        bytes memory apiData,
        bytes memory inputData
    ) internal returns (bytes memory) {
        bytes memory combined = abi.encodePacked(apiData, inputData);
        return abi.encodePacked(keccak256(combined));
    }

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
    function compute(bytes memory inputData) external override returns (bytes memory) {
        return inputData;
    }
}