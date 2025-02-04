Convenir

Overview Convenir is a modular platform for confidential on‐chain and verifiable off‐chain computation in Web3. It integrates Oasis Sapphire’s hardware-based Trusted Execution Environments (TEEs), API3’s verifiable data feeds, and Ocean Protocol’s token-based data management. The goal is to enable developers to build secure, composable decentralized applications that process sensitive data without sacrificing privacy or verifiability.

Architecture

Off–Chain Confidential Computation • Computation occurs off–chain within Oasis Sapphire’s TEEs (for example, Intel SGX).
• The TEE performs secure computations and produces an attestation quote containing input/output hashes, a code identifier, a timestamp, and a nonce.
• This attestation quote is signed by the TEE’s attestation key off–chain. • A trusted relay or oracle then submits the attestation and its signature on–chain. The contract verifies the signature and records only the verified attestation hash (or an off–chain pointer) for provenance.

Verifiable Data Feeds • API3 Airnodes provide real-time data that is cryptographically signed.
• Convenir’s contracts require that API3 data be submitted along with its signature, which is then verified explicitly on–chain.

Data Management • Ocean Protocol manages encrypted data through Data NFTs with on–chain token-based access control.
• Decryption occurs only within the secure TEE when permission parameters are met.

Standard Interfaces

Attestation Verification & Configuration Inside the smart contracts (for example, in EnclaveService), functions that accept attestation data will consult configurable parameters. For example: • Check that the attestation timestamp is within maxAttestationAge. • Verify that the attestation includes the expected nonce (if requireNonce is true). • Optionally verify that the code hash matches expected values (if verifyCodeHash is enabled).

A sample attestation configuration interface might include a structure such as:

AttestationConfig: maxAttestationAge: Maximum allowed age (in seconds) for a valid attestation. expectedNonce: Expected nonce value (to prevent replay attacks). requireNonce: Flag to enable nonce checking. verifyCodeHash: Flag to enable verification of the TEE code identifier.

Trusted Relayer Management Since off–chain attestations are submitted via relayers, Convenir provides an interface for managing trusted relayer addresses. For example, an interface might define functions as follows:

interface IRelayerManagement { function addTrustedRelayer(address relayer) external; function removeTrustedRelayer(address relayer) external; function isTrustedRelayer(address relayer) external view returns (bool); }

The deployed instance of Courier, Custodian, or other Enclave Services will include functions to set and check these addresses so that only authorized relayers can submit off–chain TEE attestations and computation results.

Contracts

EnclaveService • An abstract base contract that provides core functionality for verifying off–chain attestations and external signatures. • Exposes a verifySignature function for explicit ECDSA signature verification. • Exposes a recordAttestation function which accepts an attestation (produced off–chain) and its signature, verifies it using the configured TEE signer (using the SGX attestation standard), and returns its hash. • Declares an abstract createOutputNFT function that derived contracts must implement.

Courier • Extends EnclaveService and ERC721 (using ERC721URIStorage). • Responsible for making requests to API3 for external data. • Accepts off–chain responses that include both API3 data (with its signature) and a TEE attestation (with its signature). • Calls recordAttestation to verify the TEE attestation. • Mints a Certified Payload NFT that records the verified attestation hash along with computation metadata.

Custodian • Extends EnclaveService and ERC721. • Focuses on managing Data NFTs from Ocean Protocol. • Bundles assets (Data NFTs, Certified Payloads, etc.) into Certified Packages. • Accepts off–chain produced TEE attestations during the package creation process. • Provides functions for configuring authorized couriers for asset updates.

Deployment & Developer Configuration

Developers deploying an instance of Courier, Custodian, or another Enclave Service will:

• Set the TEE Signer: Specify the public key (address) of the trusted TEE signer used for SGX attestation verification.

• Configure Attestation Verification: Use the provided interface to set attestation configuration parameters (such as maxAttestationAge, expectedNonce, etc.) according to their security requirements.

• Manage Trusted Relayers: Add one or more trusted relayer addresses that are permitted to submit off–chain attestations.

• Integrate Off–Chain Storage (Optional): Developers may integrate with external storage solutions (such as IPFS) and include storage pointers along with attestation hashes if desired.

• Deploy via Factories: Use upgradeable factory contracts (for example, using the UUPS proxy pattern) to deploy immutable instances of the core contracts. Factories can be upgraded separately without affecting the deployed Enclave Service contracts.

Future Integrations

While the current proof-of-concept focuses on integrating API3, Oasis, and Ocean Protocol, the standard interfaces are designed to be extensible. Future integrations may include:

• Additional Oracle Providers, such as Chainlink. • Decentralized Storage Solutions for off–chain attestation storage. • Enhanced Confidentiality Modules, such as NuCypher for additional data encryption. • Zero-Knowledge Proofs to improve scalability and privacy.

Contributing

Contributions are welcome. Please refer to the CONTRIBUTING file for guidelines on how to contribute to the project, report issues, and propose enhancements.

License

This project is licensed under the MIT License. See the LICENSE file for details.
