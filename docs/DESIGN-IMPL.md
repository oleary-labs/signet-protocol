Important characteristics of intended design:

* a single instance of a signet server - also referred to as a node - will be part of one or more groups of nodes.
* the overall protocol will define and manage groups of nodes. 
* groups are defined and managed users of the systems that can be application developers or any user who needs to manage keys and signing on behalf of end users.
* end users can submit key generation and signature requests to any node in a group.
  * the node that receives the requests will coordinate with other nodes in the group to accomplish the request.
* at any given time, a given node must be able to simultaneously and efficiently service multiple concurrent requests from users of the same and different groups.
  * in other words, the implementation must not have any bottlenecks handling keygen or signing within the same group of nodes or across different groups.  


* the implementation should strongly bias efficiency of the communication protocol
  * each round of the protocol keygen and signing protocols requires communication across the network.
  * the network should be assumed to be the internet - assume there will be significant latency
  * the implementation should require direct server-to-server connections for protocol communication. do not gossip protocol communications.
  * server-to-server communication requires that the implementation maintain direct connections to all active servers in all active groups.
  * these connections can and will be used to service many concurrent executions of keygen and signing protocols.

TRANSPORT SECURITY
* FROST (RFC 9591) requires authenticated channels — each node must be certain which peer sent each message, but confidentiality of signing-round messages is not required by the protocol.
* DKG (keygen) has a stricter requirement: bytemare/dkg explicitly requires confidential, authenticated, secure channels because round-2 messages carry unicast secret share fragments that must be readable only by the intended recipient.
* The current implementation satisfies both requirements automatically. libp2p defaults to the Noise protocol for transport security, which provides mutual authentication (peer identity is cryptographically bound to the libp2p keypair) and encryption on every stream. No additional work is needed.

RESHARE
* Neither bytemare/frost nor bytemare/dkg currently supports resharing. The reshare stub in tss/reshare.go is a placeholder.
* Resharing allows the group to rotate key shares without reconstructing or changing the underlying secret key. Use cases: adding/removing nodes from a group, changing the signing threshold, proactive share refresh to limit the window of exposure from a compromised node.
* Planned approach: Lagrange-weighting on top of Feldman VSS (Herzberg et al. 1995 proactive secret sharing), adapted to produce FROST-compatible output shares.
  * Each old participant splits their share into sub-shares using a new random polynomial and distributes them to new participants.
  * New participants combine received sub-shares via Lagrange interpolation to reconstruct a fresh share of the same secret.
  * Feldman VSS commitments allow new participants to verify the consistency of received sub-shares without reconstructing the secret.
* This is an improvement over a naive reshare because it avoids reconstructing the secret at any point and gives new participants cryptographic verification of their shares. The security assumption is that fewer than threshold old nodes are actively malicious during the reshare window.
* Adaptive adversary hardening (Canetti et al.) is a further possible extension but is deferred.


DATA MANAGEMENT
* the node config should have a parameter that refers to the data directory of the node.
  * the config parameter will be 'data_dir'
* all data artifacts will be stored under this directory.
  * necessary child file names in the data directory will be picked by the implementation
  * the current node key file will be named 'node.key'
  * we will use the bbolt library to store key shard data.
  * the key shards will be stored in a file named 'keyshards.db'

SMART CONTRACTS / GROUP + NODE MEMBERSHIP MANAGEMENT
* A set of Solidity smart contracts will define and manage grouping of nodes that participate in the protocol.
* There will be a factory contract that allows anyone to create a group. This allows us to control the implementation of the group logic.
* The group creator can be any user who wants to select a set of nodes to collectively create shared keys and use them for signing.
* Although the group creator can be anyone, the assumed use case will be an application developer who wants end users to create accounts to interact with their application.
* The factory should maintain a global list of registered nodes.
  * Any node operator can register with the factory without permissions.
  * The registration should validate that the registering account corresponds to the public ID (public key) of the node.
  * The registered node will also indicate whether they are open to be added to any group who wants them, or whether the node operator can decline to be added to a group.
* While a group creator can ask for any node to be included in the group - depending on the node operator's choice - it may be necessary for the node operator to accept the inclusion.
* A group creator or manager can opt to remove a node at anytime. There should be a delay queue for this change.
* Similarly, a node operator can remove themselves from a group at any time. This should also have a queue to delay the change.
* The registration and acceptance of nodes should emit appropriate events so that this data can be indexed from the blockchain.
* Similarly, remove of nodes from groups should emit corresponding events.
* There should be a method of a group contract that allows for the iteration of all active nodes in the group.
  * given that there will only ever be a relatively small number of nodes in a group, this can be managed with an array.
* This group should also define the important parameters of the protocol, such as the required node threshold for keygen and signatures.

NODE DISCOVERY
* Nodes can be configured with a static set of known peers at startup (bootstrap peers).
* The on-chain registry contains a node's identity (public key / libp2p peer ID) but NOT its physical network address. Addresses must be discovered dynamically through peer-to-peer mechanisms.
* Discovery approach:
  * Bootstrap peers are the seed: a new node connects to its configured bootstrap peers on startup.
  * From there, address resolution uses DHT rendezvous: each node advertises its multiaddr under its peer ID in the DHT. When a chain event signals a new node has joined a group, existing nodes use the new node's peer ID (from chain) to look up its address via the DHT.
  * libp2p's peerstore also propagates addresses transitively through connected peers, so a node reachable by any bootstrap peer becomes discoverable by the whole network over time.
* Node departure is less common but must also be handled:
  * A node removal event on-chain triggers peers to drop that connection and update their in-memory group membership.
  * Nodes should also handle ungraceful departures (connection loss / timeout) by marking the peer unavailable and retrying with backoff, independent of any on-chain signal.
* Direct peer connections (not gossip) are maintained for protocol communication, consistent with the latency-efficiency requirement above. Discovery feeds the pool of peers that direct connections are established to.

NODE STARTUP and GROUP MEMBERSHIP MANAGEMENT
* When nodes start up they should read their group membership information from a configured blockchain.
* In order to do this the group factory contract should maintain a mapping from its node id to active groups it is a member of.
* The mapping in the factory will be maintained from group contracts when nodes become active and inactive.
* After the node discovers it's current group membership state on startup it will watch blockchain events to dynamically detect when group membership changes.
* Nodes will keep an internal mapping - in memory - of which groups they belong to and the other nodes in that group.
* Using this mapping, keygen and signing requests will refer to the id of the group - the groups contract address - when submitting requests. Node will look up the nodes in the group from the mapping.
* In the keygen and signing api's there should not be a session id. during keygen the caller should specify a key id. the new key will be
  generated and stored under that id. the signing api should ask for keys by id. those key names are scoped to the group id. this requires that
  storage of node key shard info be scoped by group id and key id.

KEY SCOPING AND SMART WALLET INTEGRATION
* Keys are stored under (group_id, key_id). When a group has OAuth issuers configured, key_id is derived as iss:sub or iss:sub:suffix — globally unique across providers. Groups without issuers require key_id to be supplied explicitly.
* A user authenticating with the same provider to two different groups will derive the same key_id path but produce separate key entries (different key material, different public keys). This is intentional — the group is the security and operational context for the key.
* Known limitation: there is currently no mechanism for a user to hold the same public key across groups. Each group independently generates fresh key material for the same identity. For use cases where the user's key represents a portable on-chain identity this is a constraint, but it is acceptable for the current design.
* Intended use case: the FROST key controls an EIP-4337 smart wallet. The threshold signature acts as the owner/signer of the account, and user operations are authorized by the group producing a valid signature. This means the key does not need to be portable — the smart wallet address is the stable identity, not the signing key itself.
* Future consideration: there may be mechanisms to discover or link a derived key to an existing smart wallet. For example, an application or user could register a mapping from their iss:sub identity to an existing account address on-chain, allowing the system to recognize returning users and associate new key material with an existing wallet rather than implying a new one. This is not designed yet.