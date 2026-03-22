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


* currently, test logs show many instances of a 'round already finalized' message
  * this implies that the currently implementation is not efficiently detecting when a protocol round has finalized and is continuing to spam the network with unnecessary messages.


TODO
* implement the event-driven fix and remove the artificial sleep
* BUG: protocol hangs / spins if requested key does not exist


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