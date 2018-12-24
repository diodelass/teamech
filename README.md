# Teamech
## A Simple Application Layer for the Intranet of Things
  
### Introduction
For many folks who work on technology, the "Internet of Things" has become a scary term. It 
brings to mind completely frivolous and frighteningly insecure systems that let you use your
smartphone to control your household appliances remotely, usually involving a propretary app
and company-hosted web service for each device. In spite of how awful this is, I don't think
that the core concept of networked devices is always useless and silly, and for the few
particular applications where network control makes sense, it's possible to implement it in
a simple, useful, and sane way. Teamech is my first attempt to do this. It attempts to be a
minimal, easy-to-understand SCADA system for controlling small networks of devices on the
scale of a household or laboratory, with adequate security and very small resource footprint.  
Teamech is designed for constructing an IoT network which does not rely on a bunch of
distant, unrelated servers operated by device vendors, but instead uses an on-site server
operated by the owner of the devices managed by the network. It is thus not reliant on any
company or other third party to remain operational, unlike many extant consumer IoT devices.
The main embedded device I have in mind is the Raspberry Pi, which has enough computing power
to do a lot of neat things while remaining low-power and inexpensive. A Pi can currently act
as either a server or a client on the network; In the future, versions of the client 
targeting smaller and cheaper microcontroller modules are also planned.  
  
### Network Architecture
Teamech uses a tree topology for its networks. Networks must include at least one server, and
may include any number of clients. Messages sent from one client to the server are relayed to
any subset of clients based on each client's unique name and set of group-defining classes.  
Teamech uses UDP as its transport layer to improve latency, simplicity, and behavior of 
links that remain idle for long periods. By default, the Teamech server is configure to
exchange data on UDP port 3840, but this is configurable. Clients may use any free port. 
As UDP is a connectionless protocol, Teamech uses "subscriptions" to manage which packets are
sent where. When a new client sends a valid encrypted message to the server, the server adds 
it to a list of "subscribed" (active) clients, and begins relaying messages from other clients 
to the new client. Clients are unsubscribed when they cancel their subscription or fail to 
acknowledge too many relayed messages at a time.
  
### Communication
Whenever a client wants to send a message over a Teamech network, it assembles a message
addressed to a certain set of recipients and containing some data payload. It then encrypts
this message and sends it over the network to the server. The server decrypts the message and
logs its contents, then re-encrypts it and relays it to each other client matching its
address pattern. If other servers are connected to the server that receives the message, the
message will also be passed along to the other servers, allowing large distributed networks
to be created. Protection against infinite loops is present, meaning that servers can be
linked into an arbitrarily-organized mesh while retaining functionality - although some
network topologies may exhibit lower latency than others for a given application.
Clients registered to the "supervisor" class are always sent all messages, allowing them to
observe all activity on the network.
Teamech imposes a maximum packet size of 8192 bytes. This is much higher than the maximum
recommended UDP packet size (508 bytes) and packets over the recommended maximum may be
frequently dropped in transit, especially over long distances. Depending on network
infrastructure, larger packets may be sendable over short distances, and so have been allowed
by Teamech itself in case they prove useful.
  
### Security
Teamech uses a custom symmetric-key authenticated encryption system to secure messages,
informally called `teacrypt`, which leverages the speed and security of the Keccak hash
function (SHA-3) as a block cipher. `teacrypt` is currently still in heavy development
and will often see broken backwards-compatibility with new versions. The 1.0 release of
Teamech will signify, among other things, the establishment of a stable specification for
`teacrypt`. 
Unlike previous iterations of `teacrypt`, the one provided in version 0.10.0 and onwards 
provides some degree of internal compartmentalization that reduces the impact of insider 
attacks. Rather than using a single key for the entire network, each client now registers its
own unique key, and can thus only decrypt messages intended for it. With server-side 
identities also in place, it is no longer possible to spoof messages from arbitrary clients
once subscribed to the network.
  
### Server
The Teamech server acts as a packet relay and network authenticator, handling message 
verification, client registrations, and activity logging in addition to data transfer. It can
run on very low-powered hardware, and requires network throughput capability equal to the 
maximum continuous throughput from each client times the typical number of clients. For most
control applications, this throughput will be very low.  
Clients registered with a server have one unique name and any number of non-unique classes 
associated with them. Names are prefixed with the character `@`, while classes are prefixed
with `#`. Packets sent to the server to be relayed contain a boolean expression that matches
any number, packet length permitting, of names and classes (i.e. `(@foo|#bar)&#baz` to match
clients in the class `#baz` and either the name `@foo` or the class `#bar`).  
Servers can be linked to each other through the same mechanism as client-server 
subscriptions. In this case, servers send each other all packets that are relayed through 
them, and relay all incoming packets provided they do not match any recently-relayed packets
(as a loop-mitigation measure). Since all traffic is routed between servers regardless of 
destination address expressions, server-server links will require considerably more bandwidth
than individual server-client links.

### Clients
A Teamech client is any device on the network connected to a physical machine being 
controlled or doing the controlling. One client might run on a computer terminal facing a
human user, which communicates with another connected to an electrical apparatus being 
controlled over the network. Raspberry Pis are well-suited to the latter role, as they are
very inexpensive and their GPIO interfaces allow them to be connected to a huge variety of
different devices. The basic Teamech data exchange functionality is provided by this library,
but a special Teamech client should be implemented using it for each different device being
used.

### Registration Setup
In order to connect to the server, clients must have a unique identity file associated with
them and registered on the server. These identity files contain the names and classes of the
client, a 64-bit tag, and a 256-bit encryption key. The `keygen` program found in the
`examples` directory can be used to generate a new identity file (with placeholder names and
classes, which should be changed). Clients must specify the path to their identity file on
the command line. Servers will load all identity files found in a certain directory, usually
`teamech/keys/server/` (determined by static variables).  
I make absolutely no guarantees about the security of any Teamech network, no matter what key
size and key life cycle practices you adhere to. This software is a personal project to
familiarize myself with cryptography, network programming, and version control, and you
shouldn't trust it in any context. Teamech's security is best thought of as similar to that
of unencrypted data being transmitted over a long cable - it's probably safe, but only
provided that no one is seriously interested in it.

### Mobile Support
Smartphone-based clients are not planned for any of the Teamech reference implementations.
However, there is no reason that one couldn't be written, so I may eventually attempt to
write an Android app depending on how useful this project becomes. I will not write an iOS
client, and iOS clients may not be written using this library, due to the Apple App Store's
inherent non-compliance with the (A)GPL.

### Origin of Name
The name "Teamech" comes from a naïve and silly mishearing of a voice line from Overwatch,
when Brigitte activates her ultimate ability. The real line is "Alla till mig!" (Swedish:
"Everyone to me!"). It doesn't really sound like "tea mech" even to the most obtuse American
ear, but I guess I had bad speakers when I first played Overwatch.  
