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
The main embedded device I have in mind is the Raspberry Pi, which has enough computing power
to do a lot of neat things while remaining low-power and inexpensive. A Pi can currently act
as either a server or a client on the network; In the future, versions of the client targeting 
smaller and cheaper microcontroller modules are also planned.  
  
### Network Architecture
Teamech uses a tree topology for its networks. Networks must include at least one server, and
may include any number of clients. Messages sent from one client to the server are relayed to
any subset of clients based on each client's unique name and set of group-defining classes.  
Teamech uses UDP as its transport layer to improve latency, simplicity, and behavior of 
links that remain idle for long periods. By default, the Teamech server is configure to
exchange data on UDP port 6666, but this is configurable. Clients may use any free port. 
As UDP is a connectionless protocol, Teamech uses "subscriptions" to manage which packets are
sent where. When a new client sends a valid encrypted message to the server, the server adds 
it to a list of "subscribed" (active) clients, and begins relaying messages from other clients 
to the new client. Clients are unsubscribed when they cancel their subscription or fail to 
acknowledge too many relayed messages at a time.
  
### Communication
Whenever a client wants to send a message over a Teamech network, it assembles a message containing 
its name and primary class, an expression matching the names and/or classes of the message's intended 
recipients, and the message's contents. It then encrypts this message and sends it over the network to 
the server. The server decrypts the message, logs itscontents, and relays it to all clients who match 
its address pattern. If other servers are connected to the server that receives the message, the message 
will also be passed along to the other servers, allowing large distributed networks to be created. 
Protection against infinite loops is present.  
Clients bearing the "supervisor" class are always sent all messages. This class does not offer any 
security for supervisor privileges, and is mainly intended to keep network traffic volumes lower (by 
not sending every message to every client). 
Teamech imposes a maximum packet size of 8192 bytes. This is much higher than the maximum recommended
UDP packet size (508 bytes) and packets over the recommended maximum may be frequently dropped in transit,
especially over long distances. Depending on network infrastructure, larger packets may be sendable over
short distances, and so have been allowed by Teamech itself in case they prove useful.
  
### Security
Teamech includes its own custom encryption scheme, Teacrypt, which is designed to be simple 
and reasonably secure. While it should not be relied upon in cases where security is critical,
it should be good enough to prevent your nosy neighbors, IT department, or local police from
spying on you thanks to its high toughness against brute-force decryption and man-in-the-
middle attacks. Teacrypt provides integrity verification for all messages and requires clients
to authenticate using their encryption keys before they can subscribe; messages that were not
encrypted correctly with the same key that the server uses are rejected and not relayed.
As a symmetric-key algorithm, however, Teacrypt relies on the physical security of both the 
server and the client devices, and so these devices must be trusted and physically accounted 
for at all times for the network to remain secure. Additionally, exchange of keys must be done 
out-of-band before a client can contact a server.  
Generally speaking, Teamech networks are only secure against outsiders, and are very vulnerable 
to malicious devices which have been entrusted with the appropriate key file. In all cases, the 
network operator is encouraged to only connect devices whose software and operating conditions 
are fully understood, ideally those which have been home-built. Once a device has access to
the network, there is nothing to stop it from sending any message to any device, or claiming
itself to be any class of device. For very sensitive applications or networks managed by more
than one person, it is strongly recommended to use another authentication layer on top of 
Teamech to verify messages on a per-client basis.
  
### Server
The Teamech server is essentially a very simple packet relay with message authentication. It
can run on very low-powered hardware, and requires network throughput capability equal to the
maximum continuous throughput from each client times the typical number of clients. For most 
control applications, this throughput will be very low.  
Clients subscribed to a server can declare one unique name and any number of non-unique classes. Names
are prefixed with the character `@`, while classes are prefixed with `#`. Packets sent to the server to
be relayed contain a Boolean expression that matches any number, packet length permitting, of names and
classes (i.e. `(@foo|#bar)&#baz` to match clients in the class `#baz` and either the name `@foo` or the
class `#bar`).  
Servers can be linked to each other through the same mechanism as client-server subscriptions. In this
case, servers send each other all packets that are relayed through them, and relay all incoming packets
provided they do not match any recently-relayed packets (as a loop-mitigation measure). Since all
traffic is routed between servers regardless of destination address expressions, server-server links
will require considerably more bandwidth than individual server-client links.

### Clients
A Teamech client is any device on the network connected to a physical machine being controlled or
doing the controlling. One client might run on a computer terminal facing a human user, which communicates
with another connected to an electrical apparatus being controlled over the network. Raspberry Pis are
well-suited to the latter role, as they are very inexpensive and their GPIO interfaces allow them to
be connected to a huge variety of different devices.
The basic Teamech data exchange functionality is provided by this library, but a special Teamech client
should be implemented using it for each different device being used.

### Encryption Setup
In order to work, both the Teamech server and client must use a large symmetric key file, referred
to elsewhere as a pad file. In theory, any file will work as a pad file, but for optimal security,
the pad file should be generated using a secure random number generator.  
For optimal security, you should replace the pad file and install a new one on all of the network's 
devices every time the network exchanges a total of about half the pad file's size using that pad.
This is not operationally necessary, and there are currently no known vulnerabilities that would cause
failure to update the pads to allow an attacker to gain access to the system or decrypt its messages,
but by doing this, you ensure that you're at least a moving target should this change.  
Pad files should be large enough to be reasonably sure of including every possible byte at least once.
Practically, they should be as large as you can make them while still reasonably holding and transporting
them using the storage media you have available. A few megabytes is probably reasonable.  
On Linux, you can generate a pad file easily using `dd` and `/dev/urandom`. For instance, to create
a 10-megabyte pad:  
`dd if=/dev/urandom of=teamech-october-2018.pad bs=1M count=10 status=progress`  
You should then copy this pad file to the server and all clients, and select it as the pad file to
use at the command line.  
I make absolutely no guarantees about the security of any Teamech network, no matter what key size 
and key life cycle practices you adhere to. This software is a personal project to familiarize myself
with cryptography, network programming, and version control, and you shouldn't trust it in any context.
Teamech's security is best thought of as similar to that of unencrypted data being transmitted over
a long cable - it's probably safe, but only provided that no one is seriously interested in it.

### Mobile Support
Smartphone-based clients are not planned for any of the Teamech reference implementations. However, there
is no reason that one couldn't be written, so I may eventually attempt to write an Android app depending 
on how useful this project becomes. I don't plan to ever write an iOS app, since I have no desire to
purchase any Apple hardware or to send anything through Apple's approval process.  
Due to the vulnerability of the Teamech system to insider attacks, the use of smartphone-based clients
is liable to seriously compromise the security of Teamech networks as a result of the heavily-monitored
nature of smartphones. This may be considered an acceptable risk by some, but it bears mentioning.

### Origin of Name
The name "Teamech" comes from a naïve and silly mishearing of a voice line from Overwatch, when
Brigitte activates her ultimate ability. The real line is "Alla till mig!" (Swedish: "Everyone to me!").
It doesn't really sound like "tea mech" even to the most obtuse American ear, but I guess I had bad 
speakers when I first played Overwatch.  
