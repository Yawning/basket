### basket: More eggs in the Guard basket.
#### Yawning Angel (yawning at schwanenlied dot me)

Basket is a experimental pluggable transport aimed at increasing Tor's
resistance to end-to-end correlation attacks (amongst other things) by
utilizing active defenses that are extremely bandwidth intensive.

The "correct" way to do this sort of thing would be to run the defense from
the client to at least the middle relay, but doing so is incredibly difficult
due to the need for a substantial fraction of the network to upgrade for that
to be effective, and the numerous technical problems (such as the massive
catastrophic performance impact due to HOL issues and the dramatic increase
in bandwidth requirements).  The people that say to just use ScrambleSuit for
inter-relay traffic are being naive at best as the defenses there are designed
with a enterely different adversary in mind (and still guts performance).

So basket does things the "wrong" way and runs the defense to the Guard, on the
assumption that people that care, could run their own Bridge.  The downside here
is that, unless the Bridge in question is actually servicing a decent number of
users, running a fancy defense doesn't actually buy anything vs adversaries that
can observe all of the traffic to/from the Bridge, and it requires a Guard that
can be trusted absolutely.  Such is the life of tradeoffs.

As an added bonus, traffic between the client and the Bridge is secured using
cryptographic primitives that are thought to be resistant to quantum computing
based attacks in addition to standard classical primitives (So, even if the
PQ crypto primitives are broken, the adversary will still need a quantum
computer).

Dependencies:
 * code.google.com/p/go.crypto
 * github.com/agl/ed25519
 * github.com/dchest/blake256
 * github.com/dchest/blake512
 * github.com/yawning/ntru
 * github.com/yawning/sphincs256

WARNINGS:
 * If your Bridge is actively malicious, you will lose.  Thus the name as it is
   placing more eggs in the Guard basket.
 * If you are the only user of a given Bridge, and the adversary can observe the
   Bridge, you will lose.  It is an open question as to how much traffic volume
   is adequate cover on each Bridge.
 * No attempt is made to hide the fact that basket is being used.  If you are
   primarily interested in reachability, look at obfs4 instead.
 * This consumes a rediculous amount of bandwidth for cover traffic, and
   a non-trivial amount of CPU for the handshake.
 * The bulk throughput of each connection is limited by the active defense
   parameters.  Don't put "linenhighwayd3g6.onion" or whatever bullshit
   marketplace that gets a lot of traffic behind a basket link and come crying
   to me when it's slow, though it may work as long as your link is big enough
   since the transmission rate will adapt to link conditions.
 * This is experimental and should not be used by anybody.

Notes:
 * I'll document the protocol when I get around to it, in the meanwhile read
   the code.
 * Pulling out the TCP/IP state via getsockopt is non-portable and requires
   platform specific code.  BSD support is possible, but hasn't been done yet.
   Patches accepted for Windows.
 * Not using the obfs4proxy framework is a licensing/packaging based decision
   rather than a technical one.

TODO:
 * Allow specifying the various algorithms via options/bridge line.
 * Allow specifying the AuthKey via options/bridge line.
 * Actually implement CS-BuFLO.

Acknowledgements:
 * Thanks to Marc Juarez (KU Leuven) and Mike Perry, who provided inspiration
   and kickstarted my interest in this subject.
