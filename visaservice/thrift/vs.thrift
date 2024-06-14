// vs.thrift - api for the visa service

// This is the new visa-service API for the Reference Implementation. Note that
// the Visa Support Serice API is not longer needed because we have changed 
// the way that a visa service and node connect.
//
// The new connection protocol is:
//
//     1. Start a node. Node is given a visa from the compiler that will allow
//        it to communicate the the visa service when it comes online.
//
//     2. Start the visa service's adatper.  This adapter will present a
//        certificate to the node that is (a) signed by the ZPR authority and
//        (b) has a well known CN that tells the node that it is the visa
//        service's adapter.
//  
//     3. The node allows this adapter to connect -- even though the node has
//        has no policy yet.  The pre-built visa includes the hard-coded visa
//        service adapter's ZPR address.
//
//     ~~ Now this visa sercice API kicks in ~~
//
//     4. The node sends a HELLO message to the visa service.
//
//     5. The visa sercice sends a HELLO-RESPONSE which includes a challenge.
//
//     6. The node performs the crypto operations to satisfy the challenge and
//        sends back the AUTHENTICATE message.
//
//     6. The visa service checks the nodes crypto, checks policy, and if all
//        is well will send back an API Key that the node can use when calling
//        any of the other functions on this API.
// 
//
// TODO: There is currently no mechanism described for how to expire or 
//       refresh the API key.



// The go code slots into core/pkg/vsapi
namespace go vsapi

// The rust goes TBD
namespace rs vsapi


exception UnauthorizedError {}


// Means visa service sends a nonce buffer, and node is expected to 
// create a suitable HMAC.
const i32 CHALLENGE_TYPE_HMAC_SHA256 = 0


enum StatusCode {
  SUCCESS = 0,
  FAIL = 1
}

enum AgentType {
  ADAPTER = 0,
  NODE = 1,
}



// Basic agent to support early iteration of ZPR.
struct Agent {
  1: AgentType agent_type,
  2: map<string, string> attrs,
  3: i64 auth_expires, // unix time stamp
  4: binary zpr_addr,  // assigned ZPR address
  5: binary tether_addr,
  6: string ident,     // unique in this ZPRnet 
  7: list<string> provides,
}



struct Challenge {
  1: i32 challenge_type,
  2: binary challenge_data,
}

struct HelloResponse {
  1: i32 session_id,
  2: Challenge challenge,
}

struct NodeAuthRequest {
  1: i32 session_id,
  2: Challenge challenge,
  3: i64 timestamp,
  4: binary node_cert,
  5: binary hmac,
  6: Agent node_agent,
}


struct ConnectRequest {
  1: i32 connection_id,
  2: binary dock_addr, // dock ZPR address
  3: map<string, string> claims,
  4: binary challenge,  // assume this is old protocol buffer challenge-request
  5: list<binary> challenge_responses,  // assume this is old protocol buffer challenge-response
}


struct ConnectResponse {
  1: i32 connection_id, // copied from request
  2: StatusCode status, // SUCCESS if connect request granted
  3: optional Agent agent,
  4: optional string reason,  // Optional message in case of non SUCCESS
}

struct VisaHop {
  1: binary visa_pb, // visa in "old" protocol buffer form
  2: i32 hop_count,
  3: i32 issuer_id,   // copied out of visa
}

struct VisaRevocation {
  1: i32 issuer_id,
  2: i64 configuration,
}

struct PollResponse {
  1: list<VisaHop> visas,
  2: list<VisaRevocation> revocations,
  3: i32 more, // >0 if there are more visas or revocations available.
}

struct TrafficDesc {
  1: binary source,
  2: binary dest,
  3: i32 protocol,
  4: i32 source_port,
  5: i32 dest_port,
  6: i32 flags,
  7: i16 icmp_type,
  8: i16 icmp_code,
  9: i32 size,
  10: optional binary icmp_addr
}

struct VisaResponse {
  1: StatusCode status,
  2: VisaHop visa,
  3: optional string reason, // optional message if request has failed.
}

service VisaService {

  // Visa Service response to this with a challenge.
  HelloResponse hello(),

  // Node uses this to respond to the `hello` challenge, visa service returns an API key.
  //
  // The HMAC is a SHA256_HMAC(nonce + big_endian(timestamp) + big_endian(session_id)) using the node's private key.
  string authenticate(1:NodeAuthRequest auth_request)

  // De-register removes a node from the visa service access list -- AND visa service assumes that
  // node is disconnecting -- so this also does an agent_disconnect for the node.
  oneway void de_register(1:string key),



  // Node calls this everytime an adapter connects.
  // Note that the visa service assumes that the connection completes.
  // If the agent ends up not connecting, or disconnecting the node must
  // let the visa service know.
  ConnectResponse authorize_connect(1:string key, 2:ConnectRequest request),


  // Notify the visa service that an agent has disconnected. Pass in the ZPR address
  // assigned to the agent via `authorize_connect`.  
  void agent_disconnect(1:string keym, 2:binary zpr_addr),

  PollResponse poll(1:string key),

  VisaResponse request_visa(1:string key, 2:binary src_tether_addr, 3:TrafficDesc traffic),

}
