// vs.thrift - api for the visa service
// 


// The go code slots into core/pkg/vsapi
namespace go vsapi

// The rust goes TBD
namespace rs vsapi



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


struct ChallengeResponse {
  1: i32 challenge_type,
  2: i32 response_type,
  3: binary response_data,
}


struct ConnectRequest {
  1: i32 connection_id,
  2: binary dock_addr, // dock ZPR address
  3: map<string, string> claims,
  4: binary challenge,
  5: binary challenge_response,
}


struct ConnectResponse {
  1: i32 connection_id, // copied from request
  2: StatusCode status, // SUCCESS if connect request granted
  3: optional Agent agent,
  4: optional string reason,     // Optional message in case of non SUCCESS
}

struct VisaHop {
  1: binary visa_pb, // visa in protocol buffer form
  2: i32 hop_count
}

struct VisaRevocation {
  1: i32 issuer_id,
  2: i64 configuration,
}

struct PollResponse {
  1: list<VisaHop> visas,
  2: list<VisaRevocation> revocations,
  3: i32 more,
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

  // Polite disconnect message.
  oneway void de_register(1:string key),



  // Node calls this everytime an adapter connects.
  ConnectResponse authorize_connect(1:string key, 2:ConnectRequest request),

  PollResponse poll(1:string key),

  VisaResponse request_visa(1:string key, 2:binary src_tether_addr, 3:TrafficDesc traffic),

}
