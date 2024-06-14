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


struct VSChallenge {
  1: i64 session_id,
  2: binary nonce,
}


typedef string APIKey

service VisaService {

  VSChallenge hello(),
  APIKey authenticate(1:VSChallenge challenge, 2:i64 timestamp, 3:binary node_cert, 4:binary hmac, 5:Agent node_agent),  

  oneway void de_register(1:APIKey key),

  // Node calls this everytime an adapter connects.
  ConnectResponse authorize_connect(1:APIKey key, 2:ConnectRequest request)
}
