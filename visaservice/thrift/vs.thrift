
/**
 * vs.thrift
 *
 * This file includes:
 *  - the visa struct (passed around in the visa service APIs)
 *  - the visa service API (runs on a visa service)
 *  - the visa support service API (runs on a node)
 */



// The go code slots into core/pkg/vsapi
namespace go vsapi

// The rust goes TBD
namespace rs vsapi



////////////////////////////////////////////////////////////////////////////////
//
// Types related to the visa data structure
// ========================================
//
//



/** Which pre-defined PEP the visa is targeting. */
enum PEPIndex {
  UDP = 1,
  TCP = 2,
  ICMP =3,
}


/** The visa session key */
struct KeySet {
    1: i32 format,

    /** session key encrypted for ingress node to read  */
    2: binary ingress_key,

    /** session key encrypted for egress node to read */
    3: binary egress_key,
}


/** Visa constraints. */
struct Constraints {
    /** not set or none means no bandwidth constraint  */
    1: bool bw,
    2: i64 bw_limit_bps,
    /** empty/None means no data cap  */
    3: string data_cap_id,
    4: i64 data_cap_bytes,
    /** tether address of service agent  */
    5: binary data_cap_affinity_addr,
}


/** Visa can be signed */
struct Signature {
    1: i32 type,
    2: binary signature,
}


/** Shared by both TCP and UDP basic PEPs. */
struct PEPArgsTCPUDP {
    1: binary source_contact_addr,
    2: binary dest_contact_addr,
    3: i32 source_port = 0,
    4: i32 dest_port = 0,
    /** If this visa is for dock on server side. */
    5: bool server,
    /** list of allowed ICMP types     */
    6: list<i32> icmp_allowed,
}


struct PEPArgsICMP {
    1: binary source_contact_addr,
    2: binary dest_contact_addr,
    /** the allowed ICMP type and code (in lower 16 bits)     */
    3: i32 icmp_type_code,
    /** use 0xFF for none     */
    4: i32 icmp_antecedent,
    /** timeout for state in milliseconds     */
    5: i32 state_timeout_ms,
    /** If we allow only one reply to a request     */
    6: bool one_shot = false,
}


/**
 * Visa is a thrift copy of the protocol buffer visa format used in the
 * prototype and still used in the prototype-derived visa service.
 */
struct Visa {
  1: i32 issuer_id,
  2: i64 configuration,
  /** unix time (milliseconds)   */
  3: i64 expires,
  /** packet source (tether address)   */
  4: binary source,
  /** packet sink (tether address)   */
  5: binary dest,
  /** source contact addr   */
  6: binary source_contact,
  /** dest contact addr   */
  7: binary dest_contact,
  8: PEPIndex dock_pep,
  9: optional PEPArgsTCPUDP tcpudp_pep_args,
  10: optional PEPArgsICMP icmp_pep_args,
  11: KeySet session_key,
  12: Constraints cons,
  13: Signature sig,
}



////////////////////////////////////////////////////////////////////////////////
//
// Types related to the two APIs (visa service and visa support service)
// =====================================================================
//


exception UnauthorizedError {}


enum StatusCode {
  SUCCESS = 0,
  FAIL = 1
}


enum AgentType {
  ADAPTER = 0,
  NODE = 1,
}


/**
 * Basic agent to support early iteration of ZPR.
 * Probably missing things.
 */
struct Agent {
  1: AgentType agent_type,
  2: map<string, string> attrs,
  /** unix time stamp   */
  3: i64 auth_expires,
  /** assigned ZPR address   */
  4: binary zpr_addr,
  5: binary tether_addr,
  /** unique in this ZPRnet   */
  6: string ident,
  7: list<string> provides,
}


// Means visa service sends a nonce buffer, and node is expected to
// create a suitable HMAC.
const i32 CHALLENGE_TYPE_HMAC_SHA256 = 0


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
  /** 'ADDR:PORT'   */
  6: string vss_service,
  7: Agent node_agent,
}


struct ConnectRequest {
  1: i32 connection_id,
  /** dock ZPR address   */
  2: binary dock_addr,
  3: map<string, string> claims,
  /** assume this is old protocol buffer challenge-request   */
  4: binary challenge,
  /** assume this is old protocol buffer challenge-response   */
  5: list<binary> challenge_responses,
}


struct ConnectResponse {
  /** copied from request   */
  1: i32 connection_id,
  /** SUCCESS if connect request granted   */
  2: StatusCode status,
  3: optional Agent agent,
  /** Optional message in case of non SUCCESS  */
  4: optional string reason,
}


struct VisaHop {
  1: Visa visa,
  2: i32 hop_count,
  /** copied out of visa   */
  3: i32 issuer_id,
}


/** Response to the Ping call. */
struct Pong {
  1: i64 configuration,
  2: i64 policy_version,
}


struct VisaResponse {
  1: StatusCode status,
  2: VisaHop visa,
  /** optional message if request has failed.  */
  3: optional string reason,
}


struct VisaRevocation {
  1: i32 issuer_id,
  2: i64 configuration
}


struct PolicyInfo {
  1: i64 policy_id,
  2: i64 config_id,
  3: map<string, string> node_config
  // TODO: links. Prototype includes network topology information. Once we have
  //       more than one node we will need to add that info back in.
}




/**
 *
 *  The visa service API
 *  ====================
 *
 *
 * This is the new visa-service API for the Reference Implementation.
 *
 * The new connection protocol is:
 *
 * 1. Start a node. Node is given a visa from the compiler that will allow
 *    it to communicate the the visa service when it comes online.
 *
 * 2. Start the visa service's adatper.  This adapter will present a
 *    certificate to the node that is (a) signed by the ZPR authority and
 *    (b) has a well known CN that tells the node that it is the visa
 *    service's adapter.
 *
 * 3. The node allows this adapter to connect -- even though the node has
 *    has no policy yet.  The pre-built visa includes the hard-coded visa
 *    service adapter's ZPR address.
 *
 * ~~ Now this visa service API kicks in ~~
 *
 * 4. The node sends a HELLO message to the visa service.
 *
 * 5. The visa service sends a HELLO-RESPONSE which includes a challenge.
 *
 * 6. The node performs the crypto operations to satisfy the challenge and
 *    sends back the AUTHENTICATE message.
 *
 * 6. The visa service checks the nodes crypto, checks policy, and if all
 *    is well will send back an API Key that the node can use when calling
 *    any of the other functions on this API.
 *
 *
 * TODO: There is currently no mechanism described for how to expire or
 * refresh the API key.
 */
service VisaService {

  /** Visa Service response to this with a challenge. */
  HelloResponse hello(),

  /**
   * Node uses this to respond to the `hello` challenge, visa service returns an API key.
   *
   * The HMAC is a SHA256_HMAC(nonce + big_endian(timestamp) + big_endian(session_id)) using the node's private key.
   */
  string authenticate(1:NodeAuthRequest auth_request)

  /**
   * De-register removes a node from the visa service access list -- AND visa service assumes that
   * node is disconnecting -- so this also does an agent_disconnect for the node.
   */
  oneway void de_register(1:string key)



  /**
   * Node calls this everytime an adapter connects.
   * Note that the visa service assumes that the connection completes.
   * If the agent ends up not connecting, or disconnecting the node must
   * let the visa service know.
   */
  ConnectResponse authorize_connect(1:string key, 2:ConnectRequest request)


  /**
   * Notify the visa service that an agent has disconnected. Pass in the ZPR address
   * assigned to the agent via `authorize_connect`.
   */
  void agent_disconnect(1:string key, 2:binary zpr_addr)

  /**
   * For now, fully optional. Use to test connectivity or key or just to check on
   * current policy version and config.  "Pong" message is returned.
   */
  Pong ping(1:string key)

  /**  `traffic` is the initial packet detected for an unknown flow. */
  VisaResponse request_visa(1:string key, 2:binary src_tether_addr, 3: i8 l3_type, 4:binary traffic)
}

/**
 *
 *  The visa support service API
 *  ============================
 *
 * Access to the visa support socket on the node is controlled by ZPR.
 */
service VisaSupport {

  /**
   * Visa service tells node when policy and config IDs change. In the future
   * there may be links that need to be brought up or turn down.  There may
   * also be updated configuration details for the node.
   */
  void NetworkPolicyInstalled(1:PolicyInfo pi)

  /**
   * Visa service pushes visas to the node.  Node need not tell other nodes
   * about these since the visa service is in contact with all nodes.
   */
  void InstallVisas(1:list<VisaHop> vh)

  /**
   * Visa service revokes visas.  Node need not tell other nodes about these as
   * the visa service is in contact with all nodes.
   */
  void RevokeVisas(1:list<VisaRevocation> vr)

  // TODO: Revocation of credentials/agents.  Could be implemented at the
  //       visa service and just end up being a series of visa revocations.
  //       Though how do we tell a node to disconnect an adapter?

}






