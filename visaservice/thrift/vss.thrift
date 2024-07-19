// vss.thrift - the visa service support API - node is server, visa service is client.




namespace go vssapi
namespace rs vssapi



// TODO: the node registration operation should tell the visa service
//       what port the VSS is listening on.  Maybe address too?

// TODO: The push and revoke operations mean we can get rid of the polling.
//       Though VS should keep track of failures to push and retry.


struct VisaHop {
  1: required binary visa_pb, // visa in "old" protocol buffer form
  2: required i32 hop_count,
  3: required i32 issuer_id   // copied out of visa
}

struct VisaRevocation {
  1: required i32 issuer_id,
  2: required i64 configuration
}

struct PolicyInfo {
  1: required i64 policy_id,
  2: required i64 config_id,
  3: map<string, string> node_config
  // TODO: links
}


// Access to the visa support socket on the node is controlled by ZPR.
// TODO: What if someone is on node host and connects via localhost?
//
//       Need to figure out how to secure this (and other thrift stuff too).
//       For this API specifically, a visa service should not call this
//       until the node has registered with the visa service first.
//       So the node knows the address of the visa service and we could
//       check that (TODO: how to get client addr in thrift server?).
//       Or we could generate an API key and pass it to the visa service
//       during registration.  Or, and maybe best, the node can get the
//       visa service cert during registration and we can enable TLS on
//       this service and check the visa service key.
//
service VisaSupport {

  // Visa service tells node when policy and config IDs change. In the future
  // there may be links that need to be brought up or turn down.  There may
  // also be updated configuration details for the node.
  void NetworkPolicyInstalled(1:PolicyInfo pi)

  // Visa service pushes visas to the node.  Node need not tell other nodes
  // about these since the visa service is in contact with all nodes.
  void InstallVisas(1:list<VisaHop> vh)

  // Visa service revokes visas.  Node need not tell other nodes about these as 
  // the visa service is in contact with all nodes.
  void RevokeVisas(1:list<VisaRevocation> vr)

  // TODO: Revocation of credentials/agents.  Could be implemented at the
  //       visa service and just end up being a series of visa revocations.
  //       Though how do we tell a node to disconnect an adapter?

}


