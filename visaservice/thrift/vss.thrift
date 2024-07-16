// vss.thrift - the visa service support API - node is server, visa service is client.




namespace go vssapi
namespace rs vssapi



// TODO: the node registration operation should tell the visa service
//       what port the VSS is listening on.  Maybe address too?

// TODO: The push and revoke operations mean we can get rid of the polling.
//       Though VS should keep track of failures to push and retry.


struct VisaHop {
  1: binary visa_pb, // visa in "old" protocol buffer form
  2: i32 hop_count,
  3: i32 issuer_id,   // copied out of visa
}

struct VisaRevocation {
  1: i32 issuer_id,
  2: i64 configuration,
}

struct PolicyInfo {
  1: i64 policy_id,
  4: i64 config_id,
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

  // Visa service tells node when policy and config IDs change.
  NetworkPolicy(1:PolicyInfo pi)

  // Visa service pushes visas to the node.
  PushVisas(1:list<VisaHop> vh)

  // Visa service revokes visas.
  RevokeVisa(1:list<VisaRevocation> vr)

  // TODO: Revocation of credentials/agents.  Could be implemented at the
  //       visa service and just end up being a series of visa revocations.
  //       Though how do we tell a node to disconnect an adapter?
}


