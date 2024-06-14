package compiler

import (
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"zpr.org/vsx/polio"
	"zpr.org/vsx/zpl/defs"
	"zpr.org/vsx/zpl/doc"
)

// SetLinks sets the policy link structure. Capitalized only so that I can unit test it. Not intended to be used outside of Compiler.
// Also does various sanity checks on the nodes.
func (c *Compilation) SetLinks(d *doc.Doc) error {
	topo := d.Zpr.Topology

	// Setup indexes:
	var nodeServices []*doc.Component
	for nn, ncomp := range d.Zpr.Nodes {
		c.nodeKeys = append(c.nodeKeys, nn)
		nodeServices = append(nodeServices, ncomp)
	}
	sort.Slice(c.nodeKeys, func(i, j int) bool {
		return strings.Compare(c.nodeKeys[i], c.nodeKeys[j]) < 0
	})
	for ln := range topo.LANs {
		c.lanKeys = append(c.lanKeys, ln)
	}
	sort.Slice(c.lanKeys, func(i, j int) bool {
		return strings.Compare(c.lanKeys[i], c.lanKeys[j]) < 0
	})

	if err := c.checkNodeAddresses(d.Zpr); err != nil {
		return err
	}
	if err := c.checkNodesOnLANs(d.Zpr); err != nil {
		return err
	}

	// All nodes in a LAN are linked to each other.
	if len(nodeServices) > 0 {

		bridges := make(map[string]string) // nodeA -> nodeB (is bi-directional)

		for _, br := range topo.Bridges {
			// Valid bridge: nodes must be in distinct lans -- assumes bridge is two nodes only.
			nodeA, nodeB := checkBridge(br, topo)
			if nodeA == "" || nodeB == "" {
				return fmt.Errorf("invalid bridge %v", br.Nodes)
			}
			if bridges[nodeA] == nodeB || bridges[nodeB] == nodeA {
				continue // already have it
			}
			lnk, err := c.linkNodes(nodeA, []string{nodeB}, d, nodeServices)
			if err != nil {
				return fmt.Errorf("failed to create bridge: %v", err)
			}
			if cost, err := br.Cost.AsUint64(); err == nil {
				lnk.Terms[0].Cost = uint32(cost)
			} else {
				lnk.Terms[0].Cost = doc.DefaultBridgeCost
			}
			bridges[nodeA] = nodeB
			c.infof("[bridge] <%v> -> <%v>, cost %d",
				strings.Join(c.LANsContaining(nodeA, topo), ", "), strings.Join(c.LANsContaining(nodeB, topo), ", "),
				lnk.Terms[0].Cost)
			c.policy.Links = append(c.policy.Links, lnk)
		}

		for _, lanName := range c.lanKeys {
			ln := topo.LANs[lanName]
			if len(ln.Nodes) > 1 {
				for i, srcN := range ln.Nodes {
					// Configure a link structure for the i'th node with all the others in the LAN.
					var remain []string
					for j, nn := range ln.Nodes {
						if i == j {
							continue
						}
						remain = append(remain, nn.String())
					}
					lnk, err := c.linkNodes(srcN.String(), remain, d, nodeServices)
					if err != nil {
						return err
					}
					c.infof("[link] %v (LAN %v)", srcN, lanName)
					for _, t := range lnk.Terms {
						c.infof("       to %v  @ %v:%d", net.IP(t.ZprId), t.Host, t.Port)
					}
					c.policy.Links = append(c.policy.Links, lnk)
				}
			}
		}
	}
	return nil
}

// checkNodeAddresses ensures that each node has a unique ZPR address and unique POE value.
func (c *Compilation) checkNodeAddresses(dzpr *doc.ZPR) error {
	addrsInUse := make(map[string]string)
	for _, nn := range c.nodeKeys {
		node := dzpr.Nodes[nn]
		naddr, err := c.resolve(node.Address.String())
		if err != nil {
			return doc.ZplScalarErrorf(node.Address, "node %v with invalid address: %v: %w", nn, node.Address, err)
		}
		addr := net.ParseIP(naddr)
		if addr == nil || addr.IsUnspecified() {
			return doc.ZplScalarErrorf(node.Address, "node %v failed address resolution: %v: %v", nn, naddr, err)
		}
		if existing, matched := addrsInUse[addr.String()]; matched {
			return doc.ZplScalarErrorf(node.Address, "node %v address already in use by %v", nn, existing)
		} else {
			addrsInUse[addr.String()] = nn
		}
		for _, ifdef := range node.Interfaces {
			if existing, matched := addrsInUse[ifdef.Netaddr.String()]; matched {
				return doc.ZplScalarErrorf(ifdef.Netaddr, "node %v POE address already in use by %v", nn, existing)
			} else {
				addrsInUse[ifdef.Netaddr.String()] = nn
			}
		}
	}
	return nil
}

// checkNodesOnLANs return error if a node is found to not be on any LAN
func (c *Compilation) checkNodesOnLANs(dzpr *doc.ZPR) error {
	for _, nn := range c.nodeKeys {
		found := false
	SEARCHLOOP:
		for _, lan := range dzpr.Topology.LANs {
			for _, ln := range lan.Nodes {
				nodeID, _ := splitNodeAndInterfaceID(ln.String())
				if nodeID == nn {
					found = true
					break SEARCHLOOP
				}
			}
		}
		if !found {
			return fmt.Errorf("node %v not on any LAN", nn)
		}
	}
	return nil
}

// splitNodeAndInterfaceID in ZPL topology rules a node is referenced by its
// name plus its interface.  Interface is optional when there is just one interface
// on the node.
func splitNodeAndInterfaceID(nodeAndIF string) (nodeID string, ifID string) {
	bits := strings.Split(nodeAndIF, ".")
	if len(bits) == 2 {
		nodeID, ifID = bits[0], bits[1]
	} else {
		nodeID = nodeAndIF
	}
	return
}

// LANsContaining return names of all LANs that contain the given node.
func (c *Compilation) LANsContaining(nodeName string, topo *doc.Topology) []string {
	var lans []string
	for _, name := range c.lanKeys {
		lan := topo.LANs[name]
		for _, nn := range lan.Nodes {
			if nn.String() == nodeName {
				lans = append(lans, name)
				break
			}
		}
	}
	return lans
}

// checkBridge returns the distinct nodes in the bridge pair, ensuring that the nodes are in distinct LANs.
// If either return values are empty string then the check failed.
func checkBridge(br *doc.Bridge, topo *doc.Topology) (nodeA string, nodeB string) {

	var nodeALan, nodeBLan string

	for _, brNode := range br.Nodes {
		found := false
		for lanName, ldesc := range topo.LANs {
			for _, nn := range ldesc.Nodes {
				if nn.String() == brNode.String() {
					// Found bridge node in this LAN
					found = true
					break
				}
			}
			if found {
				if nodeALan == "" {
					nodeALan = lanName
					nodeA = brNode.String()
				} else if nodeBLan == "" {
					nodeBLan = lanName
					nodeB = brNode.String()
				}
				break
			}
		}
	}

	if nodeALan == nodeBLan {
		nodeA, nodeB = "", "" // error condition (same LAN)
	}
	if nodeALan == "" || nodeBLan == "" {
		nodeA, nodeB = "", "" // error condition (one or more LANs not found)
	}

	return
}

// linkNodes
//
// Note names (`srcN` and all the strings in `terms`) are of the form
// <NODE_ID>.<INTERFACE_ID> and interface can be omitted if the node only
// has one.
func (c *Compilation) linkNodes(srcNodeIf string, terms []string, elDoc *doc.Doc, nodeComponents []*doc.Component) (*polio.Link, error) {
	srcNID, _ := splitNodeAndInterfaceID(srcNodeIf)
	sourceNode := elDoc.Zpr.Nodes[srcNID]
	sourceAddrStr, err := c.resolve(sourceNode.Address.String())
	if err != nil {
		return nil, doc.ZplScalarErrorf(sourceNode.Address, "node address error: %v: %w", srcNID, err)
	}
	sourceAddr := net.ParseIP(sourceAddrStr)
	if sourceAddr == nil {
		return nil, doc.ZplScalarErrorf(sourceNode.Address, "node address error: %v: %v", srcNID, sourceAddrStr)
	}
	plink := &polio.Link{
		SourceId: sourceAddr, // is-a ZPR address
	}
	for _, dstNodeIf := range terms {
		dstNID, dstNIfID := splitNodeAndInterfaceID(dstNodeIf)
		destNode, found := elDoc.Zpr.Nodes[dstNID]
		if !found {
			return nil, fmt.Errorf("topology node reference unknown: '%v'", dstNID)
		}
		addr, err := c.resolve(destNode.Address.String())
		if err != nil {
			return nil, doc.ZplScalarErrorf(destNode.Address, "node address error: %v: %v", dstNID, err)
		}
		remAddr := net.ParseIP(addr)
		if remAddr == nil {
			return nil, doc.ZplScalarErrorf(destNode.Address, "node address error: %v: %v", dstNID, addr)
		}
		host, port, err := func() (string, int, error) {
			var dstPOE *doc.Interface
			if len(destNode.Interfaces) > 1 {
				if dstNIfID == "" {
					return "", 0, doc.ZplScalarErrorf(elDoc.Zpr.Topology.ZplRef, "LAN linkage for %v requires an interface name", destNode.ID.String())
				}
				if idef, ok := destNode.Interfaces[dstNIfID]; !ok {
					return "", 0, doc.ZplScalarErrorf(elDoc.Zpr.Topology.ZplRef, "unknown interface name '%v' on node '%v'", dstNIfID, destNode.ID.String())
				} else {
					dstPOE = idef
				}
			} else {
				for _, v := range destNode.Interfaces {
					dstPOE = v
					break
				}
			}

			// In old version, the POE was also the forwarder address.  Until we extend
			// ZPL to support specifying the forwarder port, the default is to run the forwarder
			// at poe_PORT + 1.  (event if the node does not have a dock).
			h, p, err := net.SplitHostPort(dstPOE.Netaddr.String())
			if err != nil {
				return "", 0, doc.ZplScalarErrorf(dstPOE.Netaddr, "%w", err)
			}
			pn, err := strconv.Atoi(p)
			if err != nil {
				return "", 0, doc.ZplScalarErrorf(dstPOE.Netaddr, "illegal node POE port: %v: %w", dstPOE.Netaddr, err)
			}
			pn += 1
			return h, pn, nil
		}()
		if err != nil {
			return nil, err
		}
		destNoisePK, err := hex.DecodeString(destNode.Key.String())
		// The PK value has been checked already in the compilation chain.
		if err != nil {
			panic(err)
		}
		term := &polio.NodeAddr{
			ZprId:   remAddr,      // ZPR address
			Host:    host,         // POE address
			Port:    uint32(port), // POE port
			ExtAuth: c.needsExternalAuth(elDoc, destNode),
			Key:     destNoisePK,
		}
		plink.Terms = append(plink.Terms, term)
	}
	return plink, nil
}

func (c *Compilation) needsExternalAuth(d *doc.Doc, svc *doc.Component) bool {
	for _, attrExpr := range svc.Provider {
		key := strings.ToLower(attrExpr.Key.String())
		if key == defs.KAttrAuthority {
			prv, ok := c.authProviders[attrExpr.Value.String()]
			if !ok {
				panic(doc.ZplScalarErrorf(svc.ZplRef, "no auth provider with prefix (zpr.authority of) %v", attrExpr.Value))
			}
			// preprocessor ensures attr expr op is "eq" or "has" in this case
			if prv.External {
				return true
			}
		} else {
			pfx := strings.Split(key, ".")[0]
			if pfx == "zpr" {
				continue
			}
			prv, ok := c.authProviders[pfx]
			if !ok {
				panic(doc.ZplScalarErrorf(svc.ZplRef, "no auth provider with prefix %v", pfx))
			}
			if prv.External {
				return true
			}
		}
	}
	return false
}
