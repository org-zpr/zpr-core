package adb

import (
	"net/netip"

	"zpr.org/vsapi"
)

type PushItem struct {
	Broadcast   bool
	NodeAddr    netip.Addr
	Visas       []*vsapi.VisaHop
	Revocations []*vsapi.VisaRevocation
}

type PushBuffer struct {
	items []*PushItem
}

func NewPushBuffer() *PushBuffer {
	return &PushBuffer{
		items: make([]*PushItem, 0),
	}
}

func (pb *PushBuffer) Drain() []*PushItem {
	items := pb.items
	pb.items = nil
	return items
}

func (pb *PushBuffer) Push(item *PushItem) {
	pb.items = append(pb.items, item)
}

func (pb *PushBuffer) Size() int {
	return len(pb.items)
}
