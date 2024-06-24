package vservice

import (
	"sync"
	"time"

	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/vsapi"
)

// Mailbox is a system designed to support polling of the visa service for
// revocations and unsolicitied visas.
type Mailbox struct {
	log        logr.Logger
	mtx        sync.RWMutex
	nextMsgNum uint64
	msgs       []*VisaPushMsg // Ordered oldest to newest
	pollers    map[string]*Poller
}

type VisaPushMsg struct {
	MsgNumber uint64 // always increasing
	Msg       *vsapi.PollResponse
}

type Poller struct {
	ID              string
	LastMessageSeen uint64
	LastPoll        time.Time
}

func NewMailbox(log logr.Logger) *Mailbox {
	return &Mailbox{
		log:        log,
		nextMsgNum: 1,
		pollers:    make(map[string]*Poller),
	}
}

func (m *Mailbox) AddPoller(ID string) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.pollers[ID] = &Poller{
		ID:              ID,
		LastMessageSeen: m.nextMsgNum - 1,
	}
}

func (m *Mailbox) HasPoller(ID string) bool {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	_, found := m.pollers[ID]
	return found
}

func (m *Mailbox) RemovePoller(ID string) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	delete(m.pollers, ID)
	m.compactMboxes()
}

// MessagesFor will return (nil, false) if the mboxID is unknown.
func (m *Mailbox) MessagesFor(mboxID string, limit int) ([]*vsapi.PollResponse, bool) {
	var results []*vsapi.PollResponse
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	poller, found := m.pollers[mboxID]
	if !found {
		return nil, false
	}
	poller.LastPoll = time.Now()
	mcount := len(m.msgs)
	if mcount > 0 {
		// Quick check, is this poller already up to date?
		if poller.LastMessageSeen >= m.msgs[mcount-1].MsgNumber {
			return results, true
		}
		// proceeed until we get to last message seen by this poller
		mstartx := 0
		for i := 0; i < mcount; i++ {
			mstartx = i
			if m.msgs[i].MsgNumber > poller.LastMessageSeen {
				break
			}
		}
		if mstartx < mcount {
			sz := 0
			var n uint64
			for i := mstartx; i < mcount && sz < limit; i++ {
				n = m.msgs[i].MsgNumber
				msg := m.msgs[i]
				results = append(results, msg.Msg)
				sz++
			}
			poller.LastMessageSeen = n
		}
	}
	return results, true
}

func (m *Mailbox) AppendVisaResponseMessage(r *vsapi.VisaResponse) {
	if r.Status != vsapi.StatusCode_SUCCESS {
		m.log.Error("attempt to append an error visa-response message to mailbox")
		return
	}
	vpr := &vsapi.PollResponse{
		Visas: []*vsapi.VisaHop{r.Visa},
	}
	m.AppendMessage(vpr)
}

func (m *Mailbox) AppendMessage(r *vsapi.PollResponse) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if len(m.pollers) == 0 {
		return // Nobody in the forest? Tree didn't fall!
	}
	m.msgs = append(m.msgs, &VisaPushMsg{
		MsgNumber: m.nextMsgNum,
		Msg:       r,
	})
	m.nextMsgNum++
	if m.nextMsgNum%50 == 0 {
		m.compactMboxes() // TODO: Maybe better to allow caller to decide when to do this.
	}
}

func (m *Mailbox) Size() int {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	return len(m.msgs)
}

// compactMboxes requires write lock
func (m *Mailbox) compactMboxes() {
	sz := len(m.msgs)
	if sz == 0 {
		return
	}
	// If there are messages all pollers have seen, remove them from the message buffer.
	//
	// Each poller keeps track of the last message seen. Locate the smallest last message
	// seen as that (+1) will be the first message we need to keep.

	maxi := m.msgs[sz-1].MsgNumber + 1
	lastseen := maxi

	for _, p := range m.pollers {
		if p.LastMessageSeen < lastseen {
			lastseen = p.LastMessageSeen
		}
	}

	if lastseen == maxi {
		// all pollers are up to date, zero out cache
		m.msgs = nil
		return
	}
	if lastseen == 0 {
		// at least one poller hasn't seen anything, no changes.
		return
	}

	keepIdx := -1
	for i, msg := range m.msgs {
		if msg.MsgNumber > lastseen {
			keepIdx = i // `i` is index of first message we need to keep
			break
		}
	}

	if keepIdx >= 0 {
		newLen := sz - keepIdx
		// Now remove 0...(keepIdx - 1) from the slice
		newslice := make([]*VisaPushMsg, newLen)
		copy(newslice, m.msgs[keepIdx:])
		m.msgs = newslice
	} else {
		// no message has a number larger than lastseen, so all can be purged.
		m.msgs = nil
	}
}

func (m *Mailbox) Compact() {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.compactMboxes()
}
