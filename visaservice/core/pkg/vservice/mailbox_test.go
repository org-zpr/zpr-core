package vservice_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/vsapi"
	"zpr.org/vs/pkg/vservice"
)

func TestMailboxEmpty(t *testing.T) {
	mb := vservice.NewMailbox(logr.NewTestLogger())
	_, ok := mb.MessagesFor("foo", 100)
	require.False(t, ok)
}

func newPollResponseWithHopCount(hopCount uint32) *vsapi.PollResponse {
	return &vsapi.PollResponse{
		Visas: []*vsapi.VisaHop{
			{
				HopCount: int32(hopCount),
			},
		},
	}
}

func TestMailboxAdd(t *testing.T) {
	mb := vservice.NewMailbox(logr.NewTestLogger())
	mb.AddPoller("foo")
	res, ok := mb.MessagesFor("foo", 100)
	require.True(t, ok)
	require.Empty(t, res)

	mb.AddPoller("fee")

	require.Equal(t, 0, mb.Size())
	for i := 0; i < 200; i++ {
		mb.AppendMessage(newPollResponseWithHopCount(uint32(i + i)))
	}
	require.Equal(t, 200, mb.Size())

}

func TestMailboxAddPoll(t *testing.T) {
	mb := vservice.NewMailbox(logr.NewTestLogger())
	mb.AddPoller("foo")
	mb.AddPoller("fee")

	require.Equal(t, 0, mb.Size())
	for i := 0; i < 200; i++ {
		mb.AppendMessage(newPollResponseWithHopCount(uint32(i + 1)))
	}
	require.Equal(t, 200, mb.Size()) // added 200 messages, highest num is 200

	{ // expect 1...20
		res, ok := mb.MessagesFor("foo", 20)
		require.True(t, ok)
		require.Len(t, res, 20)
		require.Equal(t, int32(1), res[0].GetVisas()[0].HopCount)
		require.Equal(t, int32(20), res[19].GetVisas()[0].HopCount)
	}
	{ // expect 21 ... 40
		res, ok := mb.MessagesFor("foo", 20)
		require.True(t, ok)
		require.Len(t, res, 20)
		require.Equal(t, int32(21), res[0].GetVisas()[0].HopCount)
		require.Equal(t, int32(40), res[19].GetVisas()[0].HopCount)
	}
	{ // expect REST
		res, ok := mb.MessagesFor("foo", 2000)
		require.True(t, ok)
		require.Len(t, res, 160)
		require.Equal(t, int32(41), res[0].GetVisas()[0].HopCount)
		require.Equal(t, int32(200), res[159].GetVisas()[0].HopCount)
	}
	{ // no more left for foo
		res, ok := mb.MessagesFor("foo", 2000)
		require.True(t, ok)
		require.Len(t, res, 0)
	}

	{ // expect 1...100
		res, ok := mb.MessagesFor("fee", 100)
		require.True(t, ok)
		require.Len(t, res, 100)
		require.Equal(t, int32(1), res[0].GetVisas()[0].HopCount)
		require.Equal(t, int32(100), res[99].GetVisas()[0].HopCount)
	}

	mb.AppendMessage(newPollResponseWithHopCount(uint32(1000))) // message 201
	{                                                           // foo sees new message
		res, ok := mb.MessagesFor("foo", 2000)
		require.True(t, ok)
		require.Len(t, res, 1)
		require.EqualValues(t, 1000, res[0].GetVisas()[0].HopCount)
	}
	{ // fee sees new message
		res, ok := mb.MessagesFor("fee", 1000)
		require.True(t, ok)
		require.Len(t, res, 101)
		require.EqualValues(t, 1000, res[100].GetVisas()[0].HopCount)
	}

	mb.AppendMessage(newPollResponseWithHopCount(uint32(2000))) // message 202
	{
		res, ok := mb.MessagesFor("foo", 2000)
		require.True(t, ok)
		require.Len(t, res, 1)
		require.EqualValues(t, 2000, res[0].GetVisas()[0].HopCount)
	}

	// Without compaction there are 202 message in the stack, but only 1 unseen (by fee)
	require.Equal(t, 202, mb.Size())
	mb.Compact()
	require.Equal(t, 1, mb.Size())

	mb.RemovePoller("fee")
	// Now fee is gone, so
	mb.Compact()
	require.Equal(t, 0, mb.Size())

}
