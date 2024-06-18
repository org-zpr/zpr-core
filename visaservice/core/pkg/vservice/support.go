package vservice

type RConstraint struct {
	Origin        []byte
	Key           string
	CapBytes      uint64
	PeriodSeconds uint64
	PeriodStarts  uint64
	Consumed      uint64
}

// In the prototype we used RAFT on the nodes to keep track of the constraints.
//
// TODO: This needs to move to visa service.
type ConstraintService interface {
	ProposeConstraint(*RConstraint)
	ConstraintByKey(string) *RConstraint
}

func (c *RConstraint) GetCapBytes() uint64 {
	return c.CapBytes
}

func (c *RConstraint) GetPeriodStarts() uint64 {
	return c.PeriodStarts
}

// The visa service support interface will eventually also have functions to work with the
// constraint database.  For now this is just a dummy version.

type DummyConstraintService struct {
	db map[string]*RConstraint
}

func NewDummyConstraintService() *DummyConstraintService {
	return &DummyConstraintService{
		db: make(map[string]*RConstraint),
	}
}

func (dcs *DummyConstraintService) ProposeConstraint(c *RConstraint) {
	dcs.db[c.Key] = c
}

func (dcs *DummyConstraintService) ConstraintByKey(key string) *RConstraint {
	return dcs.db[key]
}
