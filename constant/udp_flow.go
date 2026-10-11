package constant

// UDPFlowOwner is an optional incoming-packet ownership boundary. The retained
// flow outlives individual packet buffers and keeps its original run/network
// context. Close admission before retirement; complete only after its sender,
// read worker and physical Close have returned. An uncertain Close is reported
// to the owner rather than treated as reclaimed capacity. Legacy packets need
// not implement this interface. A denied admission owns no flow and returns nil
// callbacks; it must not start a replacement NAT socket for a closing source.
type UDPFlowOwner interface {
	RetainUDPFlow() (closeAdmission func(), complete func(error), admitted bool)
}

func (p *packetAdapter) RetainUDPFlow() (func(), func(error), bool) {
	if owner, ok := p.UDPPacket.(UDPFlowOwner); ok {
		return owner.RetainUDPFlow()
	}
	return nil, nil, true
}
