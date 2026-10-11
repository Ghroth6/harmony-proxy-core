package constant

// UDPFlowOwner is an optional incoming-packet ownership boundary. The retained
// flow outlives individual packet buffers and keeps its original run/network
// context. Close admission before retirement; complete only after its sender,
// read worker and physical Close have returned. An uncertain Close is reported
// to the owner rather than treated as reclaimed capacity. Legacy packets need
// not implement this interface.
type UDPFlowOwner interface {
	RetainUDPFlow() (closeAdmission func(), complete func(error))
}

func (p *packetAdapter) RetainUDPFlow() (func(), func(error)) {
	if owner, ok := p.UDPPacket.(UDPFlowOwner); ok {
		return owner.RetainUDPFlow()
	}
	return nil, nil
}
