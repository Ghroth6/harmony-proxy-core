package statistic

// SubscribeConnections observes completed tracker creation after registration
// in this manager, including short-lived and internal (pushToManager=false)
// connections. It does not report failed dials or individual HTTP requests.
// Tracker identity and its initial metadata are available during the callback;
// consumers retaining history should copy the needed fields rather than depend
// on a later active-connection snapshot.
//
// Callbacks run synchronously on the creating goroutine, may run concurrently,
// and must return promptly. Cancellation is idempotent and does not wait for
// callbacks already selected by another goroutine. Callbacks may unsubscribe
// themselves, query the manager, or close the tracker.
func (m *Manager) SubscribeConnections(fn func(Tracker)) (cancel func()) {
	return m.created.Subscribe(fn)
}
