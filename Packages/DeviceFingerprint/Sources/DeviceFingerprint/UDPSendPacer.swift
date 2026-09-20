/// Enforces a minimum spacing between successive `waitTurn()` returns so a
/// burst of near-instant UDP probe sends (one probe per subnet host) spreads
/// out over time instead of firing all at once — the shape that reads as a
/// flood/scan signature to a network IDS.
///
/// Design note: this loops and re-checks against the CURRENT `nextSlot` after
/// every sleep, rather than pre-computing a fixed grid up front. A fixed-grid
/// approach (tried and found insufficient) assumes bounded, order-preserving
/// overshoot from Task.sleep; under real concurrent contention (many callers
/// racing the same shared pacer, competing for Swift's cooperative thread
/// pool), an individual call's overshoot can be large and unpredictable, and
/// actual-completion order can differ from intended schedule order. Re-checking
/// against live state every time removes the dependency on that assumption:
/// every claim of a slot happens atomically (actor-serialized, synchronous,
/// no await in between) against the REAL current time, never a stale plan.
///
/// A cancelled caller's `waitTurn()` returns immediately, without claiming a
/// slot. Returning does NOT mean "your turn is guaranteed safe to use" —
/// callers must check `Task.isCancelled` before actually sending, since a
/// cancelled call can return early for that reason alone.
public actor UDPSendPacer {
    private let minimumSpacing: Duration
    private var nextSlot: ContinuousClock.Instant?
    private let clock = ContinuousClock()

    public init(minimumSpacing: Duration) {
        self.minimumSpacing = minimumSpacing
    }

    public func waitTurn() async {
        while true {
            let now = clock.now
            let floor = nextSlot ?? now
            if floor <= now {
                nextSlot = now + minimumSpacing
                return
            }
            do {
                try await Task.sleep(until: floor, tolerance: .zero, clock: clock)
            } catch {
                // Cancelled: return immediately rather than looping — swallowing
                // the error with `try?` here would busy-spin, since a cancelled
                // Task.sleep throws instantly without sleeping and `floor <= now`
                // would still be false on the very next iteration.
                return
            }
            // Loop back and re-check against the LATEST nextSlot — it may have
            // been pushed later by another caller's claim while we were asleep.
        }
    }
}
