
/// Caps total simultaneous in-flight operations across every caller,
/// regardless of what kind of work each one does — the enrichment
/// coordinator shares ONE instance across all five probe types so the total
/// outbound traffic never exceeds `maxConcurrent`, no matter how many IPs
/// or probe kinds are running at once.
public actor ProbeConcurrencyLimiter {
    private let maxConcurrent: Int
    private var current = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []

    public init(maxConcurrent: Int) {
        self.maxConcurrent = maxConcurrent
    }

    // Hand-off semantics: releasing directly to a waiter never touches
    // `current` at all — the slot count doesn't change, it just changes
    // hands atomically within the same actor-isolated call. Without this, a
    // waiter's own `current += 1` only executes once it actually re-enters
    // the actor after being resumed; in the window between the resume call
    // and that re-entry, another `acquire()` already queued on the actor
    // could see `current < maxConcurrent` and take a slot too, letting the
    // cap transiently exceed `maxConcurrent`.
    public func acquire() async {
        if current < maxConcurrent {
            current += 1
            return
        }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            waiters.append(continuation)
        }
        // No increment here anymore - release() already accounted for this
        // slot via hand-off.
    }

    public func release() {
        precondition(current > 0, "release() called without a matching acquire()")
        if !waiters.isEmpty {
            let next = waiters.removeFirst()
            next.resume()
            // current is unchanged - the slot passes directly to the
            // resumed waiter.
        } else {
            current -= 1
        }
    }
}
