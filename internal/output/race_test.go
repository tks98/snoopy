//go:build race

package output

// The race detector makes the code it checks several times slower, more so
// on a busy machine: TestHARInterim took 4 s under it with the CPUs loaded,
// against 0.07 s without. Timing limits allow for that, and still catch the
// quadratic behavior they're there for, which is slower by far more.
func init() { timingSlack = 5 }
