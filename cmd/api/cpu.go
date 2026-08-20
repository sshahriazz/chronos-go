package main

import (
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// resolveCPULimit reports how many CPUs this process may actually use.
//
// # Why this exists at all
//
// `runtime.GOMAXPROCS(0)` is not the container's CPU limit. Under a CFS quota
// the Go runtime still reports the HOST's core count — a 0.5-CPU pod on a
// 64-core node reports 64 — and nothing in the runtime notices. That is normally
// a throughput curiosity. Here it is a memory bound: the Argon2id hasher's
// concurrency limit defaults to GOMAXPROCS, every concurrent hash holds its full
// 32 MiB working set for its whole duration, and the limit is reachable by
// unauthenticated traffic. Sized from the host's core count, a pod with a
// 2-CPU quota on a 64-core node would permit 64 simultaneous hashes: 2 GiB of
// resident memory to do the work of two, on a container that will be OOM-killed
// long before it gets there.
//
// # Why the cgroup rather than automaxprocs
//
// Three options were on the table and this one is the narrowest.
//
//   - `go.uber.org/automaxprocs` is the popular answer and it does more than is
//     wanted: it changes GOMAXPROCS for the WHOLE runtime, which changes GC
//     assist behaviour, scheduler parallelism and every other sizing decision in
//     the process. That may well be right, but it is a separate decision from
//     "how much memory may password hashing hold", and taking it as a side
//     effect of fixing the hasher is how one change acquires a blast radius
//     nobody reviewed. It is also a new dependency for ~60 lines of parsing.
//   - Configuration alone (IDENTITY_PASSWORD_HASH_CONCURRENCY) does not fix the
//     DEFAULT, and the default is what every deployment runs until an incident.
//   - Reading the quota fixes the default, changes nothing else about the
//     runtime, and leaves the explicit override in place for a measurement that
//     disagrees. That is what is implemented here.
//
// # What it reads
//
// cgroup v2 first — `/sys/fs/cgroup/cpu.max`, holding "<quota> <period>" or
// "max <period>" for unlimited — then cgroup v1's
// `cpu.cfs_quota_us` / `cpu.cfs_period_us`, where a quota of -1 is unlimited.
// The quotient is rounded UP: a 1.5-CPU quota is 2, because rounding down to 1
// would halve throughput on the strength of an accounting detail, while the
// memory it costs is one extra hash.
//
// Everything degrades to GOMAXPROCS: no cgroup filesystem (macOS, a bare VM), an
// unreadable file, an unparseable value, or "max". The result is never above
// GOMAXPROCS — a quota of 8 CPUs on a runtime pinned to 2 is still 2 real
// parallel hashes — and never below 1.
func resolveCPULimit(log *slog.Logger) int {
	procs := max(runtime.GOMAXPROCS(0), 1)

	quota, source, ok := cgroupCPUQuota()
	if !ok {
		// Not an error and not a warning: this is the normal case on a developer
		// machine and on any host without a quota. Logged at DEBUG so the
		// question "what did it decide, and from what" is answerable without
		// adding a line to every boot.
		log.Debug("no cgroup CPU quota found; sizing from GOMAXPROCS",
			"gomaxprocs", procs)
		return procs
	}

	if quota < procs {
		log.Info("cgroup CPU quota is below GOMAXPROCS; CPU-bound limits are sized from the quota",
			"quota", quota, "gomaxprocs", procs, "source", source)
		return quota
	}
	return procs
}

// cgroupCPUQuota returns the effective CPU count from the cgroup, the file it
// came from, and whether one was found at all.
func cgroupCPUQuota() (cpus int, source string, ok bool) {
	// cgroup v2: "<quota> <period>", or "max <period>" when unlimited.
	if raw, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) == 2 && fields[0] != "max" {
			quota, qErr := strconv.ParseInt(fields[0], 10, 64)
			period, pErr := strconv.ParseInt(fields[1], 10, 64)
			if n, valid := cpusFrom(quota, period, qErr == nil && pErr == nil); valid {
				return n, "/sys/fs/cgroup/cpu.max", true
			}
		}
		// A v2 file that says "max" is a definitive answer — unlimited — so do
		// not fall through to v1 paths that will not exist on a v2 host anyway.
		return 0, "", false
	}

	// cgroup v1: two files, and -1 means unlimited.
	quotaRaw, qErr := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	periodRaw, pErr := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if qErr != nil || pErr != nil {
		return 0, "", false
	}
	quota, qParse := strconv.ParseInt(strings.TrimSpace(string(quotaRaw)), 10, 64)
	period, pParse := strconv.ParseInt(strings.TrimSpace(string(periodRaw)), 10, 64)
	if n, valid := cpusFrom(quota, period, qParse == nil && pParse == nil); valid {
		return n, "/sys/fs/cgroup/cpu/cpu.cfs_quota_us", true
	}
	return 0, "", false
}

// cpusFrom rounds a quota/period pair UP to whole CPUs.
//
// Separated from the file handling so the arithmetic — which is the part with a
// wrong answer that looks plausible — is testable without a filesystem.
func cpusFrom(quota, period int64, parsed bool) (int, bool) {
	if !parsed || quota <= 0 || period <= 0 {
		return 0, false
	}
	cpus := max((quota+period-1)/period, 1)
	return int(cpus), true
}
