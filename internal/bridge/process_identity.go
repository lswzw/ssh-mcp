package bridge

// ProcessStartTime returns the platform-native start identity for pid. It is
// exported for local lifecycle code that must validate a persisted PID marker
// before inspecting or stopping a process.
func ProcessStartTime(pid int) (uint64, error) {
	return platformProcessStartTime(pid)
}

// processStartTime and processWorkingDirectory are deliberately implemented
// per operating system. The start time is part of OwnerID and prevents a PID
// reuse from inheriting an old bridge capability. A working directory is
// best-effort metadata and may be empty on platforms that do not expose it to
// an unrelated process.
func processStartTime(pid int) (uint64, error) {
	return ProcessStartTime(pid)
}

func processWorkingDirectory(pid int) string {
	return platformProcessWorkingDirectory(pid)
}
