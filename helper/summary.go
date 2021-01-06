package helper

// status summary
type Summary struct {
	Host    string
	Success bool
	Message string
}

// summarize status and message
func (s Summary) Status() string {
	var status = "OK"
	if s.Success == false {
		status = "FAILED"
	}

	if len(s.Message) > 0 {
		status += " - " + s.Message
	}

	return status
}
