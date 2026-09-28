// Package logging routes the log records of sigils and sigilc: every record
// at Info and above goes to the service log, and a copy goes to a ring of
// recent events that the IPC API serves. Values marked Private, such as the
// output of on_change and exec DNS programs, reach only the service log.
package logging
