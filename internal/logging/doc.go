// Package logging routes the log records of certfolds and certfoldc: every record
// at Info and above goes to the service log, and a copy goes to a ring of
// recent events that the IPC API serves. Values marked Private, such as the
// output of on_change and exec DNS programs, are withheld from the events
// and from the Windows event log; only a service log with restricted
// readers, such as journald, holds them. So are the queries of URLs, where
// some DNS provider APIs take credentials.
package logging
