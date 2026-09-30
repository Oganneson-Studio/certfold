package config

// ReadClientField reads the value of key in the client section of the
// client.yaml at path, as ReadServerField does in server.yaml: sigilc enroll
// compares name and server_url with its token, and CLI commands locate the
// daemon with ipc_socket. It expands ${VAR} only in this value and does not
// validate the file, so the variables other values reference, such as a
// PKCS#12 password that only the service's environment sets, need not be set
// in the caller's environment, which sudo does not pass on. The value is
// expanded exactly as LoadClient expands it, and a relative data_dir or
// ipc_socket is refused as LoadClient refuses it. An empty value means the
// key is not set.
func ReadClientField(path, key string) (string, error) {
	return readField(path, "client", key)
}
