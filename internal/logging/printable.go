package logging

import (
	"strings"
	"unicode"
)

// Printable returns s fit to print to a terminal: every control character
// but "\n", which errors.Join puts between errors, becomes a space, and
// invalid UTF-8 becomes U+FFFD. The errors sigils and sigilc print can quote
// the network, such as the names in the certificate of a man in the middle.
// Printed as they are, the escape sequences in them could retitle the
// terminal, rewrite what it shows or set its clipboard. unicode.IsControl
// covers C0, DEL and C1, whose U+009B some terminals take for CSI, as 8-bit
// terminals take a bare 0x9B byte. A newline that the network put into the
// text would start a line of its choosing, so text from the network goes
// through OneLine first, and Printable keeps only the newlines between it.
func Printable(s string) string {
	// strings.Map also turns invalid UTF-8 into U+FFFD.
	return strings.Map(func(r rune) rune {
		if r != '\n' && unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

// OneLine is Printable with "\n" replaced by a space as well, for text that
// must stay on one line of a terminal.
func OneLine(s string) string {
	return strings.ReplaceAll(Printable(s), "\n", " ")
}
