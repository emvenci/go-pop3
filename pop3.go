// Package pop3 provides an implementation of the Post Office Protocol, Version
// 3 as defined in RFC 1939. Commands specified as optional are not
// implemented; however, this implementation may be trivially extended to
// support them.

package pop3

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
)

// The POP3 client.
type Client struct {
	conn net.Conn
	bin  *bufio.Reader
}

// Dial creates an unsecured connection to the POP3 server at the given address
// and returns the corresponding Client.
func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return NewClient(conn)
}

// DialTLS creates a TLS-secured connection to the POP3 server at the given
// address and returns the corresponding Client.
func DialTLS(addr string) (*Client, error) {
	conn, err := tls.Dial("tcp", addr, nil)
	if err != nil {
		return nil, err
	}
	return NewClient(conn)
}

// NewClient returns a new Client object using an existing connection.
func NewClient(conn net.Conn) (*Client, error) {
	client := &Client{
		bin:  bufio.NewReader(conn),
		conn: conn,
	}
	// send dud command, to read a line
	_, err := client.Cmd("")
	if err != nil {
		return nil, err
	}
	return client, nil
}

// Convenience function to synchronously run an arbitrary command and wait for
// output. The terminating CRLF must be included in the format string.
//
// Output sent after the first line must be retrieved via readLines.
func (c *Client) Cmd(format string, args ...interface{}) (string, error) {
	if format != "" {
		format += "\r\n"
	}
	fmt.Fprintf(c.conn, format, args...)
	line, _, err := c.bin.ReadLine()
	if err != nil {
		return "", err
	}
	l := string(line)
	last := l
	if split := strings.SplitN(l, " ", 2); len(split) == 2 {
		last = split[1]
	}
	if l[0] != '+' {
		return "", errors.New(last)
	}
	return last, nil
}

func (c *Client) ReadLines() (lines []string, err error) {
	lines = make([]string, 0)
	l, _, err := c.bin.ReadLine()
	line := string(l)
	for err == nil && line != "." {
		if len(line) > 0 && line[0] == '.' {
			line = line[1:]
		}
		lines = append(lines, line)
		l, _, err = c.bin.ReadLine()
		line = string(l)
	}
	return
}

func (c *Client) Caps() (caps []string, err error) {
	_, err = c.Cmd("CAPA")
	return c.ReadLines()
}

// Auth sends the given username and password to the server, calling the User
// and Pass methods as appropriate.
func (c *Client) Auth(username, password string) error {
	caps, err := c.Caps()
	var sasl []string
	plain := false
	for _, c := range caps {
		if strings.HasPrefix(c, "SASL") {
			sasl = strings.Split(c, " ")
			sasl = sasl[1:]
		} else if c == "PLAIN" {
			plain = true
		}
	}
	if sasl != nil {
		for _, v := range sasl {
			if v == "CRAM-MD5" {
				line, err := c.Cmd("AUTH CRAM-MD5")
				if err != nil {
					return err
				}
				chal, err := base64.StdEncoding.DecodeString(line)
				if err != nil {
					return err
				}
				cram := smtp.CRAMMD5Auth(username, password)
				auth, err := cram.Next(chal, true)
				if err != nil {
					return err
				}
				response := base64.StdEncoding.EncodeToString(auth)
				_, err = c.Cmd(response)
				return err
			}
		}
	}
	if plain {
		_, err = c.Cmd("AUTH %s %s", username, base64.StdEncoding.EncodeToString([]byte(password)))
		return err
	}
	return errors.New("No supported auth methods found.")
}

// Stat retrieves a drop listing for the current maildrop, consisting of the
// number of messages and the total size (in octets) of the maildrop.
// Information provided besides the number of messages and the size of the
// maildrop is ignored. In the event of an error, all returned numeric values
// will be 0.
func (c *Client) Stat() (count, size int, err error) {
	l, err := c.Cmd("STAT")
	if err != nil {
		return 0, 0, err
	}
	parts := strings.Fields(l)
	count, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, errors.New("Invalid server response")
	}
	size, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, errors.New("Invalid server response")
	}
	return
}

// List returns the size of the given message, if it exists. If the message
// does not exist, or another error is encountered, the returned size will be
// 0.
func (c *Client) List(msg int) (size int, err error) {
	l, err := c.Cmd("LIST %d", msg)
	if err != nil {
		return 0, err
	}
	size, err = strconv.Atoi(strings.Fields(l)[1])
	if err != nil {
		return 0, errors.New("Invalid server response")
	}
	return size, nil
}

// ListAll returns a list of all messages and their sizes.
func (c *Client) ListAll() (msgs []int, sizes []int, err error) {
	_, err = c.Cmd("LIST")
	if err != nil {
		return
	}
	lines, err := c.ReadLines()
	if err != nil {
		return
	}
	msgs = make([]int, len(lines), len(lines))
	sizes = make([]int, len(lines), len(lines))
	for i, l := range lines {
		var m, s int
		fs := strings.Fields(l)
		m, err = strconv.Atoi(fs[0])
		if err != nil {
			return
		}
		s, err = strconv.Atoi(fs[1])
		if err != nil {
			return
		}
		msgs[i] = m
		sizes[i] = s
	}
	return
}

// Retr downloads and returns the given message. The lines are separated by LF,
// whatever the server sent.
func (c *Client) Retr(msg int) (text string, err error) {
	_, err = c.Cmd("RETR %d", msg)
	if err != nil {
		return "", err
	}
	lines, err := c.ReadLines()
	text = strings.Join(lines, "\n")
	return
}

// Dele marks the given message as deleted.
func (c *Client) Dele(msg int) (err error) {
	_, err = c.Cmd("DELE %d", msg)
	return
}

// Noop does nothing, but will prolong the end of the connection if the server
// has a timeout set.
func (c *Client) Noop() (err error) {
	_, err = c.Cmd("NOOP")
	return
}

// Rset unmarks any messages marked for deletion previously in this session.
func (c *Client) Rset() (err error) {
	_, err = c.Cmd("RSET")
	return
}

// Quit sends the QUIT message to the POP3 server and closes the connection.
func (c *Client) Quit() error {
	_, err := c.Cmd("QUIT")
	if err != nil {
		return err
	}
	c.conn.Close()
	return nil
}
