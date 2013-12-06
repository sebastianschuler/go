/*
 * Written by Kevin Ballard (https://github.com/kballard/go-shellquote)
 * Changes by Sebastian Schuler
 */
package os

import (
	"bytes"
	"errors"
	"strings"
	"syscall"
	"unicode/utf8"
	"unicode/utf16"
)

var (
	UnterminatedSingleQuoteError = errors.New("Unterminated single-quoted string")
	UnterminatedDoubleQuoteError = errors.New("Unterminated double-quoted string")
	UnterminatedEscapeError      = errors.New("Unterminated backslash-escape")
)

var (
	splitChars        = " \n\t"
	singleChar        = '\''
	doubleChar        = '"'
	escapeChar        = '\\'
	doubleEscapeChars = "$`\"\n\\"
)

// Split splits a string according to /bin/sh's word-splitting rules. It
// supports backslash-escapes, single-quotes, and double-quotes. Notably it does
// not support the $'' style of quoting. It also doesn't attempt to perform any
// other sort of expansion, including brace expansion, shell expansion, or
// pathname expansion.
//
// If the given input has an unterminated quoted string or ends in a
// backslash-escape, one of UnterminatedSingleQuoteError,
// UnterminatedDoubleQuoteError, or UnterminatedEscapeError is returned.
func CommandLineToArgv(input string) (words []string, err error) {
	var buf bytes.Buffer
	words = make([]string, 0)
	
	// If an empty input string is provided this function needs to 
	// return the executable file name
	if input == "" {
		b := make([]uint16, 300)
		n, e := syscall.GetModuleFileName(0, &b[0], uint32(len(b)))
		if e != nil {
			return words, e
		}
		words = append(words, string(utf16.Decode(b[0:n])))
		return
	}
		
	for len(input) > 0 {
		// skip any splitChars at the start
		c, l := utf8.DecodeRuneInString(input)
		if strings.ContainsRune(splitChars, c) {
			input = input[l:]
			continue
		}

		var word string
		word, input, err = splitWord(input, &buf)
		if err != nil {
			return
		}
		words = append(words, word)
	}
	return
}

func splitWord(input string, buf *bytes.Buffer) (word string, remainder string, err error) {
	buf.Reset()

raw:
	{
		cur := input
		for len(cur) > 0 {
				c, l := utf8.DecodeRuneInString(cur)
				cur = cur[l:]
				if c == singleChar {
						buf.WriteString(input[0 : len(input)-len(cur)-l])
						input = cur
						goto single
				} else if c == doubleChar {
						buf.WriteString(input[0 : len(input)-len(cur)-l])
						input = cur
						goto double
				} else if c == escapeChar {
						buf.WriteString(input[0 : len(input)-len(cur)-l])
						input = cur
						goto escape
				} else if strings.ContainsRune(splitChars, c) {
						buf.WriteString(input[0 : len(input)-len(cur)-l])
						return buf.String(), cur, nil
				}
		}
		if len(input) > 0 {
				buf.WriteString(input)
				input = ""
		}
		goto done
	}

escape:
	{
		if len(input) == 0 {
			return "", "", UnterminatedEscapeError
		}
		c, l := utf8.DecodeRuneInString(input)
		if c == '\n' {
			// a backslash-escaped newline is elided from the output entirely
		} else {
			buf.WriteString(input[:l])
		}
		input = input[l:]
	}
	goto raw

single:
	{
		i := strings.IndexRune(input, singleChar)
		if i == -1 {
			return "", "", UnterminatedSingleQuoteError
		}
		buf.WriteString(input[0:i])
		input = input[i+1:]
		goto raw
	}

double:
	{
		cur := input
		for len(cur) > 0 {
			c, l := utf8.DecodeRuneInString(cur)
			cur = cur[l:]
			if c == doubleChar {
				buf.WriteString(input[0 : len(input)-len(cur)-l])
				input = cur
				goto raw
			} else if c == escapeChar {
				// bash only supports certain escapes in double-quoted strings
				c2, l2 := utf8.DecodeRuneInString(cur)
				cur = cur[l2:]
				if strings.ContainsRune(doubleEscapeChars, c2) {
					buf.WriteString(input[0 : len(input)-len(cur)-l-l2])
					if c2 == '\n' {
						// newline is special, skip the backslash entirely
					} else {
						buf.WriteRune(c2)
					}
					input = cur
				}
			}
		}
		return "", "", UnterminatedDoubleQuoteError
	}

done:
	return buf.String(), input, nil
}
