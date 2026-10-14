// Package contentcoding undoes the content codings of an HTTP message body
// (RFC 9110 section 8.4) within a bound: gzip, deflate, br and zstd, one per
// message.
//
// ParseList reads the codings from the captured Content-Encoding fields and
// decides, before anything is decoded, whether they are supported: one coding
// this package undoes, or none. Decode then undoes that coding as one stage and
// returns the first decisive outcome: Decoded with the content, or
// DecodingFailed, DecodedTooLarge or Refused with nothing.
//
// The stage is bounded. Its output is read into a buffer of at most bound + 1
// bytes, so an output of exactly bound bytes passes and the byte after it is
// DecodedTooLarge, found without decoding further. Its decoder's workspace,
// Workspace, is planned from the stream's headers and reserved before the
// decoder exists, and released after it is closed. Each output buffer is
// reserved whole before it is allocated, and the one a growth replaces is
// released once copied; the last passes to the caller with the content. What
// one decode holds at once is at most Peak; what it allocates in total,
// garbage included, is at most Cumulative.
//
// The caller supplies the Reserver that accounts for those charges, and a
// refused reservation ends the decode as Refused, every charge released.
package contentcoding
