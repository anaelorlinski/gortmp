package gortmp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/zhangpeihao/log"
)

func Handshake2(c net.Conn, br *bufio.Reader, bw *bufio.Writer, timeout time.Duration) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()
	// Send C0+C1
	err = bw.WriteByte(0x03)
	CheckError(err, "Handshake() Send C0")
	c1 := CreateRandomBlock(RTMP_SIG_SIZE)
	// Set Timestamp
	binary.BigEndian.PutUint32(c1, uint32(time.Now().Unix()))
	// Set FlashPlayer version
	for i := 0; i < 4; i++ {
		//c1[4+i] = FLASH_PLAYER_VERSION[i]
		c1[4+i] = 0
	}

	_, err = bw.Write(c1)
	CheckError(err, "Handshake() Send C1")
	if timeout > 0 {
		c.SetWriteDeadline(time.Now().Add(timeout))
	}
	err = bw.Flush()
	CheckError(err, "Handshake() Flush C0+C1")

	// Read S0
	if timeout > 0 {
		c.SetReadDeadline(time.Now().Add(timeout))
	}
	s0, err := br.ReadByte()
	CheckError(err, "Handshake() Read S0")
	if s0 != 0x03 {
		return errors.New(fmt.Sprintf("Handshake() Got S0: %x", s0))
	}

	// Read S1
	s1 := make([]byte, RTMP_SIG_SIZE)
	if timeout > 0 {
		c.SetReadDeadline(time.Now().Add(timeout))
	}
	_, err = io.ReadAtLeast(br, s1, RTMP_SIG_SIZE)
	CheckError(err, "Handshake Read S1")

	// write c2?
	bw.Write(s1)
	err = bw.Flush()
	CheckError(err, "Handshake() Flush C2")

	// Read S2
	if timeout > 0 {
		c.SetReadDeadline(time.Now().Add(timeout))
	}
	s2 := make([]byte, RTMP_SIG_SIZE)
	_, err = io.ReadAtLeast(br, s2, RTMP_SIG_SIZE)
	CheckError(err, "Handshake() Read S2")

	// compare with cliebnt
	if !bytes.Equal(c1, s2) {
		return errors.New("Server response validating failed")
	}

	if timeout > 0 {
		c.SetDeadline(time.Time{})
	}

	return
}

func SHandshake2(c net.Conn, br *bufio.Reader, bw *bufio.Writer, timeout time.Duration) (err error) {

	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()
	// Send S0+S1
	err = bw.WriteByte(0x03)
	CheckError(err, "SHandshake() Send S0")
	s1 := CreateRandomBlock(RTMP_SIG_SIZE)
	// Set Timestamp
	// binary.BigEndian.PutUint32(s1, uint32(GetTimestamp()))
	binary.BigEndian.PutUint32(s1, uint32(0))
	// Set FlashPlayer version
	for i := 0; i < 4; i++ {
		s1[4+i] = FMS_VERSION[i]
	}

	_, err = bw.Write(s1)
	CheckError(err, "SHandshake() Send S1")
	if timeout > 0 {
		c.SetWriteDeadline(time.Now().Add(timeout))
	}
	err = bw.Flush()
	CheckError(err, "SHandshake() Flush S0+S1")

	// Read C0
	if timeout > 0 {
		c.SetReadDeadline(time.Now().Add(timeout))
	}
	c0, err := br.ReadByte()
	CheckError(err, "SHandshake() Read C0")
	if c0 != 0x03 {
		return errors.New(fmt.Sprintf("SHandshake() Got C0: %x", c0))
	}

	// Read C1
	c1 := make([]byte, RTMP_SIG_SIZE)
	if timeout > 0 {
		c.SetReadDeadline(time.Now().Add(timeout))
	}
	_, err = io.ReadAtLeast(br, c1, RTMP_SIG_SIZE)
	CheckError(err, "SHandshake Read C1")
	logger.ModulePrintf(logHandler, log.LOG_LEVEL_DEBUG,
		"SHandshake() Flash player version is %d.%d.%d.%d", c1[4], c1[5], c1[6], c1[7])

	// Generate S2, miror C1
	// Send S2
	_, err = bw.Write(c1)
	CheckError(err, "SHandshake() Send S2")

	if timeout > 0 {
		c.SetWriteDeadline(time.Now().Add(timeout))
	}
	err = bw.Flush()
	CheckError(err, "SHandshake() Flush S2")

	// Read C2
	if timeout > 0 {
		c.SetReadDeadline(time.Now().Add(timeout))
	}
	c2 := make([]byte, RTMP_SIG_SIZE)
	_, err = io.ReadAtLeast(br, c2, RTMP_SIG_SIZE)
	CheckError(err, "SHandshake() Read C2")
	// TODO: check C2
	if timeout > 0 {
		c.SetDeadline(time.Time{})
	}
	return
}
