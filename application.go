package rtcp

import (
	"encoding/binary"
	"fmt"
)

// The Application packet indicates application data
type Application struct {
	// subtype
	SubType uint8
	// SSRC or CSRC
	SSRC uint32
	// Namee (ASCII)
	Name [4]byte

	// application-dependent data
	Data []byte
}

var _ Packet = (*Application)(nil) // assert is a Packet

const (
	appSSRCOffset = 0
	appNameOffset = appSSRCOffset + ssrcLength
	appNameLength = 4
	appDataOffset = appNameOffset + appNameLength
)

// Marshal encodes the Application packet in binary
func (app Application) Marshal() ([]byte, error) {
	/*
	 *  0                   1                   2                   3
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |V=2|P| subtype |   PT=APP=204  |             length            |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                           SSRC/CSRC                           |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                          name (ASCII)                         |
	 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	 * |                   application-dependent data                ...
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	rawPacket := make([]byte, app.MarshalSize())
	packetBody := rawPacket[headerLength:]

	binary.BigEndian.PutUint32(packetBody, app.SSRC)
	copy(packetBody[appNameOffset:], app.Name[:])
	copy(packetBody[appDataOffset:], app.Data)

	hData, err := app.Header().Marshal()
	if err != nil {
		return nil, err
	}
	copy(rawPacket, hData)

	if getPadding(app.packetLen()) != 0 {
		rawPacket[len(rawPacket)-1] = uint8(app.MarshalSize() - app.packetLen())
	}

	return rawPacket, nil
}

// Unmarshal decodes the Application packet from binary
func (app *Application) Unmarshal(rawPacket []byte) error {
	/*
	 *  0                   1                   2                   3
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |V=2|P| subtype |   PT=APP=204  |             length            |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                           SSRC/CSRC                           |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                          name (ASCII)                         |
	 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
	 * |                   application-dependent data                ...
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	var header Header
	if err := header.Unmarshal(rawPacket); err != nil {
		return err
	}

	if header.Type != TypeApplicationDefined {
		return errWrongType
	}

	if len(rawPacket) < headerLength || getPadding(len(rawPacket)) != 0 {
		return errPacketTooShort
	}

	packetBody := rawPacket[headerLength:]
	if len(packetBody) < appDataOffset {
		return errPacketTooShort
	}

	app.SubType = header.Count
	app.SSRC = binary.BigEndian.Uint32(packetBody[appSSRCOffset:])
	copy(app.Name[:], packetBody[appNameOffset:])

	dataBody := packetBody[appDataOffset:]
	if header.Padding {
		len := len(dataBody) - int(dataBody[len(dataBody)-1])
		dataBody = dataBody[:len]
	}
	if len(app.Data) < len(dataBody) {
		app.Data = make([]byte, len(dataBody))
	}
	copy(app.Data, dataBody)

	return nil
}

// Header returns the Header associated with this packet.
func (app *Application) Header() Header {
	return Header{
		Padding: getPadding(app.packetLen()) != 0,
		Count:   app.SubType,
		Type:    TypeApplicationDefined,
		Length:  uint16((app.MarshalSize() / 4) - 1),
	}
}

func (app *Application) MarshalSize() int {
	l := app.packetLen()
	return l + getPadding(l)
}

func (app *Application) packetLen() int {
	return headerLength + ssrcLength + appNameLength + len(app.Data)
}

// DestinationSSRC returns an array of SSRC values that this packet refers to.
func (app *Application) DestinationSSRC() []uint32 {
	return []uint32{app.SSRC}
}

func (app *Application) String() string {
	out := fmt.Sprintf("Application from %x\n", app.SSRC)
	out += fmt.Sprintf("\tSubType: %x\n", app.SubType)
	out += fmt.Sprintf("\tName: %c%c%c%c\n", app.Name[0], app.Name[1], app.Name[2], app.Name[3])
	out += fmt.Sprintf("\tData: %v\n", app.Data)
	return out
}
