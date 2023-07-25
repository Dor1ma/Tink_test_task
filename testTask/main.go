package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

type packet struct {
	Length  byte
	Payload payload
	CRC8    byte
}

type varuint uint64

func (v *varuint) Read(buf *bytes.Reader) error {
	var shift uint
	for {
		b, err := buf.ReadByte()
		if err != nil {
			return err
		}
		*v |= varuint(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return nil
}

type payload struct {
	Src     varuint
	Dst     varuint
	Serial  varuint
	DevType byte
	Cmd     byte
	CmdBody cmd_body
}

type cmd_body struct {
	Timestamp varuint
	Value     byte
	DevName   []byte
}

func (object *packet) get_info() {
	fmt.Println("LENGTH: ", object.Length)
	object.Payload.get_info()
	fmt.Println("CRC8: ", object.CRC8)
}

func (object *payload) get_info() {
	fmt.Println("Source: ", object.Src)
	fmt.Println("DST: ", object.Dst)
	fmt.Println("Serial: ", object.Serial)
	fmt.Println("Dev_type: ", object.DevType)
	fmt.Println("Cmd: ", object.Cmd)
	fmt.Println("Cmd_body: ", object.CmdBody)
}

func decodePackets(decodedData []byte) ([]packet, error) {
	packets := make([]packet, 0, 10)
	buf := bytes.NewReader(decodedData)

	for buf.Len() > 0 {
		var pt packet
		err := binary.Read(buf, binary.LittleEndian, &pt.Length)
		if err != nil {
			break
		}

		temp := make([]byte, pt.Length)

		err = binary.Read(buf, binary.LittleEndian, &temp)
		if err != nil {
			break
		}

		pt.Payload, err = decodePayload(temp)
		if err != nil {
			break
		}

		err = binary.Read(buf, binary.LittleEndian, &pt.CRC8)
		if err != nil {
			pt.CRC8 = crc8(decodedData)
		}

		packets = append(packets, pt)
	}

	return packets, nil
}

func decodePayload(data []byte) (payload, error) {
	buf := bytes.NewReader(data)

	var pt payload
	err := pt.Src.Read(buf)
	if err != nil {
		return pt, err
	}

	err = pt.Dst.Read(buf)
	if err != nil {
		return pt, err
	}

	err = pt.Serial.Read(buf)
	if err != nil {
		return pt, err
	}

	err = binary.Read(buf, binary.LittleEndian, &pt.DevType)
	if err != nil {
		return pt, err
	}

	err = binary.Read(buf, binary.LittleEndian, &pt.Cmd)
	if err != nil {
		return pt, err
	}

	temp := make([]byte, buf.Len())
	err = binary.Read(buf, binary.LittleEndian, &temp)
	if err != nil {
		return pt, err
	}

	pt.CmdBody, err = decodeCmdBody(temp, &pt)

	return pt, err
}

func decodeCmdBody(data []byte, pt *payload) (cmd_body, error) {
	buf := bytes.NewReader(data)

	var cb cmd_body
	if pt.DevType == 6 && pt.Cmd == 6 {
		err := cb.Timestamp.Read(buf)
		if err != nil {
			return cmd_body{}, nil
		}

	} else if pt.DevType == 2 {
		var size byte
		err := binary.Read(buf, binary.LittleEndian, &size)
		if err != nil {
			return cmd_body{}, nil
		}

		temp := make([]byte, size)
		err = binary.Read(buf, binary.LittleEndian, &temp)
		cb.DevName = temp

		err = binary.Read(buf, binary.LittleEndian, &cb.Value)
		if err != nil {
			return cmd_body{}, nil
		}
	} else if pt.DevType == 4 {
		var size byte
		_ = binary.Read(buf, binary.LittleEndian, &size)

		temp := make([]byte, size)
		_ = binary.Read(buf, binary.LittleEndian, &temp)
		cb.DevName = temp
	}

	return cb, nil
}

func makeRequest(url string, message string) ([]byte, int) {
	var temp []byte

	// "DLMG_38BAQEEMHgwMc0"
	//"Bv9_AgkDA5I" - GETSTATUS FOR SWITCH
	// "B_9_giAJAwOR" - GETSTATUS FOR LAMP
	// "CP9_giAPBAUBvQ" - SETSTATUS FOR LAMP
	payload := strings.NewReader(message)

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return temp, 99
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return temp, 99
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return temp, 99
	}

	if resp.StatusCode == 200 {
		return responseBody, 200
	} else if resp.StatusCode == 204 {
		return temp, 204
	} else {
		return temp, 99
	}
}

func createMessage(data []byte) {

}

func MillisecondsToTime(milliseconds int64) time.Time {
	return time.Unix(0, milliseconds*int64(time.Millisecond))
}

func encodePacket(packets []packet) string {
	encodedData := make([]byte, 0, len(packets))

	for _, pt := range packets {
		encodedData = append(encodedData, pt.Length)

		byte_payload := payloadEncoder(pt.Payload)

		encodedData = append(encodedData, byte_payload...)
		encodedData = append(encodedData, crc8(encodedData))
	}

	base64Str := base64.URLEncoding.EncodeToString(encodedData)
	return base64Str
}

func payloadEncoder(p payload) []byte {
	encodedData := make([]byte, 0)

	encodedData = append(encodedData, encodeVaruint(uint64(p.Src))...)
	encodedData = append(encodedData, encodeVaruint(uint64(p.Dst))...)
	encodedData = append(encodedData, encodeVaruint(uint64(p.Serial))...)

	encodedData = append(encodedData, p.DevType)
	encodedData = append(encodedData, p.Cmd)

	cmd_payload := cmdEncoder(p.CmdBody)

	encodedData = append(encodedData, cmd_payload...)

	return encodedData
}

func cmdEncoder(cb cmd_body) []byte {
	encodedData := make([]byte, 0)

	encodedData = append(encodedData, encodeVaruint(uint64(cb.Timestamp))...)

	return encodedData
}

func encodeVaruint(value uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, value)
	return buf[:n]
}

func crc8(data []byte) byte {
	crc := byte(0)
	for _, b := range data {
		crc ^= b
		for i := 0; i < 8; i++ {
			if crc&0x80 != 0 {
				crc = (crc << 1) ^ 0x07
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

var previousTime varuint
var disabledDevices map[varuint]bool

func packetsHandler(packets *[]packet) int {
	for _, pt := range *packets {
		if pt.Payload.DevType == 6 && pt.Payload.Cmd == 6 {
			newTime := pt.Payload.CmdBody.Timestamp

			if newTime-previousTime > 300 {
				disabledDevices[pt.Payload.Src] = true
				previousTime = newTime
			} else {
				_, ok := disabledDevices[pt.Payload.Src]
				if ok {
					delete(disabledDevices, pt.Payload.Src)
				}
			}
			previousTime = newTime
		}
	}

	return 0
}

func main() {
	url := os.Args[1]
	_ = os.Args[2]

	disabledDevices = make(map[varuint]bool)
	message := ""
	i := 0

	for {
		if i == 0 {
			message = "DLMG_38BAQEEMHgwMc0"
		}

		data, code := makeRequest(url, message)
		if code != 200 {
			if code == 204 {
				os.Exit(0)
			} else {
				os.Exit(99)
			}
		}

		newData := string(data)

		newData = strings.ReplaceAll(newData, " ", "")
		newData = strings.ReplaceAll(newData, "\t", "")
		newData = strings.ReplaceAll(newData, "\n", "")

		decodedData, err := base64.URLEncoding.DecodeString(newData)
		if err != nil {
			continue
		}

		packets, err := decodePackets(decodedData)
		if err != nil {
			continue
		}

		packetsHandler(&packets)
		i++
	}
}
