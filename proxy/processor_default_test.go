package proxy

import (
	"bytes"
	"encoding/hex"
	"github.com/grepplabs/kafka-proxy/proxy/protocol"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestHandleRequest(t *testing.T) {
	tt := []struct {
		name       string
		apiKey     int16
		apiVersion int16
		hexInput   string
	}{
		{name: "Produce v2, kafka-client 0.10.2.2, acks=1", apiKey: 0, apiVersion: 2,
			hexInput: "00000086000000020000000500144b61666b614578616d706c6550726f647563657200010000753000000001000f746573742d6e6f2d68656164657273000000010000000000000041000000000000000000000035fe96cb720100000001734a61d94200000008000001734a61d8df0000001748656c6c6f204d6f6d2031353934363830373933333131",
		},
		{name: "Produce v2, kafka-client 0.10.2.2, acks=all", apiKey: 0, apiVersion: 2,
			hexInput: "00000086000000020000000500144b61666b614578616d706c6550726f6475636572ffff0000753000000001000f746573742d6e6f2d68656164657273000000010000000000000041000000000000000000000035f472a86d0100000001734a6349bb00000008000001734a6349600000001748656c6c6f204d6f6d2031353934363830383837363438",
		},
		{name: "Produce v2, kafka-client 0.10.2.2, acks=0", apiKey: 0, apiVersion: 2,
			hexInput: "00000086000000020000000500144b61666b614578616d706c6550726f647563657200000000753000000001000f746573742d6e6f2d68656164657273000000010000000000000041000000000000000000000035557b46590100000001734a64b31f00000008000001734a64b2be0000001748656c6c6f204d6f6d2031353934363830393830313538",
		},
		{name: "Produce v3, kafka-client 0.11.0.2, acks=1", apiKey: 0, apiVersion: 3,
			hexInput: "000000c2000000030000000500144b61666b614578616d706c6550726f6475636572ffff00010000753000000001000f746573742d6e6f2d6865616465727300000001000000000000007b00000000000000000000006fffffffff0231f7fe0e000000000000000001734a66bef6000001734a66bef6ffffffffffffffffffffffffffff000000017a00000010000001734a66be5f2e48656c6c6f204d6f6d203135393436383131313432303702146865616465722d6b6579186865616465722d76616c7565",
		},
		{name: "Produce v3, kafka-client 0.11.0.2, acks=all", apiKey: 0, apiVersion: 3,
			hexInput: "000000c2000000030000000500144b61666b614578616d706c6550726f6475636572ffffffff0000753000000001000f746573742d6e6f2d6865616465727300000001000000000000007b00000000000000000000006fffffffff028386cf33000000000000000001734a6836c1000001734a6836c1ffffffffffffffffffffffffffff000000017a00000010000001734a68363f2e48656c6c6f204d6f6d203135393436383132313034333102146865616465722d6b6579186865616465722d76616c7565",
		},
		{name: "Produce v3, kafka-client 0.11.0.2, acks=0", apiKey: 0, apiVersion: 3,
			hexInput: "000000c2000000030000000500144b61666b614578616d706c6550726f6475636572ffff00000000753000000001000f746573742d6e6f2d6865616465727300000001000000000000007b00000000000000000000006fffffffff0274ff21b4000000000000000001734a68c09a000001734a68c09affffffffffffffffffffffffffff000000017a00000010000001734a68c0162e48656c6c6f204d6f6d203135393436383132343537313802146865616465722d6b6579186865616465722d76616c7565",
		},
		{name: "Produce v3, kafka-client 2.5.0, acks=1", apiKey: 0, apiVersion: 8,
			hexInput: "000000c2000000080000000300144b61666b614578616d706c6550726f6475636572ffff00010000753000000001000f746573742d6e6f2d6865616465727300000001000000000000007b00000000000000000000006fffffffff02662a226b000000000000000001734a69dfbd000001734a69dfbdffffffffffffffffffffffffffff000000017a00000010000001734a69deba2e48656c6c6f204d6f6d203135393436383133313930393802146865616465722d6b6579186865616465722d76616c7565",
		},
		{name: "Produce v3, kafka-client 2.5.0, acks=all", apiKey: 0, apiVersion: 8,
			hexInput: "000000c2000000080000000300144b61666b614578616d706c6550726f6475636572ffffffff0000753000000001000f746573742d6e6f2d6865616465727300000001000000000000007b00000000000000000000006fffffffff025afc90c2000000000000000001734a6ae36d000001734a6ae36dffffffffffffffffffffffffffff000000017a00000010000001734a6ae2592e48656c6c6f204d6f6d203135393436383133383535363102146865616465722d6b6579186865616465722d76616c7565",
		},
		{name: "Produce v3, kafka-client 2.5.0, acks=0", apiKey: 0, apiVersion: 8,
			hexInput: "000000c2000000080000000300144b61666b614578616d706c6550726f6475636572ffff00000000753000000001000f746573742d6e6f2d6865616465727300000001000000000000007b00000000000000000000006fffffffff02021b145f000000000000000001734a6c14d6000001734a6c14d6ffffffffffffffffffffffffffff000000017a00000010000001734a6c13e42e48656c6c6f204d6f6d203135393436383134363337383002146865616465722d6b6579186865616465722d76616c7565",
		},
		{name: "ApiVersions v3, kafka-client 2.5.0", apiKey: 18, apiVersion: 3,
			hexInput: "00000038001200030000000000144b61666b614578616d706c6550726f647563657200126170616368652d6b61666b612d6a61766106322e352e3000",
		},
		{name: "Metadata v9, kafka-client 2.5.0, acks=0", apiKey: 3, apiVersion: 9,
			hexInput: "00000035000300090000000100144b61666b614578616d706c6550726f6475636572000210746573742d6e6f2d686561646572730001000000",
		},
	}
	for _, tc := range tt {
		input, err := hex.DecodeString(tc.hexInput)
		if err != nil {
			t.Fatal(err)
		}
		//TODO: implement me!
		_ = input
	}
}

func TestHandleResponse(t *testing.T) {
	netAddressMappingFunc := func(brokerHost string, brokerPort int32) (listenerHost string, listenerPort int32, err error) {
		if brokerHost == "localhost" {
			switch brokerPort {
			case 19092:
				return "0.0.0.0", 30001, nil
			case 29092:
				return "0.0.0.0", 30002, nil
			case 39092:
				return "0.0.0.0", 30003, nil
			}
		}
		return "", 0, errors.Errorf("unexpected broker %s:%d", brokerHost, brokerPort)
	}
	buf := make([]byte, defaultResponseBufferSize)
	tt := []struct {
		name       string
		apiKey     int16
		apiVersion int16
		hexInput   string
		hexOutput  string
	}{
		{name: "Produce v2, kafka-client 0.10.2.2", apiKey: 0, apiVersion: 2,
			hexInput: "000000370000000500000001000f746573742d6e6f2d6865616465727300000001000000000000000000000000000affffffffffffffff00000000",
		},
		{name: "Produce v5, kafka-client 1.1.1", apiKey: 0, apiVersion: 5,
			hexInput: "0000003f0000001000000001000f746573742d6e6f2d68656164657273000000010000000000000000000000000008ffffffffffffffff000000000000000000000000",
		},
		{name: "Produce v6, kafka-client 2.0.1", apiKey: 0, apiVersion: 6,
			hexInput: "0000003f0000000e00000001000f746573742d6e6f2d68656164657273000000010000000000000000000000000077ffffffffffffffff000000000000000000000000",
		},
		{name: "Produce v7, kafka-client 2.2.2", apiKey: 0, apiVersion: 7,
			hexInput: "0000003f0000000e00000001000f746573742d6e6f2d68656164657273000000010000000000000000000000000059ffffffffffffffff000000000000000000000000",
		},
		{name: "Produce v8", apiKey: 0, apiVersion: 8,
			hexInput: "000000450000000300000001000f746573742d6e6f2d6865616465727300000001000000000000000000000000000affffffffffffffff000000000000000000000000ffff00000000",
		},
		{name: "Fetch v11, kafka-client 2.3.1", apiKey: 1, apiVersion: 11,
			hexInput: "0000003d0000000200000000000000010011746f7069632d73746172742d6f6c642d3200000001000000000000ffffffffffffffff000000000000000000000000",
		},
		{name: "ListOffsets v5, kafka-client 2.3.1", apiKey: 2, apiVersion: 5,
			hexInput: "0000003d0000000200000000000000010011746f7069632d73746172742d6f6c642d3200000001000000000000ffffffffffffffff000000000000000000000000",
		},
		{name: "Metadata v5, kafka-client 1.1.1", apiKey: 3, apiVersion: 5,
			hexInput:  "000000830000000300000000000000030000000200096c6f63616c686f7374000071a4ffff0000000300096c6f63616c686f7374000098b4ffff0000000100096c6f63616c686f737400004a94ffff001641765a42526d583151377567314972466861387a6b4100000001000000010005000f746573742d6e6f2d686561646572730000000000",
			hexOutput: "0000007d000000030000000000000003000000020007302e302e302e3000007532ffff000000030007302e302e302e3000007533ffff000000010007302e302e302e3000007531ffff001641765a42526d583151377567314972466861387a6b4100000001000000010005000f746573742d6e6f2d686561646572730000000000",
		},
		{name: "Metadata v6, kafka-client 2.0.1", apiKey: 3, apiVersion: 6,
			hexInput:  "000000a10000000300000000000000030000000200096c6f63616c686f7374000071a4ffff0000000300096c6f63616c686f7374000098b4ffff0000000100096c6f63616c686f737400004a94ffff001661675a5354684564533236587a3343566a6944614b5100000003000000010000000f746573742d6e6f2d686561646572730000000001000000000000000000030000000100000003000000010000000300000000",
			hexOutput: "0000009b000000030000000000000003000000020007302e302e302e3000007532ffff000000030007302e302e302e3000007533ffff000000010007302e302e302e3000007531ffff001661675a5354684564533236587a3343566a6944614b5100000003000000010000000f746573742d6e6f2d686561646572730000000001000000000000000000030000000100000003000000010000000300000000",
		},
		{name: "Metadata v7, kafka-client 2.1.1", apiKey: 3, apiVersion: 7,
			hexInput:  "000000a50000000200000000000000030000000200096c6f63616c686f7374000071a4ffff0000000300096c6f63616c686f7374000098b4ffff0000000100096c6f63616c686f737400004a94ffff001661675a5354684564533236587a3343566a6944614b5100000003000000010000000f746573742d6e6f2d68656164657273000000000100000000000000000003000000000000000100000003000000010000000300000000",
			hexOutput: "0000009f000000020000000000000003000000020007302e302e302e3000007532ffff000000030007302e302e302e3000007533ffff000000010007302e302e302e3000007531ffff001661675a5354684564533236587a3343566a6944614b5100000003000000010000000f746573742d6e6f2d68656164657273000000000100000000000000000003000000000000000100000003000000010000000300000000",
		},
		{name: "Metadata v8, kafka-client 2.3.1", apiKey: 3, apiVersion: 8,
			hexInput:  "000000ad0000000100000000000000030000000200096c6f63616c686f7374000071a4ffff0000000300096c6f63616c686f7374000098b4ffff0000000100096c6f63616c686f737400004a94ffff001661675a5354684564533236587a3343566a6944614b5100000003000000010000000f746573742d6e6f2d686561646572730000000001000000000000000000030000000000000001000000030000000100000003000000000000000000000000",
			hexOutput: "000000a7000000010000000000000003000000020007302e302e302e3000007532ffff000000030007302e302e302e3000007533ffff000000010007302e302e302e3000007531ffff001661675a5354684564533236587a3343566a6944614b5100000003000000010000000f746573742d6e6f2d686561646572730000000001000000000000000000030000000000000001000000030000000100000003000000000000000000000000",
		},
		{name: "Metadata v9, kafka-client 2.4.1", apiKey: 3, apiVersion: 9,
			hexInput:  "0000009a00000001000000000004000000020a6c6f63616c686f7374000071a40000000000030a6c6f63616c686f7374000098b40000000000010a6c6f63616c686f737400004a9400001761675a5354684564533236587a3343566a6944614b510000000302000010746573742d6e6f2d686561646572730002000000000000000000030000000002000000030200000003010000000000000000000000",
			hexOutput: "00000094000000010000000000040000000208302e302e302e300000753200000000000308302e302e302e300000753300000000000108302e302e302e300000753100001761675a5354684564533236587a3343566a6944614b510000000302000010746573742d6e6f2d686561646572730002000000000000000000030000000002000000030200000003010000000000000000000000",
		},
		{name: "OffsetFetch v5, kafka-client 2.3.1", apiKey: 9, apiVersion: 5,
			hexInput: "000000390000000c00000000000000010011746f7069632d73746172742d6f6c642d3200000001000000000000000000000000ffffffff000000000000",
		},
		{name: "OffsetFetch v6, kafka-client 2.4.1", apiKey: 9, apiVersion: 6,
			hexInput: "000000350000000c00000000000212746f7069632d73746172742d6f6c642d3202000000000000000000000000ffffffff0100000000000000",
		},
		{name: "DescribeGroups v3, kafka-client 2.3.1", apiKey: 15, apiVersion: 3,
			hexInput: "000000400000000a0000000000000001000000154b61666b614578616d706c65436f6e73756d6572320005456d7074790008636f6e73756d657200000000000000000000",
		},
		{name: "ListGroups v2, kafka-client 2.3.1", apiKey: 16, apiVersion: 2,
			hexInput: "0000002f000000040000000000000000000100154b61666b614578616d706c65436f6e73756d6572320008636f6e73756d6572",
		},
		{name: "FindCoordinator v2, kafka-client 2.3.1", apiKey: 10, apiVersion: 2,
			hexInput:  "000000230000000b00000000000000044e4f4e450000000200096c6f63616c686f7374000071a4",
			hexOutput: "000000210000000b00000000000000044e4f4e45000000020007302e302e302e3000007532",
		},
		{name: "FindCoordinator v3, kafka-client 2.4.1", apiKey: 10, apiVersion: 3,
			hexInput:  "000000230000000900000000000000054e4f4e45000000020a6c6f63616c686f7374000071a400",
			hexOutput: "000000210000000900000000000000054e4f4e450000000208302e302e302e300000753200",
		},
		{name: "SaslHandshake v1, kafka-client 2.3.1 ", apiKey: 17, apiVersion: 1,
			hexInput: "00000011000000000000000000010005504c41494e",
		},
		{name: "ApiVersions v1, kafka-client 1.1.1", apiKey: 18, apiVersion: 1,
			hexInput: "0000012e0000000000000000003000000000000800010000000b000200000005000300000009000400000004000500000002000600000006000700000003000800000008000900000006000a00000003000b00000006000c00000004000d00000004000e00000004000f00000005001000000003001100000001001200000003001300000005001400000004001500000001001600000002001700000003001800000001001900000001001a00000001001b00000000001c00000002001d00000001001e00000001001f00000001002000000002002100000001002200000001002300000001002400000001002500000001002600000002002700000001002800000001002900000001002a00000002002b00000002002c00000001002d00000000002e00000000002f0000000000000000",
		},
		{name: "ApiVersions v2, kafka-client 2.2.2", apiKey: 18, apiVersion: 2,
			hexInput: "0000012e0000000400000000003000000000000800010000000b000200000005000300000009000400000004000500000002000600000006000700000003000800000008000900000006000a00000003000b00000006000c00000004000d00000004000e00000004000f00000005001000000003001100000001001200000003001300000005001400000004001500000001001600000002001700000003001800000001001900000001001a00000001001b00000000001c00000002001d00000001001e00000001001f00000001002000000002002100000001002200000001002300000001002400000001002500000001002600000002002700000001002800000001002900000001002a00000002002b00000002002c00000001002d00000000002e00000000002f0000000000000000",
		},
		{name: "ApiVersions v3, kafka-client 2.4.1 ", apiKey: 18, apiVersion: 3,
			hexInput: "0000015c000000030000310000000000080000010000000b000002000000050000030000000900000400000004000005000000020000060000000600000700000003000008000000080000090000000600000a0000000300000b0000000600000c0000000400000d0000000400000e0000000400000f000000050000100000000300001100000001000012000000030000130000000500001400000004000015000000010000160000000200001700000003000018000000010000190000000100001a0000000100001b0000000000001c0000000200001d0000000100001e0000000100001f000000010000200000000200002100000001000022000000010000230000000100002400000001000025000000010000260000000200002700000001000028000000010000290000000100002a0000000200002b0000000200002c0000000100002d0000000000002e0000000000002f00000000000000000000",
		},
		{name: "DescribeAcls v2, kafka-client 2.4.1 ", apiKey: 29, apiVersion: 1,
			hexInput: "000000390000000300000000003600294e6f20417574686f72697a657220697320636f6e66696775726564206f6e207468652062726f6b657200000000",
		},
		{name: "SaslAuthenticate v1, kafka-client 2.3.1 ", apiKey: 36, apiVersion: 1,
			hexInput: "0000000d00000003000000000000000100",
		},
		{name: "ElectLeaders v2, kafka-client 2.4.1 ", apiKey: 43, apiVersion: 2,
			hexInput: "0000000d00000003000000000000000100",
		},
	}
	for _, tc := range tt {

		input, err := hex.DecodeString(tc.hexInput)
		if err != nil {
			t.Fatal(err)
		}
		var expected []byte
		if tc.hexOutput != "" {
			expected, err = hex.DecodeString(tc.hexOutput)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			expected = input
		}

		readBuffer := bytes.NewBuffer(input)
		src := &TestDeadlineReader{
			Buffer: readBuffer,
		}
		output := bytes.NewBuffer(make([]byte, 0))
		dst := &TestDeadlineWriter{
			Buffer: output,
		}

		openRequestsChannel := make(chan protocol.RequestKeyVersion, 1)
		openRequestsChannel <- protocol.RequestKeyVersion{ApiKey: tc.apiKey, ApiVersion: tc.apiVersion}

		ctx := &ResponsesLoopContext{openRequestsChannel: openRequestsChannel, timeout: 1 * time.Second, buf: buf, netAddressMappingFunc: netAddressMappingFunc}

		a := assert.New(t)
		handler := &DefaultResponseHandler{}
		_, err = handler.handleResponse(dst, src, ctx)
		if err != nil {
			t.Fatal(err)
		}
		a.Equal(expected, output.Bytes())
		a.Empty(readBuffer.Bytes()) // check all bytes from input has been read
	}
}

type TestDeadlineWriter struct {
	*bytes.Buffer
}

func (w *TestDeadlineWriter) SetWriteDeadline(t time.Time) error {
	return nil
}

type TestDeadlineReader struct {
	*bytes.Buffer
}

func (w *TestDeadlineReader) SetReadDeadline(t time.Time) error {
	return nil
}
