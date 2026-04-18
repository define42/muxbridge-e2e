package controlpb

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type protoCase interface {
	proto.Message
	Reset()
	String() string
	ProtoMessage()
	ProtoReflect() protoreflect.Message
}

func TestDrainReasonEnumMethods(t *testing.T) {
	t.Parallel()

	reason := DrainReason_DRAIN_REASON_SESSION_REPLACED
	if got := reason.Enum(); got == nil || *got != reason {
		t.Fatalf("Enum() = %v, want %v", got, reason)
	}
	if got := reason.String(); got == "" {
		t.Fatal("String() returned an empty value")
	}
	if reason.Descriptor() == nil {
		t.Fatal("Descriptor() returned nil")
	}
	if reason.Type() == nil {
		t.Fatal("Type() returned nil")
	}
	if got := reason.Number(); got != protoreflect.EnumNumber(reason) {
		t.Fatalf("Number() = %v, want %v", got, protoreflect.EnumNumber(reason))
	}
	if got, _ := reason.EnumDescriptor(); len(got) == 0 {
		t.Fatal("EnumDescriptor() returned an empty descriptor")
	}
	file_proto_control_proto_init()
}

func TestEnvelopeAndMessages(t *testing.T) {
	t.Parallel()

	var zero Envelope
	if zero.GetMessage() != nil || zero.GetRegisterRequest() != nil || zero.GetRegisterResponse() != nil ||
		zero.GetHeartbeat() != nil || zero.GetHeartbeatAck() != nil || zero.GetDrainNotice() != nil || zero.GetError() != nil {
		t.Fatal("zero Envelope getters should return nil")
	}

	registerRequest := &RegisterRequest{
		Token:     "demo-token",
		Hostnames: []string{"demo.example.test"},
		SessionId: "session-1",
	}
	registerResponse := &RegisterResponse{
		Accepted:               true,
		Message:                "ok",
		Hostnames:              []string{"demo.example.test"},
		HeartbeatIntervalNanos: 10,
		HeartbeatTimeoutNanos:  20,
	}
	heartbeat := &Heartbeat{UnixNano: 11}
	heartbeatAck := &HeartbeatAck{UnixNano: 12}
	drain := &DrainNotice{Reason: DrainReason_DRAIN_REASON_SERVER_SHUTDOWN, Message: "bye"}
	errMsg := &Error{Message: "boom"}
	streamHeader := &StreamHeader{
		Hostname:           "demo.example.test",
		RemoteAddr:         "192.0.2.10:443",
		AcceptedAtUnixNano: 13,
	}

	if registerRequest.GetToken() != "demo-token" || registerRequest.GetSessionId() != "session-1" || len(registerRequest.GetHostnames()) != 1 {
		t.Fatalf("RegisterRequest getters returned unexpected values: %#v", registerRequest)
	}
	if !registerResponse.GetAccepted() || registerResponse.GetMessage() != "ok" || registerResponse.GetHeartbeatIntervalNanos() != 10 || registerResponse.GetHeartbeatTimeoutNanos() != 20 {
		t.Fatalf("RegisterResponse getters returned unexpected values: %#v", registerResponse)
	}
	if heartbeat.GetUnixNano() != 11 || heartbeatAck.GetUnixNano() != 12 {
		t.Fatalf("heartbeat getters returned unexpected values")
	}
	if drain.GetReason() != DrainReason_DRAIN_REASON_SERVER_SHUTDOWN || drain.GetMessage() != "bye" {
		t.Fatalf("DrainNotice getters returned unexpected values: %#v", drain)
	}
	if errMsg.GetMessage() != "boom" {
		t.Fatalf("Error.GetMessage() = %q, want %q", errMsg.GetMessage(), "boom")
	}
	if streamHeader.GetHostname() != "demo.example.test" || streamHeader.GetRemoteAddr() != "192.0.2.10:443" || streamHeader.GetAcceptedAtUnixNano() != 13 {
		t.Fatalf("StreamHeader getters returned unexpected values: %#v", streamHeader)
	}

	registerRequest.ProtoMessage()
	registerResponse.ProtoMessage()
	heartbeat.ProtoMessage()
	heartbeatAck.ProtoMessage()
	drain.ProtoMessage()
	errMsg.ProtoMessage()
	streamHeader.ProtoMessage()
	if got, _ := registerRequest.Descriptor(); len(got) == 0 {
		t.Fatal("RegisterRequest.Descriptor() returned an empty descriptor")
	}
	if got, _ := registerResponse.Descriptor(); len(got) == 0 {
		t.Fatal("RegisterResponse.Descriptor() returned an empty descriptor")
	}
	if got, _ := heartbeat.Descriptor(); len(got) == 0 {
		t.Fatal("Heartbeat.Descriptor() returned an empty descriptor")
	}
	if got, _ := heartbeatAck.Descriptor(); len(got) == 0 {
		t.Fatal("HeartbeatAck.Descriptor() returned an empty descriptor")
	}
	if got, _ := drain.Descriptor(); len(got) == 0 {
		t.Fatal("DrainNotice.Descriptor() returned an empty descriptor")
	}
	if got, _ := errMsg.Descriptor(); len(got) == 0 {
		t.Fatal("Error.Descriptor() returned an empty descriptor")
	}
	if got, _ := streamHeader.Descriptor(); len(got) == 0 {
		t.Fatal("StreamHeader.Descriptor() returned an empty descriptor")
	}

	checkProtoBasics(t, registerRequest)
	checkProtoBasics(t, registerResponse)
	checkProtoBasics(t, heartbeat)
	checkProtoBasics(t, heartbeatAck)
	checkProtoBasics(t, drain)
	checkProtoBasics(t, errMsg)
	checkProtoBasics(t, streamHeader)

	envelopes := []*Envelope{
		{Message: &Envelope_RegisterRequest{RegisterRequest: registerRequest}},
		{Message: &Envelope_RegisterResponse{RegisterResponse: registerResponse}},
		{Message: &Envelope_Heartbeat{Heartbeat: heartbeat}},
		{Message: &Envelope_HeartbeatAck{HeartbeatAck: heartbeatAck}},
		{Message: &Envelope_DrainNotice{DrainNotice: drain}},
		{Message: &Envelope_Error{Error: errMsg}},
	}

	wire, err := proto.Marshal(envelopes[0])
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var roundTrip Envelope
	if err := proto.Unmarshal(wire, &roundTrip); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got := roundTrip.GetRegisterRequest().GetToken(); got != "demo-token" {
		t.Fatalf("roundTrip token = %q, want %q", got, "demo-token")
	}
	if roundTrip.GetMessage() == nil {
		t.Fatal("roundTrip GetMessage() returned nil")
	}

	for _, env := range envelopes {
		checkProtoBasics(t, env)
		env.ProtoMessage()
		if got, _ := env.Descriptor(); len(got) == 0 {
			t.Fatal("Envelope.Descriptor() returned an empty descriptor")
		}
		switch env.Message.(type) {
		case *Envelope_RegisterRequest:
			if env.GetRegisterRequest() == nil {
				t.Fatal("GetRegisterRequest() returned nil")
			}
			env.Message.(*Envelope_RegisterRequest).isEnvelope_Message()
		case *Envelope_RegisterResponse:
			if env.GetRegisterResponse() == nil {
				t.Fatal("GetRegisterResponse() returned nil")
			}
			if len(env.GetRegisterResponse().GetHostnames()) != 1 {
				t.Fatal("GetHostnames() returned unexpected value")
			}
			env.Message.(*Envelope_RegisterResponse).isEnvelope_Message()
		case *Envelope_Heartbeat:
			if env.GetHeartbeat() == nil {
				t.Fatal("GetHeartbeat() returned nil")
			}
			env.Message.(*Envelope_Heartbeat).isEnvelope_Message()
		case *Envelope_HeartbeatAck:
			if env.GetHeartbeatAck() == nil {
				t.Fatal("GetHeartbeatAck() returned nil")
			}
			env.Message.(*Envelope_HeartbeatAck).isEnvelope_Message()
		case *Envelope_DrainNotice:
			if env.GetDrainNotice() == nil {
				t.Fatal("GetDrainNotice() returned nil")
			}
			env.Message.(*Envelope_DrainNotice).isEnvelope_Message()
		case *Envelope_Error:
			if env.GetError() == nil {
				t.Fatal("GetError() returned nil")
			}
			env.Message.(*Envelope_Error).isEnvelope_Message()
		}
	}
}

func checkProtoBasics(t *testing.T, msg protoCase) {
	t.Helper()

	if msg.String() == "" {
		t.Fatal("String() returned an empty value")
	}
	msg.ProtoMessage()
	if got, _ := msg.(interface{ Descriptor() ([]byte, []int) }).Descriptor(); len(got) == 0 {
		t.Fatal("Descriptor() returned an empty descriptor")
	}
	if msg.ProtoReflect().Descriptor().FullName() == "" {
		t.Fatal("ProtoReflect().Descriptor().FullName() returned an empty value")
	}
	wire, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	clone, ok := proto.Clone(msg).(protoCase)
	if !ok {
		t.Fatalf("Clone() type = %T, want protoCase", proto.Clone(msg))
	}
	if clone == nil {
		t.Fatal("Clone() returned nil")
	}
	clone.Reset()
	if _, err := proto.Marshal(clone); err != nil {
		t.Fatalf("Marshal(clone) error = %v, wire=%x", err, wire)
	}
}
