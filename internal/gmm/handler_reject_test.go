package gmm

import (
	"bytes"
	"testing"

	"github.com/free5gc/openapi/models"
)

// #WNC PDU-DROP/REJECT
// TestSmfRejectN1Message checks that the AMF picks the PDU Session Establishment Reject out of the
// SMF's error answer to Create SM Context, and ignores an answer that carries no N1 message.
func TestSmfRejectN1Message(t *testing.T) {
	// The reject captured in the live test: EPD 0x2E, PDU session ID 7, PTI 4, message type 0xC3, cause 26.
	reject := []byte{46, 7, 4, 195, 26}

	cases := []struct {
		name        string
		errResponse *models.PostSmContextsError
		want        []byte
	}{
		{name: "no answer", errResponse: nil, want: nil},
		{name: "answer without N1 message", errResponse: &models.PostSmContextsError{}, want: nil},
		{
			name:        "answer with empty N1 message",
			errResponse: &models.PostSmContextsError{BinaryDataN1SmMessage: []byte{}},
			want:        nil,
		},
		{
			name: "answer with reject",
			errResponse: &models.PostSmContextsError{
				JsonData:              &models.SmContextCreateError{},
				BinaryDataN1SmMessage: reject,
			},
			want: reject,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := smfRejectN1Message(tc.errResponse)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("got %v, want nil", got)
				}
				return
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
