/*
 * AMF Configuration Factory
 */

package factory

import (
	"testing"

	"github.com/asaskevich/govalidator"
)

func TestSctp_validate(t *testing.T) {
	type fields struct {
		NumOstreams    uint
		MaxInstreams   uint
		MaxAttempts    uint
		MaxInitTimeout uint
	}
	tests := []struct {
		name    string
		fields  fields
		want    bool
		wantErr bool
		numErr  int
	}{
		// TODO: Add test cases.
		{
			name: "test OK -- Max",
			fields: fields{
				NumOstreams:    10,
				MaxInstreams:   10,
				MaxAttempts:    5,
				MaxInitTimeout: 5,
			},
			want:    true,
			wantErr: false,
			numErr:  0,
		},
		{
			name: "test OK -- Min",
			fields: fields{
				NumOstreams:    1,
				MaxInstreams:   1,
				MaxAttempts:    1,
				MaxInitTimeout: 1,
			},
			want:    true,
			wantErr: false,
			numErr:  0,
		},
		{
			name: "test Error -- zeros",
			fields: fields{
				NumOstreams:    0,
				MaxInstreams:   0,
				MaxAttempts:    0,
				MaxInitTimeout: 0,
			},
			want:    false,
			wantErr: true,
			numErr:  4,
		},
		{
			name: "test Error -- upperbound",
			fields: fields{
				NumOstreams:    11,
				MaxInstreams:   11,
				MaxAttempts:    6,
				MaxInitTimeout: 6,
			},
			want:    false,
			wantErr: true,
			numErr:  4,
		},
		{
			name: "test Error -- not set",
			fields: fields{
				MaxInstreams: 10,
			},
			want:    false,
			wantErr: true,
			numErr:  3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Sctp{
				NumOstreams:    tt.fields.NumOstreams,
				MaxInstreams:   tt.fields.MaxInstreams,
				MaxAttempts:    tt.fields.MaxAttempts,
				MaxInitTimeout: tt.fields.MaxInitTimeout,
			}
			got, err := n.validate()

			if (err != nil) != tt.wantErr {
				t.Errorf("Sctp.validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				var errs govalidator.Errors = err.(govalidator.Errors)
				if len(errs) != tt.numErr {
					t.Errorf("Sctp.validate() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
			if got != tt.want {
				t.Errorf("Sctp.validate() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAllowedNssaiModeHelpers verifies the [WNC] Allowed NSSAI mode helpers.
func TestAllowedNssaiModeHelpers(t *testing.T) {
	tests := []struct {
		mode         string
		onFallback   bool
		alwaysAllReq bool
	}{
		{mode: "", onFallback: false, alwaysAllReq: false},
		{mode: AllowedNssaiModeDefault, onFallback: false, alwaysAllReq: false},
		{mode: AllowedNssaiModeAllSubscribedNoReq, onFallback: true, alwaysAllReq: false},
		{mode: AllowedNssaiModeAllSubscribedAlways, onFallback: true, alwaysAllReq: true},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			c := &Configuration{AllowedNssaiMode: tt.mode}
			if got := c.AllowAllSubscribedNssaiOnFallback(); got != tt.onFallback {
				t.Errorf("AllowAllSubscribedNssaiOnFallback() = %v, want %v", got, tt.onFallback)
			}
			if got := c.AllowAllSubscribedNssaiAlways(); got != tt.alwaysAllReq {
				t.Errorf("AllowAllSubscribedNssaiAlways() = %v, want %v", got, tt.alwaysAllReq)
			}
		})
	}
}
