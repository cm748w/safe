package jsonx

import "testing"

type rec struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

func TestDecodeStrictJSONPasses(t *testing.T) {
	data := []byte(`[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1"}]`)
	var got []rec
	if err := Decode(data, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got) != 1 || got[0].Banner != "SSH-2.0-OpenSSH_8.9p1" {
		t.Fatalf("got %#v", got)
	}
}

func TestDecodeHexEscapes(t *testing.T) {
	// \xNN is non-standard JSON; Decode must rewrite it and still succeed.
	data := []byte(`[{"ip":"1.2.3.7","port":3306,"banner":"J\x00\x00\x00\n8.0.32\x00"}]`)
	var got []rec
	if err := Decode(data, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	want := []rec{{IP: "1.2.3.7", Port: 3306, Banner: "J\x00\x00\x00\n8.0.32\x00"}}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestDecodeInvalidStillErrors(t *testing.T) {
	data := []byte(`{"bad json`)
	var got []rec
	if err := Decode(data, &got); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
