package watch

import (
	"testing"
)

func TestParseUevent(t *testing.T) {
	raw := "ACTION=add\x00SUBSYSTEM=usb\x00DEVTYPE=usb_device\x00PRODUCT=5ac/12a8/1010\x00SEQNUM=4821"
	ev := ParseUevent(raw)
	if ev["ACTION"] != "add" || ev["SUBSYSTEM"] != "usb" {
		t.Fatalf("parse broken: %+v", ev)
	}
	if ev["PRODUCT"] != "5ac/12a8/1010" {
		t.Fatalf("product lost: %+v", ev)
	}
	if _, ok := ev["SEQNUM"]; !ok {
		t.Fatal("key without value must still exist")
	}
}

func TestIsAppleDeviceAdd(t *testing.T) {
	cases := []struct {
		name string
		ev   Event
		want bool
	}{
		{"iphone", Event{"ACTION": "add", "SUBSYSTEM": "usb", "DEVTYPE": "usb_device", "PRODUCT": "5ac/12a8/1010"}, true},
		{"apple keyboard", Event{"ACTION": "add", "SUBSYSTEM": "usb", "DEVTYPE": "usb_device", "PRODUCT": "5ac/024f/106"}, true},
		{"logitech mouse", Event{"ACTION": "add", "SUBSYSTEM": "usb", "DEVTYPE": "usb_device", "PRODUCT": "46d/c52b/1200"}, false},
		{"remove event", Event{"ACTION": "remove", "SUBSYSTEM": "usb", "DEVTYPE": "usb_device", "PRODUCT": "5ac/12a8/1010"}, false},
		{"not usb subsystem", Event{"ACTION": "add", "SUBSYSTEM": "block", "PRODUCT": "5ac/12a8/1010"}, false},
		{"interface not device", Event{"ACTION": "add", "SUBSYSTEM": "usb", "DEVTYPE": "usb_interface", "PRODUCT": "5ac/12a8/1010"}, false},
		{"empty product", Event{"ACTION": "add", "SUBSYSTEM": "usb"}, false},
	}
	for _, c := range cases {
		if got := IsAppleDeviceAdd(c.ev); got != c.want {
			t.Errorf("%s: want %v, got %v", c.name, c.want, got)
		}
	}
}

func TestIPhoneProduct(t *testing.T) {
	if !IsIPhoneProduct("iPhone") || IsIPhoneProduct("Magic Keyboard") {
		t.Fatal("model filter broken")
	}
}

func TestKernelStyleEventWithoutDevtype(t *testing.T) {
	ev := Event{"ACTION": "add", "SUBSYSTEM": "usb", "PRODUCT": "5ac/12a8/1010"}
	if !IsAppleDeviceAdd(ev) {
		t.Fatal("kernel uevents may omit DEVTYPE — should still match")
	}
}
