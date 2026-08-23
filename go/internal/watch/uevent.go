package watch

import (
	"strings"
)

type Event map[string]string

func ParseUevent(raw string) Event {
	ev := Event{}
	for _, part := range strings.Split(raw, "\x00") {
		if part == "" {
			continue
		}
		if k, v, ok := strings.Cut(part, "="); ok {
			ev[k] = v
		} else {
			ev[part] = ""
		}
	}
	return ev
}

const AppleVendorID = "5ac"

func IsAppleDeviceAdd(ev Event) bool {
	if ev["ACTION"] != "add" {
		return false
	}
	if ev["SUBSYSTEM"] != "usb" {
		return false
	}
	if ev["DEVTYPE"] != "" && ev["DEVTYPE"] != "usb_device" {
		return false
	}
	product := strings.ToLower(ev["PRODUCT"])
	if product == "" {
		return false
	}
	vendor := strings.SplitN(product, "/", 2)[0]
	return vendor == AppleVendorID
}

func IsIPhoneProduct(product string) bool {
	p := strings.ToLower(strings.TrimSpace(product))
	for _, model := range []string{"iphone", "ipad"} {
		if strings.Contains(p, model) {
			return true
		}
	}
	return false
}
