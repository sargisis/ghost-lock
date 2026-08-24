// Package watch: разбор netlink uevent-событий USB.
//
// Package watch: netlink uevent parsing for USB events.
package watch

import (
	"strings"
)

// Event — одно uevent-событие в виде «ключ -> значение».
//
// Event — a single uevent as key -> value pairs.
type Event map[string]string

// ParseUevent разбирает NUL-разделённый буфер uevent.
//
// ParseUevent parses a NUL-separated uevent buffer.
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

// AppleVendorID — USB vendor id Apple ("05ac", ведущий ноль отпадает при разборе).
//
// AppleVendorID — the Apple USB vendor ID ("05ac"; the leading zero is lost in parsing).
const AppleVendorID = "5ac"

// IsAppleDeviceAdd сообщает, что это «add»-событие USB-устройства Apple.
//
// IsAppleDeviceAdd reports whether this is an Apple USB device "add" event.
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

// IsIPhoneProduct проверяет строку PRODUCT (iPhone/iPad по подстроке).
//
// IsIPhoneProduct checks a PRODUCT string (iPhone/iPad by substring).
func IsIPhoneProduct(product string) bool {
	p := strings.ToLower(strings.TrimSpace(product))
	for _, model := range []string{"iphone", "ipad"} {
		if strings.Contains(p, model) {
			return true
		}
	}
	return false
}
