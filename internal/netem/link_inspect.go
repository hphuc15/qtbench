package netem

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LinkInspection captures physical and RF layer attributes according to Table 3a.
type LinkInspection struct {
	Environment string   `json:"environment"` // "wired" or "wireless"
	Interface   string   `json:"interface"`
	IsConnected bool     `json:"is_connected"`
	SSID        string   `json:"ssid,omitempty"`
	FreqMHz     int      `json:"freq_mhz,omitempty"`
	Band        string   `json:"band,omitempty"` // "2.4 GHz", "5 GHz", etc.
	Channel     int      `json:"channel,omitempty"`
	WidthMHz    int      `json:"width_mhz,omitempty"`
	SignalRSSI  string   `json:"signal_rssi,omitempty"` // e.g. "-58 dBm"
	TxBitrate   string   `json:"tx_bitrate,omitempty"`  // e.g. "72.2 MBit/s"
	PowerSave   string   `json:"power_save,omitempty"`  // "OFF", "ON", "UNKNOWN"
	SpeedMbps   int      `json:"speed_mbps,omitempty"`  // Wired speed
	Duplex      string   `json:"duplex,omitempty"`      // "full", "half"
	LinkUp      bool     `json:"link_up,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	Infos       []string `json:"infos,omitempty"`
}

// InspectLinkLayer gathers layer 1/2 network details for iface matching envName ("wired" or "wireless").
func InspectLinkLayer(ctx context.Context, envName string, iface string) LinkInspection {
	res := LinkInspection{
		Environment: strings.ToLower(envName),
		Interface:   iface,
		PowerSave:   "UNKNOWN",
	}

	if iface == "" || iface == "any" {
		res.Infos = append(res.Infos, fmt.Sprintf("Interface set to %q, skipping specific link-layer checks.", iface))
		return res
	}

	switch res.Environment {
	case "wireless":
		inspectWireless(ctx, iface, &res)
	case "wired":
		inspectWired(ctx, iface, &res)
	}

	return res
}

func inspectWireless(ctx context.Context, iface string, res *LinkInspection) {
	// 1. iw dev <iface> link
	linkOut, err := runCmd(ctx, "iw", "dev", iface, "link")
	if err != nil || strings.Contains(linkOut, "Not connected") {
		res.IsConnected = false
		res.Warnings = append(res.Warnings, fmt.Sprintf("Wireless interface %s is not connected to any AP!", iface))
		return
	}
	res.IsConnected = true

	// Parse SSID
	if m := regexp.MustCompile(`SSID:\s*(.+)`).FindStringSubmatch(linkOut); len(m) > 1 {
		res.SSID = strings.TrimSpace(m[1])
	}

	// Parse freq
	if m := regexp.MustCompile(`freq:\s*(\d+)`).FindStringSubmatch(linkOut); len(m) > 1 {
		if f, err := strconv.Atoi(m[1]); err == nil {
			res.FreqMHz = f
			if f >= 2412 && f <= 2484 {
				res.Band = "2.4 GHz"
				if f == 2484 {
					res.Channel = 14
				} else {
					res.Channel = (f - 2407) / 5
				}
			} else if f >= 5000 && f <= 5900 {
				res.Band = "5 GHz"
				res.Channel = (f - 5000) / 5
				res.Warnings = append(res.Warnings, fmt.Sprintf("Operating on %s (%d MHz, Ch %d). Test plan specifies 2.4 GHz!", res.Band, res.FreqMHz, res.Channel))
			} else {
				res.Band = fmt.Sprintf("%d MHz", f)
			}
		}
	}

	// Parse signal
	if m := regexp.MustCompile(`signal:\s*(-?\d+\s*dBm)`).FindStringSubmatch(linkOut); len(m) > 1 {
		res.SignalRSSI = strings.TrimSpace(m[1])
		// Evaluate nominal RSSI range: -55 dBm to -65 dBm
		if numMatch := regexp.MustCompile(`-?\d+`).FindString(res.SignalRSSI); numMatch != "" {
			if rssiVal, err := strconv.Atoi(numMatch); err == nil {
				if rssiVal < -70 {
					res.Warnings = append(res.Warnings, fmt.Sprintf("RSSI is weak (%d dBm). Nominal test plan range is -55 dBm to -65 dBm.", rssiVal))
				} else if rssiVal > -45 {
					res.Infos = append(res.Infos, fmt.Sprintf("RSSI is very strong (%d dBm).", rssiVal))
				}
			}
		}
	}

	// Parse tx bitrate
	if m := regexp.MustCompile(`tx bitrate:\s*([^\n]+)`).FindStringSubmatch(linkOut); len(m) > 1 {
		res.TxBitrate = strings.TrimSpace(m[1])
	}

	// 2. iw dev <iface> info (for channel width)
	infoOut, _ := runCmd(ctx, "iw", "dev", iface, "info")
	if m := regexp.MustCompile(`width:\s*(\d+)\s*MHz`).FindStringSubmatch(infoOut); len(m) > 1 {
		if w, err := strconv.Atoi(m[1]); err == nil {
			res.WidthMHz = w
			if w > 20 {
				res.Warnings = append(res.Warnings, fmt.Sprintf("Channel width is %d MHz. Test plan specifies 20 MHz to avoid spectrum contention.", w))
			}
		}
	}

	// 3. iw dev <iface> get power_save
	psOut, _ := runCmd(ctx, "iw", "dev", iface, "get", "power_save")
	if strings.Contains(strings.ToLower(psOut), "power save: on") {
		res.PowerSave = "ON"
		res.Warnings = append(res.Warnings, fmt.Sprintf("Power Save is ON on %s! This causes artificial latency jitter. Run: sudo iw dev %s set power_save off", iface, iface))
	} else if strings.Contains(strings.ToLower(psOut), "power save: off") {
		res.PowerSave = "OFF"
	}
}

func inspectWired(ctx context.Context, iface string, res *LinkInspection) {
	sysBase := filepath.Join("/sys/class/net", iface)

	// Check operstate
	if operBytes, err := os.ReadFile(filepath.Join(sysBase, "operstate")); err == nil {
		state := strings.TrimSpace(string(operBytes))
		res.LinkUp = (state == "up")
		if !res.LinkUp {
			res.Warnings = append(res.Warnings, fmt.Sprintf("Wired interface %s operstate is %q (expected 'up')!", iface, state))
		}
	}

	// Check speed
	if speedBytes, err := os.ReadFile(filepath.Join(sysBase, "speed")); err == nil {
		if s, err := strconv.Atoi(strings.TrimSpace(string(speedBytes))); err == nil && s > 0 {
			res.SpeedMbps = s
			res.IsConnected = true
		}
	}

	// Check duplex
	if duplexBytes, err := os.ReadFile(filepath.Join(sysBase, "duplex")); err == nil {
		res.Duplex = strings.TrimSpace(string(duplexBytes))
		if res.Duplex != "full" && res.Duplex != "" {
			res.Warnings = append(res.Warnings, fmt.Sprintf("Wired link duplex is %q (expected 'full')!", res.Duplex))
		}
	}

	// Fallback to ethtool if sysfs speed is empty or negative
	if res.SpeedMbps <= 0 {
		ethtoolOut, err := runCmd(ctx, "ethtool", iface)
		if err == nil {
			if m := regexp.MustCompile(`Speed:\s*(\d+)Mb/s`).FindStringSubmatch(ethtoolOut); len(m) > 1 {
				res.SpeedMbps, _ = strconv.Atoi(m[1])
				res.IsConnected = true
			}
			if m := regexp.MustCompile(`Duplex:\s*(\w+)`).FindStringSubmatch(ethtoolOut); len(m) > 1 {
				res.Duplex = strings.ToLower(m[1])
			}
			if strings.Contains(ethtoolOut, "Link detected: yes") {
				res.LinkUp = true
			}
		}
	}

	if !res.IsConnected && !res.LinkUp {
		res.Warnings = append(res.Warnings, fmt.Sprintf("No active carrier/cable detected on wired interface %s!", iface))
	}
}

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String(), err
	}
	return stdout.String(), nil
}

// PrintBanner prints a structured, user-friendly report of the link layer configuration and warnings.
func (li *LinkInspection) PrintBanner() {
	var b strings.Builder
	sep := strings.Repeat("=", 78)
	subSep := strings.Repeat("-", 78)

	b.WriteByte('\n')
	b.WriteString(sep)
	b.WriteByte('\n')
	b.WriteString("             NETWORK LINK-LAYER CONFIGURATION CHECK (Table 3a)\n")
	b.WriteString(sep)
	b.WriteByte('\n')

	fmt.Fprintf(&b, "  Environment     : %s\n", strings.ToUpper(li.Environment))
	fmt.Fprintf(&b, "  Interface       : %s\n", li.Interface)

	switch li.Environment {
	case "wireless":
		if !li.IsConnected {
			b.WriteString("  Connection      : DISCONNECTED (No Wi-Fi AP association)\n")
		} else {
			if li.SSID != "" {
				fmt.Fprintf(&b, "  SSID            : %s\n", li.SSID)
			}
			if li.FreqMHz > 0 {
				fmt.Fprintf(&b, "  Frequency/Band  : %d MHz (%s, Channel %d)\n", li.FreqMHz, li.Band, li.Channel)
			}
			if li.WidthMHz > 0 {
				fmt.Fprintf(&b, "  Channel Width   : %d MHz\n", li.WidthMHz)
			}
			if li.SignalRSSI != "" {
				fmt.Fprintf(&b, "  Signal (RSSI)   : %s\n", li.SignalRSSI)
			}
			if li.TxBitrate != "" {
				fmt.Fprintf(&b, "  PHY Tx Bitrate  : %s\n", li.TxBitrate)
			}
			if li.PowerSave != "UNKNOWN" {
				fmt.Fprintf(&b, "  Power Save      : %s\n", li.PowerSave)
			}
		}
	case "wired":
		linkStatus := "DOWN"
		if li.LinkUp || li.IsConnected {
			linkStatus = "UP"
		}
		fmt.Fprintf(&b, "  Link Status     : %s\n", linkStatus)
		if li.SpeedMbps > 0 {
			fmt.Fprintf(&b, "  Speed           : %d Mbps\n", li.SpeedMbps)
		}
		if li.Duplex != "" {
			fmt.Fprintf(&b, "  Duplex          : %s\n", li.Duplex)
		}
	}

	b.WriteString(subSep)
	b.WriteByte('\n')

	if len(li.Warnings) == 0 {
		b.WriteString("  Status          : ALL PARAMETERS MATCH TEST PLAN SPECIFICATION\n")
	} else {
		b.WriteString("  [ATTENTION / WARNINGS DETECTED]:\n")
		for _, w := range li.Warnings {
			fmt.Fprintf(&b, "  ! %s\n", w)
		}
	}

	for _, info := range li.Infos {
		fmt.Fprintf(&b, "  * %s\n", info)
	}

	b.WriteString(sep)
	b.WriteString("\n\n")

	// Print to stdout
	scanner := bufio.NewScanner(strings.NewReader(b.String()))
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}
