package netem

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Scenario represents network degradation parameters according to Table 8.
type Scenario struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	PacketLoss float64 `json:"packet_loss_percent"`
	RateLimit  float64 `json:"rate_limit_mbps"`
	AddedDelay float64 `json:"added_delay_ms"`
}

var DefaultScenarios = map[string]Scenario{
	"B0": {ID: "B0", Name: "Control Baseline", PacketLoss: 0.0, RateLimit: 0.0, AddedDelay: 0.0},
	"B1": {ID: "B1", Name: "Light Packet Loss", PacketLoss: 10.0, RateLimit: 0.0, AddedDelay: 0.0},
	"B2": {ID: "B2", Name: "Heavy Packet Loss", PacketLoss: 40.0, RateLimit: 0.0, AddedDelay: 0.0},
	"B3": {ID: "B3", Name: "Rate Limited", PacketLoss: 0.0, RateLimit: 1.0, AddedDelay: 0.0},
	"B4": {ID: "B4", Name: "High Delay", PacketLoss: 0.0, RateLimit: 0.0, AddedDelay: 100.0},
	"B5": {ID: "B5", Name: "Combined Degradation", PacketLoss: 10.0, RateLimit: 1.0, AddedDelay: 100.0},
}

// Controller manages Linux traffic control (tc netem) qdiscs.
type Controller struct {
	Interface string
	UseSudo   bool
}

// NewController creates a new Controller for the given network interface.
func NewController(iface string, useSudo bool) *Controller {
	if iface == "" {
		iface = "lo"
	}
	return &Controller{
		Interface: iface,
		UseSudo:   useSudo,
	}
}

func (c *Controller) runTC(args ...string) (string, error) {
	cmdName := "tc"
	var cmdArgs []string

	if c.UseSudo {
		cmdName = "sudo"
		cmdArgs = append([]string{"-n", "tc"}, args...)
	} else {
		cmdArgs = args
	}

	cmd := exec.Command(cmdName, cmdArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("tc command failed (%s %s): %s %w", cmdName, strings.Join(cmdArgs, " "), stderr.String(), err)
	}
	return stdout.String(), nil
}

// Clear removes all active root qdisc rules on the configured interface.
func (c *Controller) Clear() error {
	// Attempt delete root qdisc. Ignore "Cannot delete qdisc with handle of zero" or "No such file or directory"
	_, err := c.runTC("qdisc", "del", "dev", c.Interface, "root")
	if err != nil {
		out := err.Error()
		if strings.Contains(out, "No such file or directory") || strings.Contains(out, "Cannot delete qdisc with handle of zero") {
			return nil
		}
		// Try replace with noop or return error
		return nil
	}
	return nil
}

// Apply sets up tc netem qdisc matching the specified Scenario.
func (c *Controller) Apply(sc Scenario) error {
	// Always clear existing qdisc first
	_ = c.Clear()

	if sc.ID == "B0" || (sc.PacketLoss == 0 && sc.RateLimit == 0 && sc.AddedDelay == 0) {
		// B0 requires no emulation rules
		return nil
	}

	args := []string{"qdisc", "add", "dev", c.Interface, "root", "netem"}

	if sc.AddedDelay > 0 {
		args = append(args, "delay", fmt.Sprintf("%.1fms", sc.AddedDelay))
	}
	if sc.PacketLoss > 0 {
		args = append(args, "loss", fmt.Sprintf("%.1f%%", sc.PacketLoss))
	}
	if sc.RateLimit > 0 {
		args = append(args, "rate", fmt.Sprintf("%.2fmbit", sc.RateLimit))
	}

	_, err := c.runTC(args...)
	if err != nil {
		return fmt.Errorf("failed to apply netem scenario %s: %w", sc.ID, err)
	}
	return nil
}

// Status returns current tc qdisc state on the configured interface.
func (c *Controller) Status() (string, error) {
	out, err := c.runTC("qdisc", "show", "dev", c.Interface)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// scenarioIDMap maps lowercase runner scenario IDs to the uppercase DefaultScenarios keys.
var scenarioIDMap = map[string]string{
	"b0-baseline":      "B0",
	"b1-loss1":         "B1",
	"b2-loss5":         "B2",
	"b3-delay50":       "B3",
	"b4-delay50-loss1": "B4",
	"b5-rate1mbps":     "B5",
	// Also accept uppercase directly
	"B0": "B0",
	"B1": "B1",
	"B2": "B2",
	"B3": "B3",
	"B4": "B4",
	"B5": "B5",
}

// Apply is a package-level helper that applies a named scenario to iface using sudo.
// scenarioID may be a lowercase runner key (e.g. "b0-baseline") or uppercase (e.g. "B0").
func Apply(scenarioID string, iface string) error {
	key, ok := scenarioIDMap[scenarioID]
	if !ok {
		return fmt.Errorf("unknown scenario id: %q", scenarioID)
	}
	sc, ok := DefaultScenarios[key]
	if !ok {
		return fmt.Errorf("no default scenario for key %q", key)
	}
	ctrl := NewController(iface, true)
	return ctrl.Apply(sc)
}

// Reset removes all netem rules on iface using sudo.
func Reset(iface string) error {
	if iface == "" {
		return nil
	}
	ctrl := NewController(iface, true)
	return ctrl.Clear()
}
