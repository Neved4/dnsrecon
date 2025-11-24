package dnspeek

import (
	"fmt"
	"os"
	"strings"
)

type dnsRecord struct {
	Domain  string
	Type    string
	Name    string
	Address string
	Target  string
	Text    string
	Port    int
	Note    string
}

type Config struct {
	Domain         string
	Nameservers    []string
	RangeArg       string
	Dictionary     string
	ScanTypes      []string
	UseTCP         bool
	FilterWildcard bool
	IgnoreWildcard bool
	DoAXFR         bool
	DoSPF          bool
	DoZoneWalk     bool
	DoCAA          bool
	DoCacheSnoop   bool
	DoCRT          bool
	ThreadCount    int
	TimeoutSeconds float64
	NoColor        bool
}

const (
	colorReset = "\033[0m"
	colorGood  = "\033[38;5;151m"
	colorWarn  = "\033[38;5;215m"
	colorBad   = "\033[31m"
	colorDim   = "\033[2m"
	colorInfo  = "\033[36m"
)

var useColor = true

func SetColor(enable bool) {
	useColor = enable
}

func colorize(color, msg string) string {
	if !useColor {
		return msg
	}
	return color + msg + colorReset
}

func InfoLine(msg string) {
	fmt.Println(colorize(colorInfo, "[*] "+msg))
}

func GoodLine(msg string) {
	fmt.Println(colorize(colorGood, "[+] "+msg))
}

func WarnLine(msg string) {
	fmt.Println(colorize(colorWarn, "[!] "+msg))
}

func ErrLine(msg string) {
	fmt.Fprintln(os.Stderr, colorize(colorBad, "[x] "+msg))
}

func DimLine(msg string) {
	fmt.Println(colorize(colorDim, "    "+msg))
}

func JoinAndTrim(raw string) []string {
	parts := strings.Split(raw, ",")
	var cleaned []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			cleaned = append(cleaned, p)
		}
	}
	return cleaned
}

func ValidateFlags(cfg Config) error {
	needsDomain := []string{
		"std",
		"brt",
		"srv",
		"tld",
		"axfr",
		"zonewalk",
	}
	for _, t := range cfg.ScanTypes {
		if stringIn(needsDomain, t) && cfg.Domain == "" {
			return fmt.Errorf(
				"%s scan needs --domain",
				t,
			)
		}
		if t == "rvl" && cfg.RangeArg == "" {
			return fmt.Errorf(
				"rvl scan needs --range",
			)
		}
	}
	return nil
}

func stringIn(list []string, val string) bool {
	for _, v := range list {
		if v == val {
			return true
		}
	}
	return false
}
