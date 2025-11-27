package dnspeek

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type dnsResolver struct {
	client      *dns.Client
	nameservers []string
	useTCP      bool
	timeout     time.Duration
}

func (r *dnsResolver) Nameservers() []string {
	out := make([]string, len(r.nameservers))
	copy(out, r.nameservers)
	return out
}

func NewResolver(
	domain string,
	nameservers []string,
	useTCP bool,
	timeout time.Duration,
) (*dnsResolver, error) {
	client := &dns.Client{
		Timeout: timeout,
		Net:     pickNetwork(useTCP),
	}

	nsList := sanitizeNS(nameservers)
	if len(nsList) == 0 {
		cfg, err := dns.ClientConfigFromFile(
			"/etc/resolv.conf",
		)
		if err != nil {
			return nil, fmt.Errorf(
				"load system resolvers: %w",
				err,
			)
		}
		for _, ns := range cfg.Servers {
			nsList = append(nsList, ensurePort(ns))
		}
	}

	res := &dnsResolver{
		client:      client,
		nameservers: nsList,
		useTCP:      useTCP,
		timeout:     timeout,
	}

	if len(nsList) == 0 {
		return nil, errors.New(
			"no nameservers available",
		)
	}

	// If we do not have custom NS and a domain was given, try its NS.
	if len(nameservers) == 0 && domain != "" {
		nsRecords, err := res.lookupNS(domain)
		if err == nil && len(nsRecords) > 0 {
			res.nameservers = []string{}
			for _, rec := range nsRecords {
				if rec.Address != "" {
					res.nameservers = append(
						res.nameservers,
						ensurePort(rec.Address),
					)
				}
			}
		}
	}

	return res, nil
}

func pickNetwork(useTCP bool) string {
	if useTCP {
		return "tcp"
	}
	return "udp"
}

func sanitizeNS(list []string) []string {
	var cleaned []string
	for _, ns := range list {
		ns = strings.TrimSpace(ns)
		if ns == "" {
			continue
		}
		cleaned = append(cleaned, ensurePort(ns))
	}
	return cleaned
}

func ensurePort(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]:53"
	}
	return host + ":53"
}

func (r *dnsResolver) query(
	msg *dns.Msg,
) (*dns.Msg, string, error) {
	var lastErr error

	for _, ns := range r.nameservers {
		resp, _, err := r.client.Exchange(
			msg,
			ns,
		)
		if err == nil && resp != nil {
			return resp, ns, nil
		}
		lastErr = err
	}

	if lastErr == nil {
		lastErr = errors.New(
			"no response from nameservers",
		)
	}
	return nil, "", lastErr
}

func (r *dnsResolver) lookupNS(
	domain string,
) ([]dnsRecord, error) {
	resp, _, err := r.simpleQuery(
		domain,
		dns.TypeNS,
		dns.ClassINET,
	)
	if err != nil {
		return nil, err
	}

	var records []dnsRecord
	for _, ans := range resp.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			records = append(
				records,
				dnsRecord{
					Type: "NS",
					Target: strings.TrimSuffix(
						ns.Ns,
						".",
					),
					Address: "",
					Name:    domain,
				},
			)
		}
	}
	return records, nil
}

func (r *dnsResolver) lookupSOA(
	domain string,
) ([]dnsRecord, error) {
	resp, _, err := r.simpleQuery(
		domain,
		dns.TypeSOA,
		dns.ClassINET,
	)
	if err != nil {
		return nil, err
	}

	var records []dnsRecord
	for _, ans := range resp.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			records = append(
				records,
				dnsRecord{
					Type: "SOA",
					Name: strings.TrimSuffix(
						soa.Hdr.Name,
						".",
					),
					Target: strings.TrimSuffix(
						soa.Ns,
						".",
					),
					Address: soa.Mbox,
				},
			)
		}
	}
	return records, nil
}

func (r *dnsResolver) lookupMX(
	domain string,
) ([]dnsRecord, error) {
	resp, _, err := r.simpleQuery(
		domain,
		dns.TypeMX,
		dns.ClassINET,
	)
	if err != nil {
		return nil, err
	}

	var records []dnsRecord
	for _, ans := range resp.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			records = append(
				records,
				dnsRecord{
					Type: "MX",
					Name: domain,
					Target: strings.TrimSuffix(
						mx.Mx,
						".",
					),
					Address: "",
					Port:    int(mx.Preference),
				},
			)
		}
	}
	return records, nil
}

func (r *dnsResolver) lookupA(
	host string,
) ([]dnsRecord, error) {
	resp, _, err := r.simpleQuery(
		host,
		dns.TypeA,
		dns.ClassINET,
	)
	if err != nil {
		return nil, err
	}

	var records []dnsRecord
	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			records = append(
				records,
				dnsRecord{
					Type:    "A",
					Name:    host,
					Address: rr.A.String(),
				},
			)
		case *dns.CNAME:
			records = append(
				records,
				dnsRecord{
					Type: "CNAME",
					Name: host,
					Target: strings.TrimSuffix(
						rr.Target,
						".",
					),
				},
			)
		}
	}
	return records, nil
}

func (r *dnsResolver) lookupAAAA(
	host string,
) ([]dnsRecord, error) {
	resp, _, err := r.simpleQuery(
		host,
		dns.TypeAAAA,
		dns.ClassINET,
	)
	if err != nil {
		return nil, err
	}

	var records []dnsRecord
	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.AAAA:
			records = append(
				records,
				dnsRecord{
					Type:    "AAAA",
					Name:    host,
					Address: rr.AAAA.String(),
				},
			)
		case *dns.CNAME:
			records = append(
				records,
				dnsRecord{
					Type: "CNAME",
					Name: host,
					Target: strings.TrimSuffix(
						rr.Target,
						".",
					),
				},
			)
		}
	}
	return records, nil
}

func (r *dnsResolver) lookupTXT(
	host string,
) ([]dnsRecord, error) {
	resp, _, err := r.simpleQuery(
		host,
		dns.TypeTXT,
		dns.ClassINET,
	)
	if err != nil {
		return nil, err
	}

	var records []dnsRecord
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			records = append(
				records,
				dnsRecord{
					Type: "TXT",
					Name: host,
					Text: strings.Join(
						txt.Txt,
						" ",
					),
				},
			)
		}
	}
	return records, nil
}

func (r *dnsResolver) lookupCAA(
	host string,
) ([]dnsRecord, error) {
	resp, _, err := r.simpleQuery(
		host,
		dns.TypeCAA,
		dns.ClassINET,
	)
	if err != nil {
		return nil, err
	}

	var records []dnsRecord
	for _, ans := range resp.Answer {
		if caa, ok := ans.(*dns.CAA); ok {
			rec := dnsRecord{
				Type: "CAA",
				Name: host,
				Text: caa.Value,
			}
			if caa.Tag != "" {
				rec.Target = caa.Tag
			}
			records = append(records, rec)
		}
	}
	return records, nil
}

func (r *dnsResolver) lookupSRV(
	name string,
) ([]dnsRecord, error) {
	resp, _, err := r.simpleQuery(
		name,
		dns.TypeSRV,
		dns.ClassINET,
	)
	if err != nil {
		return nil, err
	}

	var records []dnsRecord
	for _, ans := range resp.Answer {
		if srv, ok := ans.(*dns.SRV); ok {
			records = append(
				records,
				dnsRecord{
					Type: "SRV",
					Name: name,
					Target: strings.TrimSuffix(
						srv.Target,
						".",
					),
					Port: int(
						srv.Port,
					),
				},
			)
		}
	}
	return records, nil
}

func (r *dnsResolver) lookupPTR(
	ip string,
) ([]dnsRecord, error) {
	ptr, err := dns.ReverseAddr(ip)
	if err != nil {
		return nil, err
	}

	resp, _, err := r.simpleQuery(
		ptr,
		dns.TypePTR,
		dns.ClassINET,
	)
	if err != nil {
		return nil, err
	}

	var records []dnsRecord
	for _, ans := range resp.Answer {
		if rr, ok := ans.(*dns.PTR); ok {
			records = append(
				records,
				dnsRecord{
					Type: "PTR",
					Name: strings.TrimSuffix(
						rr.Ptr,
						".",
					),
					Address: ip,
				},
			)
		}
	}
	return records, nil
}

func (r *dnsResolver) simpleQuery(
	name string,
	qtype uint16,
	class uint16,
) (*dns.Msg, string, error) {
	msg := &dns.Msg{}
	msg.SetQuestion(
		dns.Fqdn(name),
		qtype,
	)
	msg.Question[0].Qclass = class
	msg.RecursionDesired = true
	return r.query(msg)
}

func (r *dnsResolver) zoneTransfer(
	domain string,
) ([]dnsRecord, error) {
	var results []dnsRecord
	var lastErr error

	for _, ns := range r.nameservers {
		m := new(dns.Msg)
		m.SetAxfr(dns.Fqdn(domain))

		t := &dns.Transfer{
			DialTimeout: r.timeout,
			ReadTimeout: r.timeout,
		}

		addr := ensurePort(ns)
		ch, err := t.In(m, addr)
		if err != nil {
			lastErr = err
			continue
		}

		for env := range ch {
			if env.Error != nil {
				lastErr = env.Error
				continue
			}
			for _, rr := range env.RR {
				rec := convertRR(rr)
				if rec != nil {
					rec.Domain = domain
					results = append(results, *rec)
				}
			}
		}

		if len(results) > 0 {
			return results, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New(
		"zone transfer failed",
	)
}

func convertRR(rr dns.RR) *dnsRecord {
	switch v := rr.(type) {
	case *dns.A:
		return &dnsRecord{
			Type:    "A",
			Name:    trimDot(v.Hdr.Name),
			Address: v.A.String(),
		}
	case *dns.AAAA:
		return &dnsRecord{
			Type:    "AAAA",
			Name:    trimDot(v.Hdr.Name),
			Address: v.AAAA.String(),
		}
	case *dns.CNAME:
		return &dnsRecord{
			Type:   "CNAME",
			Name:   trimDot(v.Hdr.Name),
			Target: trimDot(v.Target),
		}
	case *dns.NS:
		return &dnsRecord{
			Type:   "NS",
			Name:   trimDot(v.Hdr.Name),
			Target: trimDot(v.Ns),
		}
	case *dns.MX:
		return &dnsRecord{
			Type:   "MX",
			Name:   trimDot(v.Hdr.Name),
			Target: trimDot(v.Mx),
			Port:   int(v.Preference),
		}
	case *dns.SOA:
		return &dnsRecord{
			Type: "SOA",
			Name: trimDot(v.Hdr.Name),
			Target: trimDot(
				v.Ns,
			),
			Address: v.Mbox,
		}
	case *dns.TXT:
		return &dnsRecord{
			Type: "TXT",
			Name: trimDot(v.Hdr.Name),
			Text: strings.Join(
				v.Txt,
				" ",
			),
		}
	case *dns.SRV:
		return &dnsRecord{
			Type: "SRV",
			Name: trimDot(v.Hdr.Name),
			Target: trimDot(
				v.Target,
			),
			Port: int(
				v.Port,
			),
		}
	case *dns.CAA:
		return &dnsRecord{
			Type:   "CAA",
			Name:   trimDot(v.Hdr.Name),
			Target: v.Tag,
			Text:   v.Value,
		}
	case *dns.PTR:
		return &dnsRecord{
			Type: "PTR",
			Name: trimDot(v.Ptr),
		}
	default:
		return nil
	}
}

func trimDot(v string) string {
	return strings.TrimSuffix(v, ".")
}

func chooseNameserverFromSOA(
	domain string,
) string {
	res, err := NewResolver(
		"",
		nil,
		false,
		5*time.Second,
	)
	if err != nil {
		return ""
	}
	records, err := res.lookupSOA(domain)
	if err != nil {
		return ""
	}
	for _, rec := range records {
		if rec.Target != "" {
			return ensurePort(rec.Target)
		}
	}
	return ""
}

func EnvDataDir() string {
	if custom := os.Getenv("DNSPEEK_DATA"); custom != "" {
		return custom
	}
	return "data"
}
