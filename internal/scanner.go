package dnspeek

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var srvRecords = []string{
	"_gc._tcp.",
	"_kerberos._tcp.",
	"_kerberos._udp.",
	"_ldap._tcp.",
	"_test._tcp.",
	"_sips._tcp.",
	"_sip._udp.",
	"_sip._tcp.",
	"_aix._tcp.",
	"_finger._tcp.",
	"_ftp._tcp.",
	"_http._tcp.",
	"_nntp._tcp.",
	"_telnet._tcp.",
	"_whois._tcp.",
	"_h323cs._tcp.",
	"_h323cs._udp.",
	"_h323be._tcp.",
	"_h323be._udp.",
	"_h323ls._tcp.",
	"_https._tcp.",
	"_h323ls._udp.",
	"_sipinternal._tcp.",
	"_sipinternaltls._tcp.",
	"_sip._tls.",
	"_sipfederationtls._tcp.",
	"_jabber._tcp.",
	"_xmpp-server._tcp.",
	"_xmpp-client._tcp.",
	"_imap._tcp.",
	"_certificates._tcp.",
	"_crls._tcp.",
	"_pgpkeys._tcp.",
	"_pgprevokations._tcp.",
	"_cmp._tcp.",
	"_svcp._tcp.",
	"_crl._tcp.",
	"_ocsp._tcp.",
	"_pkixrep._tcp.",
	"_smtp._tcp.",
	"_hkp._tcp.",
	"_hkps._tcp.",
	"_jabber._udp.",
	"_xmpp-server._udp.",
	"_xmpp-client._udp.",
	"_jabber-client._tcp.",
	"_jabber-client._udp.",
	"_kerberos.tcp.dc._msdcs.",
	"_ldap._tcp.forestdnszones.",
	"_ldap._tcp.dc._msdcs.",
	"_ldap._tcp.pdc._msdcs.",
	"_ldap._tcp.gc._msdcs.",
	"_kerberos._tcp.dc._msdcs.",
	"_kpasswd._tcp.",
	"_kpasswd._udp.",
	"_imaps._tcp.",
	"_submission._tcp.",
	"_pop3._tcp.",
	"_pop3s._tcp.",
	"_caldav._tcp.",
	"_caldavs._tcp.",
	"_carddav._tcp.",
	"_carddavs._tcp.",
	"_x-puppet._tcp.",
	"_x-puppet-ca._tcp.",
	"_autodiscover._tcp.",
}

func generateTestName(
	length int,
	suffix string,
) string {
	alphabet := "abcdefghijklmnopqrstuvwxyz0123456789"
	var b strings.Builder
	for i := 0; i < length; i++ {
		idx := time.Now().UnixNano() + int64(i)
		b.WriteByte(alphabet[idx%int64(len(alphabet))])
	}
	return b.String() + "." + suffix
}

func checkWildcard(
	res *dnsResolver,
	domain string,
) ([]string, error) {
	test := generateTestName(12, domain)
	records, err := res.lookupA(test)
	if err != nil || len(records) == 0 {
		return nil, err
	}

	var ips []string
	for _, rec := range records {
		if rec.Address != "" {
			ips = append(ips, rec.Address)
		}
	}

	if len(ips) > 0 {
		GoodLine(
			"Wildcard DNS detected; random names resolve too.",
		)
	}
	return ips, nil
}

func checkNxDomainHijack(
	nameserver string,
	timeout time.Duration,
) ([]string, error) {
	tmp, err := NewResolver(
		"",
		[]string{nameserver},
		true,
		timeout,
	)
	if err != nil {
		return nil, err
	}
	test := generateTestName(20, "com")

	var hits []string
	for _, q := range []func(string) ([]dnsRecord, error){
		tmp.lookupA,
		tmp.lookupAAAA,
	} {
		recs, err := q(test)
		if err != nil {
			continue
		}
		for _, rec := range recs {
			if rec.Target != "" {
				hits = append(hits, rec.Target)
			} else if rec.Address != "" {
				hits = append(hits, rec.Address)
			}
		}
	}
	return hits, nil
}

func parseRangeArg(
	arg string,
) ([]string, error) {
	if strings.Contains(arg, "/") {
		_, netv, err := net.ParseCIDR(arg)
		if err != nil {
			return nil, err
		}
		var ips []string
		for ip := netv.IP.Mask(netv.Mask); netv.Contains(ip); ip = nextIP(ip) {
			ips = append(ips, ip.String())
		}
		if len(ips) > 0 {
			ips = ips[1 : len(ips)-1]
		}
		return ips, nil
	}

	if strings.Contains(arg, "-") {
		parts := strings.Split(arg, "-")
		if len(parts) != 2 {
			return nil, errors.New(
				"range must be start-end",
			)
		}
		return expandRange(
			parts[0],
			parts[1],
		)
	}

	if net.ParseIP(arg) != nil {
		return []string{arg}, nil
	}
	return nil, errors.New("invalid range")
}

func expandRange(
	start string,
	end string,
) ([]string, error) {
	startIP := net.ParseIP(start)
	endIP := net.ParseIP(end)
	if startIP == nil || endIP == nil {
		return nil, errors.New(
			"range values must be IPs",
		)
	}
	var ips []string
	for ip := startIP; !ip.Equal(endIP); ip = nextIP(ip) {
		ips = append(ips, ip.String())
	}
	ips = append(ips, endIP.String())
	return ips, nil
}

func nextIP(
	ip net.IP,
) net.IP {
	ip = ip.To16()
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func BruteDomain(
	res *dnsResolver,
	dictPath string,
	domain string,
	filter bool,
	ignoreWildcard bool,
	threads int,
) ([]dnsRecord, error) {
	wildIPs, _ := checkWildcard(res, domain)
	if len(wildIPs) > 0 && !ignoreWildcard {
		WarnLine(
			"Wildcard DNS may mask results. Continue? [y/N]",
		)
		if !promptYes() {
			return nil, errors.New(
				"bruteforce cancelled",
			)
		}
	}

	words, err := loadWordlist(dictPath)
	if err != nil {
		return nil, err
	}

	targets := make(chan string)
	results := make(chan []dnsRecord)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for host := range targets {
			recs := resolveHost(res, host)
			var filtered []dnsRecord
			for _, rec := range recs {
				if filter && contains(wildIPs, rec.Address) {
					continue
				}
				rec.Domain = domain
				filtered = append(filtered, rec)
			}
			if len(filtered) > 0 {
				results <- filtered
			}
		}
	}

	if threads < 1 {
		threads = 10
	}

	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go worker()
	}

	go func() {
		for _, word := range words {
			targets <- word + "." + domain
		}
		close(targets)
	}()

	var found []dnsRecord
	done := make(chan struct{})
	go func() {
		for recs := range results {
			for _, rec := range recs {
				GoodLine(
					fmt.Sprintf(
						"%s %s",
						rec.Type,
						renderRecord(rec),
					),
				)
				found = append(found, rec)
			}
		}
		close(done)
	}()

	wg.Wait()
	close(results)
	<-done

	InfoLine(
		fmt.Sprintf(
			"found %d records",
			len(found),
		),
	)
	return found, nil
}

func resolveHost(
	res *dnsResolver,
	host string,
) []dnsRecord {
	var recs []dnsRecord

	a, err := res.lookupA(host)
	if err == nil {
		recs = append(recs, a...)
	}
	aaaa, err := res.lookupAAAA(host)
	if err == nil {
		recs = append(recs, aaaa...)
	}
	if len(recs) == 0 {
		if net.ParseIP(host) == nil {
			ips, err := net.LookupIP(host)
			if err == nil {
				for _, ip := range ips {
					rec := dnsRecord{
						Type:    ipType(ip),
						Name:    host,
						Address: ip.String(),
					}
					recs = append(recs, rec)
				}
			}
		}
	}
	return dedupeRecords(recs)
}

func ipType(
	ip net.IP,
) string {
	if ip.To4() != nil {
		return "A"
	}
	return "AAAA"
}

func dedupeRecords(
	recs []dnsRecord,
) []dnsRecord {
	seen := map[string]bool{}
	var cleaned []dnsRecord
	for _, rec := range recs {
		key := fmt.Sprintf(
			"%s|%s|%s",
			rec.Type,
			rec.Name,
			rec.Address+rec.Target,
		)
		if seen[key] {
			continue
		}
		seen[key] = true
		cleaned = append(cleaned, rec)
	}
	return cleaned
}

func BruteReverse(
	res *dnsResolver,
	ips []string,
	threads int,
) ([]dnsRecord, error) {
	if threads < 1 {
		threads = 20
	}

	targets := make(chan string)
	results := make(chan []dnsRecord)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for ip := range targets {
			recs, err := res.lookupPTR(ip)
			if err == nil && len(recs) > 0 {
				results <- recs
			}
		}
	}

	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go worker()
	}

	go func() {
		for _, ip := range ips {
			targets <- ip
		}
		close(targets)
	}()

	var found []dnsRecord
	done := make(chan struct{})
	go func() {
		for recs := range results {
			for _, rec := range recs {
				GoodLine(
					fmt.Sprintf(
						"%s %s",
						rec.Type,
						renderRecord(rec),
					),
				)
				found = append(found, rec)
			}
		}
		close(done)
	}()

	wg.Wait()
	close(results)
	<-done

	InfoLine(
		fmt.Sprintf(
			"reverse lookups complete (%d hits)",
			len(found),
		),
	)
	return found, nil
}

func BruteSrv(
	res *dnsResolver,
	domain string,
	threads int,
) ([]dnsRecord, error) {
	if threads < 1 {
		threads = 15
	}

	targets := make(chan string)
	results := make(chan []dnsRecord)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for srv := range targets {
			recs, err := res.lookupSRV(srv)
			if err == nil && len(recs) > 0 {
				results <- recs
			}
		}
	}

	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go worker()
	}

	go func() {
		for _, srv := range srvRecords {
			targets <- srv + domain
		}
		close(targets)
	}()

	var found []dnsRecord
	done := make(chan struct{})
	go func() {
		for recs := range results {
			for _, rec := range recs {
				rec.Domain = domain
				GoodLine(
					fmt.Sprintf(
						"%s %s",
						rec.Type,
						renderRecord(rec),
					),
				)
				found = append(found, rec)
			}
		}
		close(done)
	}()

	wg.Wait()
	close(results)
	<-done

	InfoLine(
		fmt.Sprintf(
			"found %d SRV records",
			len(found),
		),
	)
	return found, nil
}

func BruteTLDs(
	res *dnsResolver,
	domain string,
	threads int,
) ([]dnsRecord, error) {
	tlds, err := fetchTLDs()
	if err != nil {
		return nil, err
	}

	if threads < 1 {
		threads = 15
	}

	targets := make(chan string)
	results := make(chan []dnsRecord)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for host := range targets {
			recs := resolveHost(res, host)
			if len(recs) > 0 {
				results <- recs
			}
		}
	}

	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go worker()
	}

	go func() {
		for _, tld := range tlds {
			targets <- domain + "." + tld
		}
		close(targets)
	}()

	var found []dnsRecord
	done := make(chan struct{})
	go func() {
		for recs := range results {
			for _, rec := range recs {
				rec.Domain = domain
				GoodLine(
					fmt.Sprintf(
						"%s %s",
						rec.Type,
						renderRecord(rec),
					),
				)
				found = append(found, rec)
			}
		}
		close(done)
	}()

	wg.Wait()
	close(results)
	<-done

	InfoLine(
		fmt.Sprintf(
			"found %d TLD hits",
			len(found),
		),
	)
	return found, nil
}

func fetchTLDs() ([]string, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	resp, err := client.Get(
		"https://publicsuffix.org/list/public_suffix_list.dat",
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tlds []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.Contains(line, " ") {
			continue
		}
		tlds = append(tlds, line)
		if len(tlds) >= 400 {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return tlds, nil
}

func GeneralEnum(
	res *dnsResolver,
	domain string,
	flags Config,
) ([]dnsRecord, error) {
	var results []dnsRecord

	wildIPs, _ := checkWildcard(res, domain)
	if len(wildIPs) == 0 {
		InfoLine("No wildcard DNS detected.")
	}

	if flags.DoAXFR {
		InfoLine("Trying zone transfer...")
		zt, err := res.zoneTransfer(domain)
		if err == nil && len(zt) > 0 {
			GoodLine("Zone transfer worked!")
			for _, rec := range zt {
				rec.Domain = domain
				results = append(results, rec)
			}
			return results, nil
		}
	}

	soa, err := res.lookupSOA(domain)
	if err == nil {
		for _, rec := range soa {
			rec.Domain = domain
			GoodLine(
				fmt.Sprintf(
					"%s %s",
					rec.Type,
					renderRecord(rec),
				),
			)
			results = append(results, rec)
		}
	}

	nsRecords, err := res.lookupNS(domain)
	if err == nil {
		for _, rec := range nsRecords {
			rec.Domain = domain
			rec.Note = ""
			nsHost := rec.Target
			if nsHost == "" {
				nsHost = rec.Address
			}
			ns := ensurePort(nsHost)
			if flags.DoCacheSnoop {
				if hits, _ := checkNxDomainHijack(
					ns,
					res.timeout,
				); len(hits) > 0 {
					rec.Note = "nxdomain-hijack"
				}
			}
			if isRec, _ := checkRecursive(ns, res.timeout); isRec {
				rec.Note = rec.Note + " recursion"
			}
			if ver := checkBindVersion(ns, res.timeout); ver != "" {
				rec.Note = strings.TrimSpace(
					rec.Note + " bind:" + ver,
				)
			}
			GoodLine(
				fmt.Sprintf(
					"%s %s",
					rec.Type,
					renderRecord(rec),
				),
			)
			results = append(results, rec)
		}
	}

	hostRecords := resolveHost(res, domain)
	for _, rec := range hostRecords {
		rec.Domain = domain
		GoodLine(
			fmt.Sprintf(
				"%s %s",
				rec.Type,
				renderRecord(rec),
			),
		)
		results = append(results, rec)
	}

	mx, err := res.lookupMX(domain)
	if err == nil {
		for _, rec := range mx {
			rec.Domain = domain
			GoodLine(
				fmt.Sprintf(
					"%s %s",
					rec.Type,
					renderRecord(rec),
				),
			)
			results = append(results, rec)
		}
	}

	txt, _ := res.lookupTXT(domain)
	if len(txt) > 0 {
		for _, rec := range txt {
			rec.Domain = domain
			GoodLine(
				fmt.Sprintf(
					"%s %s",
					rec.Type,
					renderRecord(rec),
				),
			)
			results = append(results, rec)
		}
	}

	if flags.DoSPF {
		spfRanges, err := processSPF(res, domain)
		if err == nil && len(spfRanges) > 0 {
			InfoLine("Reversing SPF ranges...")
			rv, _ := BruteReverse(
				res,
				spfRanges,
				flags.ThreadCount,
			)
			results = append(results, rv...)
		}
	}

	if flags.DoCAA {
		caa, _ := res.lookupCAA(domain)
		for _, rec := range caa {
			rec.Domain = domain
			GoodLine(
				fmt.Sprintf(
					"%s %s",
					rec.Type,
					renderRecord(rec),
				),
			)
			results = append(results, rec)
		}
	}

	if flags.DoCRT {
		InfoLine("Scraping crt.sh for names...")
		names, err := searchCRT(domain)
		if err == nil {
			crtRes := seResultProcess(
				res,
				domain,
				names,
			)
			results = append(results, crtRes...)
		} else {
			ErrLine(err.Error())
		}
	}

	srv, _ := BruteSrv(res, domain, flags.ThreadCount)
	results = append(results, srv...)

	if flags.DoZoneWalk {
		zw, err := ZoneWalk(res, domain, flags.TimeoutSeconds)
		if err == nil {
			results = append(results, zw...)
		} else {
			ErrLine(err.Error())
		}
	}

	InfoLine(
		fmt.Sprintf(
			"enumeration finished (%d records)",
			len(results),
		),
	)
	return results, nil
}

func seResultProcess(
	res *dnsResolver,
	domain string,
	entries []string,
) []dnsRecord {
	var records []dnsRecord
	for _, entry := range entries {
		recs := resolveHost(res, entry)
		for _, rec := range recs {
			rec.Domain = domain
			rec.Name = entry
			records = append(records, rec)
			GoodLine(
				fmt.Sprintf(
					"%s %s",
					rec.Type,
					renderRecord(rec),
				),
			)
		}
	}
	return records
}

func processSPF(
	res *dnsResolver,
	domain string,
) ([]string, error) {
	txt, err := res.lookupTXT(domain)
	if err != nil {
		return nil, err
	}
	var spfStrings []string
	for _, rec := range txt {
		if strings.Contains(
			strings.ToLower(rec.Text),
			"v=spf",
		) {
			spfStrings = append(spfStrings, rec.Text)
		}
	}
	if len(spfStrings) == 0 {
		return nil, nil
	}

	ip4Pattern := regexp.MustCompile(`ip4:([^\s]+)`)
	ip6Pattern := regexp.MustCompile(`ip6:([^\s]+)`)
	incPattern := regexp.MustCompile(`include:([^\s]+)`)

	var ips []string
	for _, spf := range spfStrings {
		for _, v := range ip4Pattern.FindAllStringSubmatch(
			spf,
			-1,
		) {
			ips = append(ips, v[1])
		}
		for _, v := range ip6Pattern.FindAllStringSubmatch(
			spf,
			-1,
		) {
			ips = append(ips, v[1])
		}
		for _, inc := range incPattern.FindAllStringSubmatch(
			spf,
			-1,
		) {
			incTxt, _ := res.lookupTXT(inc[1])
			for _, rec := range incTxt {
				ips = append(
					ips,
					strings.Fields(rec.Text)...,
				)
			}
		}
	}

	var ranges []string
	for _, entry := range ips {
		if strings.HasPrefix(entry, "ip4:") {
			entry = strings.TrimPrefix(entry, "ip4:")
		}
		if strings.HasPrefix(entry, "ip6:") {
			entry = strings.TrimPrefix(entry, "ip6:")
		}
		if strings.Contains(entry, "/") {
			list, err := parseRangeArg(entry)
			if err == nil {
				ranges = append(ranges, list...)
			}
			continue
		}
		if net.ParseIP(entry) != nil {
			ranges = append(ranges, entry)
		}
	}

	return uniqueStrings(ranges), nil
}

func checkBindVersion(
	nameserver string,
	timeout time.Duration,
) string {
	res, err := NewResolver(
		"",
		[]string{nameserver},
		false,
		timeout,
	)
	if err != nil {
		return ""
	}
	msg := new(dns.Msg)
	msg.SetQuestion("version.bind.", dns.TypeTXT)
	msg.Question[0].Qclass = dns.ClassCHAOS
	msg.RecursionDesired = false
	resp, _, err := res.query(msg)
	if err != nil || resp == nil {
		return ""
	}
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			return strings.Join(
				txt.Txt,
				" ",
			)
		}
	}
	return ""
}

func checkRecursive(
	nameserver string,
	timeout time.Duration,
) (bool, error) {
	res, err := NewResolver(
		"",
		[]string{nameserver},
		false,
		timeout,
	)
	if err != nil {
		return false, err
	}
	msg := new(dns.Msg)
	msg.SetQuestion("www.google.com.", dns.TypeNS)
	msg.RecursionDesired = true
	resp, _, err := res.query(msg)
	if err != nil || resp == nil {
		return false, err
	}
	return resp.MsgHdr.RecursionAvailable, nil
}

func CacheSnoop(
	ns string,
	dictFile string,
	timeout time.Duration,
) ([]dnsRecord, error) {
	res, err := NewResolver(
		"",
		[]string{ns},
		false,
		timeout,
	)
	if err != nil {
		return nil, err
	}

	fd, err := os.Open(dictFile)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	var hits []dnsRecord
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		host := scanner.Text()
		msg := new(dns.Msg)
		msg.SetQuestion(
			dns.Fqdn(host),
			dns.TypeA,
		)
		msg.RecursionDesired = false
		resp, _, err := res.query(msg)
		if err != nil {
			continue
		}
		for _, ans := range resp.Answer {
			rec := convertRR(ans)
			if rec != nil {
				rec.Domain = host
				hits = append(hits, *rec)
				GoodLine(
					fmt.Sprintf(
						"%s cached on %s",
						host,
						ns,
					),
				)
			}
		}
	}
	return hits, scanner.Err()
}

func ZoneWalk(
	res *dnsResolver,
	domain string,
	timeoutSeconds float64,
) ([]dnsRecord, error) {
	ns := chooseNameserverFromSOA(domain)
	if ns != "" {
		tmp, err := NewResolver(
			domain,
			[]string{ns},
			res.useTCP,
			time.Duration(
				timeoutSeconds*float64(
					time.Second,
				),
			),
		)
		if err == nil {
			res = tmp
		}
	}

	host := domain
	seen := map[string]bool{}
	var found []dnsRecord

	for i := 0; i < 256; i++ {
		next, err := nextNSEC(res, host)
		if err != nil || next == "" {
			break
		}
		if seen[next] {
			break
		}
		seen[next] = true
		host = next

		recs := resolveHost(res, host)
		for _, rec := range recs {
			rec.Domain = domain
			found = append(found, rec)
			GoodLine(
				fmt.Sprintf(
					"NSEC -> %s",
					renderRecord(rec),
				),
			)
		}
	}

	if len(found) == 0 {
		return nil, errors.New(
			"no NSEC data exposed",
		)
	}
	return found, nil
}

func nextNSEC(
	res *dnsResolver,
	host string,
) (string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(
		dns.Fqdn(host),
		dns.TypeA,
	)
	msg.SetEdns0(4096, true)
	resp, _, err := res.query(msg)
	if err != nil || resp == nil {
		return "", err
	}
	for _, sec := range resp.Ns {
		if nsec, ok := sec.(*dns.NSEC); ok {
			return strings.TrimSuffix(
				nsec.NextDomain,
				".",
			), nil
		}
	}
	return "", nil
}

func searchCRT(
	domain string,
) ([]string, error) {
	client := &http.Client{
		Timeout: 12 * time.Second,
	}
	u := "https://crt.sh/"
	q := url.Values{}
	q.Set("q", domain)
	q.Set("output", "json")
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		u+"?"+q.Encode(),
		nil,
	)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var payload []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(
		&payload,
	); err != nil {
		return nil, err
	}

	var names []string
	for _, row := range payload {
		if v, ok := row["name_value"].(string); ok {
			parts := strings.Split(v, "\n")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(p, "*.") {
					continue
				}
				if p != "" {
					names = append(names, p)
				}
			}
		}
	}
	return uniqueStrings(names), nil
}

func loadWordlist(path string) ([]string, error) {
	if !filepath.IsAbs(path) &&
		!strings.Contains(path, string(os.PathSeparator)) {
		path = filepath.Join(EnvDataDir(), path)
	}
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	var words []string
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		w := strings.TrimSpace(scanner.Text())
		if w != "" {
			words = append(words, w)
		}
	}
	return words, scanner.Err()
}

func uniqueStrings(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range items {
		if v == "" {
			continue
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func contains(
	list []string,
	val string,
) bool {
	for _, v := range list {
		if v == val {
			return true
		}
	}
	return false
}

func promptYes() bool {
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(strings.ToLower(text))
	return text == "y" || text == "yes"
}

func renderRecord(rec dnsRecord) string {
	parts := []string{}
	if rec.Name != "" {
		parts = append(parts, rec.Name)
	}
	if rec.Target != "" {
		parts = append(parts, "-> "+rec.Target)
	}
	if rec.Address != "" {
		parts = append(parts, rec.Address)
	}
	if rec.Port != 0 {
		parts = append(
			parts,
			fmt.Sprintf(
				"port %d",
				rec.Port,
			),
		)
	}
	if rec.Text != "" && rec.Type == "TXT" {
		parts = append(parts, rec.Text)
	}
	if rec.Note != "" {
		parts = append(
			parts,
			"["+rec.Note+"]",
		)
	}
	return strings.Join(parts, " ")
}

func ParseRangeList(
	raw string,
) ([]string, error) {
	var ips []string
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		list, err := parseRangeArg(entry)
		if err != nil {
			return nil, err
		}
		ips = append(ips, list...)
	}
	return ips, nil
}
