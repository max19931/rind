package rind
import (
	"errors"
	"log"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)
type DNSServer interface {
	Listen()
	Query(Packet)
}
type DNSService struct {
	conn       *net.UDPConn
	book       store
	memo       addrBag
	forwarders []net.UDPAddr
}
type Packet struct {
	addr    net.UDPAddr
	message dnsmessage.Message
}
const (
	udpPort int = 53
	packetLen int = 512
)
var (
	errTypeNotSupport = errors.New("type not support")
	errIPInvalid      = errors.New("invalid IP address")
)
func (s *DNSService) Listen() {
	var err error
	s.conn, err = net.ListenUDP("udp", &net.UDPAddr{Port: udpPort})
	if err != nil {
		log.Fatal(err)
	}
	defer s.conn.Close()

	for {
		buf := make([]byte, packetLen)
		_, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			log.Println(err)
			continue
		}
		var m dnsmessage.Message
		err = m.Unpack(buf)
		if err != nil {
			log.Println(err)
			continue
		}
		if len(m.Questions) == 0 {
			continue
		}
		go s.Query(Packet{*addr, m})
	}
}
func (s *DNSService) Query(p Packet) {
	if p.message.Header.Response {
		pKey := pString(p)
		if addrs, ok := s.memo.get(pKey); ok {
			for _, addr := range addrs {
				go sendPacket(s.conn, p.message, addr)
			}
			s.memo.remove(pKey)
			go s.saveBulk(qString(p.message.Questions[0]), p.message.Answers)
		}
		return
	}
	q := p.message.Questions[0]
	val, ok := s.book.get(qString(q))
	if ok {
		p.message.Answers = append(p.message.Answers, val...)
		go sendPacket(s.conn, p.message, p.addr)
	} else {
		for i := 0; i < len(s.forwarders); i++ {
			s.memo.set(pString(p), p.addr)
			go sendPacket(s.conn, p.message, s.forwarders[i])
		}
	}
}
func sendPacket(conn *net.UDPConn, message dnsmessage.Message, addr net.UDPAddr) {
	packed, err := message.Pack()
	if err != nil {
		log.Println(err)
		return
	}

	_, err = conn.WriteToUDP(packed, &addr)
	if err != nil {
		log.Println(err)
	}
}
func New(rwDirPath string, forwarders []net.UDPAddr) DNSService {
	return DNSService{
		book:       store{data: make(map[string]entry), rwDirPath: rwDirPath},
		memo:       addrBag{data: make(map[string][]net.UDPAddr)},
		forwarders: forwarders,
	}
}
func Start(rwDirPath string, forwarders []net.UDPAddr) *DNSService {
	s := New(rwDirPath, forwarders)
	s.book.load()
	go s.Listen()

	return &s
}

func (s *DNSService) save(key string, resource dnsmessage.Resource, old *dnsmessage.Resource) bool {
	ok := s.book.set(key, resource, old)
	go s.book.save()

	return ok
}

func (s *DNSService) saveBulk(key string, resources []dnsmessage.Resource) {
	s.book.override(key, resources)
	go s.book.save()
}

func (s *DNSService) all() []get {
	book := s.book.clone()
	var recs []get
	for _, r := range book {
		for _, v := range r.Resources {
			body := v.Body.GoString()
			i := strings.Index(body, "{")
			recs = append(recs, get{
				Host: v.Header.Name.String(),
				TTL:  v.Header.TTL,
				Type: v.Header.Type.String()[4:],
				Data: body[i : len(body)-1], // get content within "{" and "}"
			})
		}
	}
	return recs
}

func (s *DNSService) remove(key string, r *dnsmessage.Resource) bool {
	ok := s.book.remove(key, r)
	if ok {
		go s.book.save()
	}
	return ok
}
func toResource(req request) (dnsmessage.Resource, error) {
	rName, err := dnsmessage.NewName(req.Host)
	none := dnsmessage.Resource{}
	if err != nil {
		return none, err
	}

	var rType dnsmessage.Type
	var rBody dnsmessage.ResourceBody

	switch req.Type {
	case "A":
		rType = dnsmessage.TypeA
		ip := net.ParseIP(req.Data)
		if ip == nil {
			return none, errIPInvalid
		}
		rBody = &dnsmessage.AResource{A: [4]byte{ip[12], ip[13], ip[14], ip[15]}}
	case "NS":
		rType = dnsmessage.TypeNS
		ns, err := dnsmessage.NewName(req.Data)
		if err != nil {
			return none, err
		}
		rBody = &dnsmessage.NSResource{NS: ns}
	case "CNAME":
		rType = dnsmessage.TypeCNAME
		cname, err := dnsmessage.NewName(req.Data)
		if err != nil {
			return none, err
		}
		rBody = &dnsmessage.CNAMEResource{CNAME: cname}
	case "AAAA":
		rType = dnsmessage.TypeAAAA
		ip := net.ParseIP(req.Data)
		if ip == nil {
			return none, errIPInvalid
		}
		var ipV6 [16]byte
		copy(ipV6[:], ip)
		rBody = &dnsmessage.AAAAResource{AAAA: ipV6}
	case "SRV":
		rType = dnsmessage.TypeSRV
		srv := req.SRV
		srvTarget, err := dnsmessage.NewName(srv.Target)
		if err != nil {
			return none, err
		}
		rBody = &dnsmessage.SRVResource{Priority: srv.Priority, Weight: srv.Weight, Port: srv.Port, Target: srvTarget}
	default:
		return none, errTypeNotSupport
	}

	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  rName,
			Type:  rType,
			Class: dnsmessage.ClassINET,
			TTL:   req.TTL,
		},
		Body: rBody,
	}, nil
}

func toRType(sType string) dnsmessage.Type {
	switch sType {
	case "A":
		return dnsmessage.TypeA
	case "NS":
		return dnsmessage.TypeNS
	case "CNAME":
		return dnsmessage.TypeCNAME
	case "AAAA":
		return dnsmessage.TypeAAAA
	case "SRV":
		return dnsmessage.TypeSRV
	default:
		return 0
	}
}

func toResourceHeader(name string, sType string) (h dnsmessage.ResourceHeader, err error) {
	h.Name, err = dnsmessage.NewName(name)
	if err != nil {
		return
	}
	h.Type = toRType(sType)
	return
}
