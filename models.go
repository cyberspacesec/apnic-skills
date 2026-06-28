package apnic

import "time"

// DelegatedEntry represents a single allocation/assignment record from the standard delegated stats file.
type DelegatedEntry struct {
	Registry   string
	Country    string
	Type       string // ipv4, ipv6, asn
	Start      string
	Value      int64
	Date       time.Time
	Status     string
	Extensions []string
}

// DelegatedExtendedEntry represents a single allocation/assignment record from the extended delegated stats file.
// It includes the OpaqueID field that uniquely identifies the resource holder organization.
type DelegatedExtendedEntry struct {
	Registry   string
	Country    string
	Type       string // ipv4, ipv6, asn
	Start      string
	Value      int64
	Date       time.Time
	Status     string // available, allocated, assigned, reserved
	OpaqueID   string // unique identifier for the organization
	Extensions []string
}

// AssignedEntry represents an aggregated assignment count by prefix size from the assigned stats file.
type AssignedEntry struct {
	Registry string
	Country  string
	Type     string // ipv4, ipv6
	Prefix   string // prefix size (e.g. "256", "512")
	Count    int64  // number of assignments of this prefix size
	Status   string
}

// LegacyEntry represents a historical (legacy) resource record from the legacy stats file.
type LegacyEntry struct {
	Registry string
	Country  string
	Type     string // ipv4, ipv6, asn
	Start    string
	Value    int64
	Date     time.Time
	Status   string
}

// TransferRecord represents a single IP/ASN transfer record.
type TransferRecord struct {
	TransferDate          time.Time
	Type                  string // RESOURCE_TRANSFER, INTER_RIR_TRANSFER
	SourceRIR             string
	RecipientRIR          string
	SourceOrganization    Organization
	RecipientOrganization Organization
	IPv4Nets              *TransferNetSet
	IPv6Nets              *TransferNetSet
	ASNs                  *TransferASNSet
}

// Organization represents an organization involved in a transfer.
type Organization struct {
	Name        string
	CountryCode string
}

// TransferNetSet represents a set of IP network ranges transferred.
type TransferNetSet struct {
	TransferSet []NetRange
}

// NetRange represents a range of IP addresses.
type NetRange struct {
	StartAddress string
	EndAddress   string
}

// TransferASNSet represents a set of ASN ranges transferred.
type TransferASNSet struct {
	TransferSet []ASNRange
}

// ASNRange represents a range of AS numbers.
type ASNRange struct {
	StartASN int64
	EndASN   int64
}

// ChangeRecord represents a single resource change record.
type ChangeRecord struct {
	Country   string
	Custodian string   // opaque-id
	Resources []string // CIDR or ASN values
	Status    string   // allocated, assigned
	Timestamp time.Time
	Type      string // delegated, cc-changed
}

// WhoisInfo represents parsed Whois response information.
type WhoisInfo struct {
	Network     string
	CIDR        []string
	Country     string
	OrgName     string
	Parent      string
	Created     time.Time
	LastUpdated time.Time
}

// StatsFileHeader represents the header line of a delegated stats file.
type StatsFileHeader struct {
	Version   string
	Registry  string
	Serial    int64
	Records   int64
	StartDate time.Time
	EndDate   time.Time
	UTCOffset int
}

// StatsSummary represents a summary line from a delegated stats file.
type StatsSummary struct {
	Registry string
	Type     string // asn, ipv4, ipv6
	Count    int64
}

// TransfersMetadata represents the metadata section of the transfers data.
type TransfersMetadata struct {
	Producer       string
	ProductionDate time.Time
	StatsVersion   string
	StartDate      time.Time
	EndDate        time.Time
}

// ChangesMetadata represents the metadata section of the changes data.
type ChangesMetadata struct {
	Count      int64
	StatsBegin string
	StatsEnd   string
	Timestamp  time.Time
	Version    string
}

// DelegatedResult represents the full result of parsing a delegated stats file,
// including header, summaries, and entries.
type DelegatedResult struct {
	Header    StatsFileHeader
	Summaries []StatsSummary
	Entries   []DelegatedEntry
}

// ExtendedResult represents the full result of parsing an extended delegated stats file.
type ExtendedResult struct {
	Header    StatsFileHeader
	Summaries []StatsSummary
	Entries   []DelegatedExtendedEntry
}

// AssignedResult represents the full result of parsing an assigned stats file.
type AssignedResult struct {
	Header    StatsFileHeader
	Summaries []StatsSummary
	Entries   []AssignedEntry
}

// LegacyResult represents the full result of parsing a legacy stats file.
type LegacyResult struct {
	Header    StatsFileHeader
	Summaries []StatsSummary
	Entries   []LegacyEntry
}

// TransfersResult represents the full result of parsing transfers data.
type TransfersResult struct {
	Metadata  TransfersMetadata
	Transfers []TransferRecord
}

// ChangesResult represents the full result of parsing changes data.
type ChangesResult struct {
	Metadata ChangesMetadata
	Changes  []ChangeRecord
}

// --- RDAP Models ---

// RDAPResponse represents the common fields in all RDAP responses.
type RDAPResponse struct {
	Conformance []string     `json:"rdapConformance"`
	Notices     []RDAPNotice `json:"notices,omitempty"`
	Links       []RDAPLink   `json:"links,omitempty"`
	Port43      string       `json:"port43,omitempty"`
}

// RDAPNetwork represents an RDAP IP network object.
type RDAPNetwork struct {
	RDAPResponse
	ObjectClassName string       `json:"objectClassName"`
	Handle          string       `json:"handle,omitempty"`
	StartAddress    string       `json:"startAddress,omitempty"`
	EndAddress      string       `json:"endAddress,omitempty"`
	IPVersion       string       `json:"ipVersion,omitempty"`
	Name            string       `json:"name,omitempty"`
	Country         string       `json:"country,omitempty"`
	Type            string       `json:"type,omitempty"`
	Status          []string     `json:"status,omitempty"`
	CIDR0CIDRs      []CIDR0      `json:"cidr0_cidrs,omitempty"`
	Entities        []RDAPEntity `json:"entities,omitempty"`
	Events          []RDAPEvent  `json:"events,omitempty"`
	Remarks         []RDAPRemark `json:"remarks,omitempty"`
	ParentHandle    string       `json:"parentHandle,omitempty"`
}

// RDAPAutnum represents an RDAP Autonomous System Number object.
type RDAPAutnum struct {
	RDAPResponse
	ObjectClassName string       `json:"objectClassName"`
	Handle          string       `json:"handle,omitempty"`
	StartAutnum     int64        `json:"startAutnum,omitempty"`
	EndAutnum       int64        `json:"endAutnum,omitempty"`
	Name            string       `json:"name,omitempty"`
	Type            string       `json:"type,omitempty"`
	Status          []string     `json:"status,omitempty"`
	Country         string       `json:"country,omitempty"`
	Entities        []RDAPEntity `json:"entities,omitempty"`
	Events          []RDAPEvent  `json:"events,omitempty"`
	Remarks         []RDAPRemark `json:"remarks,omitempty"`
}

// RDAPDomain represents an RDAP domain object (reverse DNS).
type RDAPDomain struct {
	RDAPResponse
	ObjectClassName string           `json:"objectClassName"`
	Handle          string           `json:"handle,omitempty"`
	LDHName         string           `json:"ldhName,omitempty"`
	Nameservers     []RDAPNameserver `json:"nameservers,omitempty"`
	Entities        []RDAPEntity     `json:"entities,omitempty"`
	Events          []RDAPEvent      `json:"events,omitempty"`
	Remarks         []RDAPRemark     `json:"remarks,omitempty"`
}

// RDAPEntity represents an RDAP entity (contact/organization) object.
type RDAPEntity struct {
	ObjectClassName string        `json:"objectClassName"`
	Handle          string        `json:"handle,omitempty"`
	Roles           []string      `json:"roles,omitempty"`
	Events          []RDAPEvent   `json:"events,omitempty"`
	Links           []RDAPLink    `json:"links,omitempty"`
	VcardArray      []interface{} `json:"vcardArray,omitempty"`
	Entities        []RDAPEntity  `json:"entities,omitempty"`
	Remarks         []RDAPRemark  `json:"remarks,omitempty"`
	Status          []string      `json:"status,omitempty"`
}

// RDAPSearchResult represents the result of an RDAP search query.
type RDAPSearchResult struct {
	RDAPResponse
	Results []interface{} `json:"results,omitempty"`
}

// RDAPNotice represents a notice in an RDAP response.
type RDAPNotice struct {
	Title       string     `json:"title,omitempty"`
	Description []string   `json:"description,omitempty"`
	Links       []RDAPLink `json:"links,omitempty"`
}

// RDAPLink represents a link in an RDAP response.
type RDAPLink struct {
	Value string `json:"value,omitempty"`
	Rel   string `json:"rel,omitempty"`
	Href  string `json:"href,omitempty"`
	Type  string `json:"type,omitempty"`
}

// RDAPEvent represents an event in an RDAP response.
type RDAPEvent struct {
	EventAction string `json:"eventAction,omitempty"`
	EventDate   string `json:"eventDate,omitempty"`
}

// RDAPRemark represents a remark in an RDAP response.
type RDAPRemark struct {
	Title       string   `json:"title,omitempty"`
	Description []string `json:"description,omitempty"`
}

// CIDR0 represents a CIDR0 notation entry in an RDAP response.
type CIDR0 struct {
	V4Prefix string `json:"v4prefix,omitempty"`
	V6Prefix string `json:"v6prefix,omitempty"`
	Length   int    `json:"length"`
}

// RDAPNameserver represents a nameserver in an RDAP domain response.
type RDAPNameserver struct {
	LDHName string   `json:"ldhName,omitempty"`
	IPs     []string `json:"ipAddresses,omitempty"`
}

// RDAPError represents an error response from the RDAP server.
type RDAPError struct {
	ErrorCode   int      `json:"errorCode"`
	Title       string   `json:"title,omitempty"`
	Description []string `json:"description,omitempty"`
}
