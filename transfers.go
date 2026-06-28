package apnic

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// FetchTransfers fetches the latest IP/ASN transfer records from APNIC.
func (c *Client) FetchTransfers(ctx context.Context) (*TransfersResult, error) {
	url := c.statsBaseURL + "transfers/transfers_latest.json"
	body, err := c.fetchText(ctx, url)
	if err != nil {
		return nil, err
	}
	return parseTransfersData(body)
}

// FetchTransfersByYear fetches transfer records for a specific year.
func (c *Client) FetchTransfersByYear(ctx context.Context, year int) (*TransfersResult, error) {
	url := fmt.Sprintf("%stransfers/%d/transfer_log.jcr", c.statsBaseURL, year)
	body, err := c.fetchText(ctx, url)
	if err != nil {
		return nil, err
	}
	return parseTransfersData(body)
}

// transfersJSON represents the JSON structure of the transfers data file.
type transfersJSON struct {
	Version struct {
		Producer       string   `json:"producer"`
		ProductionDate string   `json:"production_date"`
		Remarks        []string `json:"remarks"`
		UTCOffset      int      `json:"UTC_offset"`
		StatsVersion   string   `json:"stats_version"`
		RecordsInterval struct {
			StartDate string `json:"start_date"`
			EndDate   string `json:"end_date"`
		} `json:"records_interval"`
	} `json:"version"`
	Transfers []transferJSON `json:"transfers"`
}

type transferJSON struct {
	TransferDate         string              `json:"transfer_date"`
	Type                 string              `json:"type"`
	SourceRIR            string              `json:"source_rir"`
	RecipientRIR         string              `json:"recipient_rir"`
	SourceOrganization   *orgJSON            `json:"source_organization"`
	RecipientOrganization *orgJSON           `json:"recipient_organization"`
	IPv4Nets             *transferNetSetJSON `json:"ip4nets"`
	IPv6Nets             *transferNetSetJSON `json:"ip6nets"`
	ASNs                 *transferASNSetJSON `json:"asns"`
}

type orgJSON struct {
	Name        string `json:"name"`
	CountryCode string `json:"country_code"`
}

type transferNetSetJSON struct {
	TransferSet []netRangeJSON `json:"transfer_set"`
}

type netRangeJSON struct {
	StartAddress string `json:"start_address"`
	EndAddress   string `json:"end_address"`
}

type transferASNSetJSON struct {
	TransferSet []asnRangeJSON `json:"transfer_set"`
}

type asnRangeJSON struct {
	StartASN int64 `json:"start_as_number"`
	EndASN   int64 `json:"end_as_number"`
}

// parseTransfersData parses the JSON transfers data.
func parseTransfersData(data string) (*TransfersResult, error) {
	var raw transfersJSON
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTransferParseFail, err)
	}

	result := &TransfersResult{
		Metadata: TransfersMetadata{
			Producer:     raw.Version.Producer,
			StatsVersion: raw.Version.StatsVersion,
		},
		Transfers: make([]TransferRecord, 0, len(raw.Transfers)),
	}

	// Parse metadata dates
	if t, err := time.Parse(time.RFC3339, raw.Version.ProductionDate); err == nil {
		result.Metadata.ProductionDate = t
	}
	if t, err := time.Parse(time.RFC3339, raw.Version.RecordsInterval.StartDate); err == nil {
		result.Metadata.StartDate = t
	}
	if t, err := time.Parse(time.RFC3339, raw.Version.RecordsInterval.EndDate); err == nil {
		result.Metadata.EndDate = t
	}

	// Parse transfer records
	for _, t := range raw.Transfers {
		record := TransferRecord{
			Type:         t.Type,
			SourceRIR:    t.SourceRIR,
			RecipientRIR: t.RecipientRIR,
		}

		if date, err := time.Parse(time.RFC3339, t.TransferDate); err == nil {
			record.TransferDate = date
		}

		if t.SourceOrganization != nil {
			record.SourceOrganization = Organization{
				Name:        t.SourceOrganization.Name,
				CountryCode: t.SourceOrganization.CountryCode,
			}
		}

		if t.RecipientOrganization != nil {
			record.RecipientOrganization = Organization{
				Name:        t.RecipientOrganization.Name,
				CountryCode: t.RecipientOrganization.CountryCode,
			}
		}

		if t.IPv4Nets != nil && len(t.IPv4Nets.TransferSet) > 0 {
			nets := make([]NetRange, 0, len(t.IPv4Nets.TransferSet))
			for _, nr := range t.IPv4Nets.TransferSet {
				nets = append(nets, NetRange{StartAddress: nr.StartAddress, EndAddress: nr.EndAddress})
			}
			record.IPv4Nets = &TransferNetSet{TransferSet: nets}
		}

		if t.IPv6Nets != nil && len(t.IPv6Nets.TransferSet) > 0 {
			nets := make([]NetRange, 0, len(t.IPv6Nets.TransferSet))
			for _, nr := range t.IPv6Nets.TransferSet {
				nets = append(nets, NetRange{StartAddress: nr.StartAddress, EndAddress: nr.EndAddress})
			}
			record.IPv6Nets = &TransferNetSet{TransferSet: nets}
		}

		if t.ASNs != nil && len(t.ASNs.TransferSet) > 0 {
			asns := make([]ASNRange, 0, len(t.ASNs.TransferSet))
			for _, ar := range t.ASNs.TransferSet {
				asns = append(asns, ASNRange{StartASN: ar.StartASN, EndASN: ar.EndASN})
			}
			record.ASNs = &TransferASNSet{TransferSet: asns}
		}

		result.Transfers = append(result.Transfers, record)
	}

	return result, nil
}
