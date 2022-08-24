package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/pkg/errors"
)

type VulnerabilitiesList struct {
	Count            int               `json:"count"`
	Page             int               `json:"page"`
	Pagesize         int               `json:"pagesize"`
	Result           []Vulnerabilities `json:"result"`
	MoreDataAllPages int               `json:"more_data_all_pages"`
}

type Vulnerabilities struct {
	Name                       string   `json:"name"`
	Description                string   `json:"description"`
	PublishDate                string   `json:"publish_date"`
	ModificationDate           string   `json:"modification_date"`
	VendorSeverity             string   `json:"vendor_severity"`
	VendorCvss2Score           float64  `json:"vendor_cvss2_score"`
	VendorCvss2Vectors         string   `json:"vendor_cvss2_vectors"`
	VendorStatement            string   `json:"vendor_statement"`
	VendorURL                  string   `json:"vendor_url"`
	NvdSeverity                string   `json:"nvd_severity"`
	NvdCvss2Score              float64  `json:"nvd_cvss2_score"`
	NvdCvss2Vectors            string   `json:"nvd_cvss2_vectors"`
	NvdCvss3Severity           string   `json:"nvd_cvss3_severity"`
	NvdCvss3Score              float64  `json:"nvd_cvss3_score"`
	NvdCvss3Vectors            string   `json:"nvd_cvss3_vectors"`
	NvdURL                     string   `json:"nvd_url"`
	FixVersion                 string   `json:"fix_version"`
	Solution                   string   `json:"solution"`
	Classification             string   `json:"classification"`
	AquaScore                  float64  `json:"aqua_score"`
	AquaSeverity               string   `json:"aqua_severity"`
	AquaVectors                string   `json:"aqua_vectors"`
	AquaScoringSystem          string   `json:"aqua_scoring_system"`
	FirstFoundDate             string   `json:"first_found_date"`
	LastFoundDate              string   `json:"last_found_date"`
	AncestorPkg                string   `json:"ancestor_pkg"`
	SiblingPkg                 string   `json:"sibling_pkg"`
	SeverityClassification     string   `json:"severity_classification"`
	AquaSeverityClassification string   `json:"aqua_severity_classification"`
	AquaScoreClassification    string   `json:"aqua_score_classification"`
	Exploitability             string   `json:"exploitability"`
	TemporalVector             string   `json:"temporal_vector"`
	ExploitType                string   `json:"exploit_type"`
	VPatchAppliedBy            string   `json:"v_patch_applied_by"`
	VPatchAppliedOn            string   `json:"v_patch_applied_on"`
	VPatchRevertedBy           string   `json:"v_patch_reverted_by"`
	VPatchRevertedOn           string   `json:"v_patch_reverted_on"`
	VPatchEnforcedBy           string   `json:"v_patch_enforced_by"`
	VPatchEnforcedOn           string   `json:"v_patch_enforced_on"`
	VPatchStatus               string   `json:"v_patch_status"`
	AcknowledgedDate           string   `json:"acknowledged_date"`
	AckScope                   string   `json:"ack_scope"`
	AckComment                 string   `json:"ack_comment"`
	AckAuthor                  string   `json:"ack_author"`
	AckExpirationDays          int      `json:"ack_expiration_days"`
	AckExpirationConfiguredAt  string   `json:"ack_expiration_configured_at"`
	AckExpirationConfiguredBy  string   `json:"ack_expiration_configured_by"`
	VPatchPolicyName           string   `json:"v_patch_policy_name"`
	VPatchPolicyEnforce        bool     `json:"v_patch_policy_enforce"`
	AuditEventsCount           int      `json:"audit_events_count"`
	BlockEventsCount           int      `json:"block_events_count"`
	Resource                   Resource `json:"resource"`
	Registry                   string   `json:"registry"`
	ImageRepositoryName        string   `json:"image_repository_name"`
	ImageName                  string   `json:"image_name"`
	ImageDigest                string   `json:"image_digest"`
	Os                         string   `json:"os"`
	OsVersion                  string   `json:"os_version"`
	Permission                 string   `json:"permission"`
}

type Resource struct {
	Type     string   `json:"type"`
	Format   string   `json:"format"`
	Path     string   `json:"path"`
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Arch     string   `json:"arch"`
	Cpe      string   `json:"cpe"`
	Licenses []string `json:"licenses"`
	Hash     string   `json:"hash"`
}

// GetVulnerabilities gets all the vulnerabilities of an image by registry, name and tag
func (cli *Client) GetVulnerabilities(image *Image) ([]Vulnerabilities, error) {
	var vulnerabilities []Vulnerabilities

	var page = 1
	var pagesize = 50
	var total = 0
	for {
		response, err := cli.getVulnerabilities(image, page, pagesize)
		if err != nil {
			return nil, err
		}
		total = total + pagesize
		page++
		vulnerabilities = append(vulnerabilities, response.Result...)
		if total-response.Count >= 0 {
			break
		}
	}

	return vulnerabilities, nil
}

func (cli *Client) getVulnerabilities(image *Image, page, pagesize int) (*VulnerabilitiesList, error) {
	var err error
	var response VulnerabilitiesList
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/risks/vulnerabilities?page=%v&pagesize=%v&include_vpatch_info=true&show_negligible=true&hide_base_image=false&image_name=%v:%v&registry_name=%v", page, pagesize, image.Repository, image.Tag, image.Registry)
	request.Set("Authorization", "Bearer "+cli.token)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Clone().Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), fmt.Sprintf("failed getting vulnerabilities with name %v/%v:%v", image.Registry, image.Repository, image.Tag))
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error unmarshaling response body")
			return nil, errors.Wrap(err, fmt.Sprintf("couldn't unmarshal get vulnerabilities response. Body: %v", body))
		}
	} else {
		var errorReponse ErrorResponse
		err = json.Unmarshal([]byte(body), &errorReponse)
		if err != nil {
			log.Println("failed to unmarshal error response")
			return nil, fmt.Errorf("failed getting vulnerabilities for image %v/%v:%v. Status: %v, Response: %v", image.Registry, image.Repository, image.Tag, events.StatusCode, body)
		}

		return nil, fmt.Errorf("failed getting vulnerabilities for image %v/%v:%v. Status: %v, error message: %v", image.Registry, image.Repository, image.Tag, events.StatusCode, errorReponse.Message)
	}

	return &response, nil
}
