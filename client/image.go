package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/pkg/errors"
)

type Image struct {
	Registry              string           `json:"registry"`
	RegistryType          string           `json:"registry_type"`
	Repository            string           `json:"repository"`
	Tag                   string           `json:"tag"`
	Labels                []string         `json:"labels"`
	Digest                string           `json:"digest"`
	VulnsFound            int              `json:"vulns_found"`
	CritVulns             int              `json:"crit_vulns"`
	HighVulns             int              `json:"high_vulns"`
	MedVulns              int              `json:"med_vulns"`
	LowVulns              int              `json:"low_vulns"`
	NegVulns              int              `json:"neg_vulns"`
	Created               string           `json:"created"`
	Author                string           `json:"author"`
	Size                  int              `json:"size"`
	Os                    string           `json:"os"`
	OsVersion             string           `json:"os_version"`
	ScanStatus            string           `json:"scan_status"`
	ScanDate              string           `json:"scan_date"`
	ScanError             string           `json:"scan_error"`
	SensitiveData         int              `json:"sensitive_data"`
	Malware               int              `json:"malware"`
	Disallowed            bool             `json:"disallowed"`
	Whitelisted           bool             `json:"whitelisted"`
	Blacklisted           bool             `json:"blacklisted"`
	PermissionAuthor      string           `json:"permission_author"`
	Permission            string           `json:"permission"`
	PermissionComment     string           `json:"permission_comment"`
	IsVulnsPerLayerView   bool             `json:"is_vulns_per_layer_view"`
	NewerImageExists      bool             `json:"newer_image_exists"`
	PartialResults        bool             `json:"partial_results"`
	Name                  string           `json:"name"`
	Metadata              Metadata         `json:"metadata"`
	History               []History        `json:"history"`
	AssuranceResults      AssuranceResults `json:"assurance_results"`
	PendingDisallowed     bool             `json:"pending_disallowed"`
	MicroenforcerDetected bool             `json:"microenforcer_detected"`
	DtaSeverityScore      string           `json:"dta_severity_score"`
	DtaSkipped            bool             `json:"dta_skipped"`
	DtaSkippedReason      string           `json:"dta_skipped_reason"`
}

type Metadata struct {
	DockerID      string   `json:"docker_id"`
	Parent        string   `json:"parent"`
	RepoDigests   []string `json:"repo_digests"`
	Comment       string   `json:"comment"`
	Created       string   `json:"created"`
	DockerVersion string   `json:"docker_version"`
	Author        string   `json:"author"`
	Architecture  string   `json:"architecture"`
	Os            string   `json:"os"`
	OsVersion     string   `json:"os_version"`
	Size          int      `json:"size"`
	VirtualSize   int      `json:"virtual_size"`
	DefaultUser   string   `json:"default_user"`
	Env           []string `json:"env"`
	DockerLabels  []string `json:"docker_labels"`
	ImageType     string   `json:"image_type"`
}

type History struct {
	ID        string `json:"id"`
	Size      int    `json:"size"`
	Comment   string `json:"comment"`
	Created   string `json:"created"`
	CreatedBy string `json:"created_by"`
}

type ChecksPerformed struct {
	PolicyName       string `json:"policy_name"`
	AssuranceType    string `json:"assurance_type"`
	Failed           bool   `json:"failed"`
	Blocking         bool   `json:"blocking"`
	Control          string `json:"control"`
	DtaSkipped       bool   `json:"dta_skipped"`
	DtaSkippedReason string `json:"dta_skipped_reason"`
}

type AssuranceResults struct {
	Disallowed      bool              `json:"disallowed"`
	ChecksPerformed []ChecksPerformed `json:"checks_performed"`
}

// CreateImage creates an Aqua Image
func (cli *Client) CreateImage(image *Image) error {
	images := struct {
		Images []Image `json:"images"`
	}{
		Images: []Image{
			*image,
		},
	}
	payload, err := json.Marshal(images)
	if err != nil {
		return err
	}

	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/images")
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, body, errs := request.Clone().Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed creating image.")
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 && resp.StatusCode != 204 {
		var errorResponse ErrorResponse
		err = json.Unmarshal([]byte(body), &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v", body)
			return fmt.Errorf("failed creating image with name %v/%v:%v. Status: %v, Response: %v", image.Registry, image.Repository, image.Tag, resp.StatusCode, body)
		}
		return fmt.Errorf("failed creating image. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}

	return nil
}

// GetImage gets an Aqua image by registry/name/tag
func (cli *Client) GetImage(imageUrl string) (*Image, error) {

	var err error
	var response Image
	request := cli.gorequest
	apiPath := fmt.Sprintf("/api/v2/images/%v", imageUrl)
	request.Set("Authorization", "Bearer "+cli.token)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return nil, err
	}
	events, body, errs := request.Clone().Get(cli.url + apiPath).End()
	if errs != nil {
		return nil, errors.Wrap(getMergedError(errs), fmt.Sprintf("failed getting image with name %v", imageUrl))
	}
	if events.StatusCode == 200 {
		err = json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Printf("Error unmarshaling response body")
			return nil, errors.Wrap(err, fmt.Sprintf("couldn't unmarshal get image response. Body: %v", body))
		}
	} else {
		var errorReponse ErrorResponse
		err = json.Unmarshal([]byte(body), &errorReponse)
		if err != nil {
			log.Println("failed to unmarshal error response")
			return nil, fmt.Errorf("failed getting image with name %v. Status: %v, Response: %v", imageUrl, events.StatusCode, body)
		}

		return nil, fmt.Errorf("failed getting image with name %v. Status: %v, error message: %v", imageUrl, events.StatusCode, errorReponse.Message)
	}

	return &response, nil
}

// RescanImage rescans an existing image
func (cli *Client) RescanImage(image *Image, fullRescan bool) error {
	images := struct {
		FullRescan bool    `json:"full_rescan"`
		Images     []Image `json:"images"`
	}{
		FullRescan: fullRescan,
		Images: []Image{
			{
				Registry:   image.Registry,
				Repository: image.Repository,
				Tag:        image.Tag,
			},
		},
	}
	payload, err := json.Marshal(images)
	if err != nil {
		return err
	}

	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v1/images/rescan")
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, _, errs := request.Clone().Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed rescaning image")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Failed to read response Body")
			return err
		}
		var errorResponse ErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", string(body), err)
			return err
		}
		return fmt.Errorf("failed rescaning. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}

	return cli.WaitUntilScanCompleted(image)
}

func (cli *Client) WaitUntilScanCompleted(image *Image) error {
	for {
		img, err := cli.GetImage(fmt.Sprintf("%v/%v/%v", image.Registry, image.Repository, image.Tag))
		if err != nil {
			return err
		}

		if img.ScanStatus != "pending" && img.ScanStatus != "in_progress" {
			break
		}

		time.Sleep(2 * time.Second)
	}

	return nil
}

// DeleteImage removes a Aqua Image
func (cli *Client) DeleteImage(image *Image) error {
	registry := image.Registry
	repo := image.Repository
	tag := image.Tag

	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	apiPath := fmt.Sprintf("/api/v2/images/%v/%v/%v", registry, repo, tag)
	err := cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, body, errs := request.Clone().Delete(cli.url + apiPath).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed deleting image")
	}
	if resp.StatusCode != 204 {
		var errorResponse ErrorResponse
		err := json.Unmarshal([]byte(body), &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v.", body)
			return err
		}
		return fmt.Errorf("failed deleting image, status: %v. error message: %v", resp.Status, errorResponse.Message)
	}
	return nil
}

func (cli *Client) ChangeImagePermission(image *Image, allow bool, permissionModificationComment string) error {
	apiPath := fmt.Sprintf("/api/v1/images/disallow")
	if allow {
		apiPath = fmt.Sprintf("/api/v1/images/allow")
	}

	images := struct {
		Comment string  `json:"comment"`
		Images  []Image `json:"images"`
	}{
		Comment: permissionModificationComment,
		Images: []Image{
			{
				Registry:   image.Registry,
				Repository: image.Repository,
				Tag:        image.Tag,
			},
		},
	}
	payload, err := json.Marshal(images)
	if err != nil {
		return err
	}

	request := cli.gorequest
	request.Set("Authorization", "Bearer "+cli.token)
	err = cli.limiter.Wait(context.Background())
	if err != nil {
		return err
	}
	resp, body, errs := request.Clone().Post(cli.url + apiPath).Send(string(payload)).End()
	if errs != nil {
		return errors.Wrap(getMergedError(errs), "failed blocking image")
	}
	if resp.StatusCode != 201 && resp.StatusCode != 204 {
		var errorResponse ErrorResponse
		err = json.Unmarshal([]byte(body), &errorResponse)
		if err != nil {
			log.Printf("Failed to Unmarshal response Body to ErrorResponse. Body: %v. error: %v", body, err)
			return fmt.Errorf("failed blocking image. Body: %v", body)
		}
		return fmt.Errorf("failed blocking image. status: %v. error message: %v", resp.Status, errorResponse.Message)
	}

	return nil
}
