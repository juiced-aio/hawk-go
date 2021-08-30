package hawkgo

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"

	"net/http"

	"github.com/anaskhan96/soup"
	fhttp "github.com/useflyent/fhttp"
)

func ReadAndCopyBody(r interface{}) ([]byte, error) {
	var bodyReadCloser io.ReadCloser
	switch r.(type) {
	case *fhttp.Response:
		bodyReadCloser = r.(*fhttp.Response).Body
	case *http.Response:
		bodyReadCloser = r.(*http.Response).Body
	}

	var body []byte
	var err error
	var b bytes.Buffer
	t := io.TeeReader(bodyReadCloser, &b)
	body, err = ioutil.ReadAll(t)
	if err != nil {
		return body, err
	}

	newReadCloser := ioutil.NopCloser(bytes.NewBuffer(body))
	switch r.(type) {
	case *fhttp.Response:
		r.(*fhttp.Response).Body = newReadCloser
	case *http.Response:
		r.(*http.Response).Body = newReadCloser
	}

	return body, err
}

func ReadAndUnmarshalBody(respBody io.ReadCloser, x interface{}) error {
	body, err := ioutil.ReadAll(respBody)
	if err != nil {
		return err
	}
	err = json.Unmarshal(body, &x)
	return err
}

func ReadAndCloseBody(respBody io.ReadCloser) ([]byte, error) {
	defer respBody.Close()
	return ioutil.ReadAll(respBody)
}

func CreateParams(paramsLong map[string]string) string {
	params := url.Values{}
	for key, value := range paramsLong {
		params.Add(key, value)
	}
	return params.Encode()
}

func CheckForCaptcha(body string) bool {
	doc := soup.HTMLParse(body)

	element := doc.Find("input", "name", "cf_captcha_kind")
	if element.Error != nil {
		return false
	}
	if val, ok := element.Attrs()["value"]; ok && val == "h" {
		return true
	}

	return false
}

func IsNewIUAMChallenge(response *fhttp.Response) bool {
	body, err := ReadAndCopyBody(response)
	if err != nil {
		return false
	}
	firstReg, err := regexp.MatchString(`cpo.src\s*=\s*"/cdn-cgi/challenge-platform/?\w?/?\w?/orchestrate/jsch/v1`, string(body))
	if err != nil {
		return false
	}
	secondReg, err := regexp.MatchString(`window._cf_chl_opt`, string(body))
	if err != nil {
		return false
	}
	return strings.Contains(response.Header.Get("Server"), "cloudflare") &&
		(response.StatusCode == 429 || response.StatusCode == 503) &&
		firstReg && secondReg

}

func IsFingerprintChallenge(response *fhttp.Response) bool {
	if response.StatusCode == 429 {
		body, err := ReadAndCopyBody(response)
		if err != nil {
			return false
		}
		if strings.Contains(string(body), "/fingerprint/script/") {
			return true
		}

	}
	return false
}

func IsNewCaptchaChallenge(response *fhttp.Response) bool {
	body, err := ReadAndCopyBody(response)
	if err != nil {
		return false
	}
	firstReg, err := regexp.MatchString(`cpo.src\s*=\s*"/cdn-cgi/challenge-platform/?\w?/?\w?/orchestrate/.*/v1`, string(body))
	if err != nil {
		return false
	}
	secondReg, err := regexp.MatchString(`window._cf_chl_opt`, string(body))
	if err != nil {
		return false
	}
	return strings.Contains(response.Header.Get("Server"), "cloudflare") &&
		(response.StatusCode == 403) &&
		firstReg && secondReg
}

func (scraper *Scraper) HandleLoopError(errFormat string, err error) {
	if scraper.Debug {
		log.Printf(errFormat, err.Error())
	}
	time.Sleep(time.Duration(scraper.ErrorDelay) * time.Second)
}
