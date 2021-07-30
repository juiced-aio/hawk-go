package hawk

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

	http "github.com/useflyent/fhttp"
)

func ReadAndCopyBody(response *http.Response) ([]byte, error) {
	var body []byte
	var err error
	var b bytes.Buffer
	t := io.TeeReader(response.Body, &b)
	body, err = ioutil.ReadAll(t)
	if err != nil {
		return body, err
	}
	response.Body = ioutil.NopCloser(bytes.NewBuffer(body))
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

func CreateParams(paramsLong map[string]string) string {
	params := url.Values{}
	for key, value := range paramsLong {
		params.Add(key, value)
	}
	return params.Encode()
}

func IsNewIUAMChallenge(response *http.Response) bool {
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

func IsFingerprintChallenge(response *http.Response) bool {
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

func (scraper *Scraper) HandleLoopError(errFormat string, err error) {
	if scraper.Debug {
		log.Printf(errFormat, err.Error())
	}
	time.Sleep(time.Duration(scraper.ErrorDelay) * time.Second)
}
