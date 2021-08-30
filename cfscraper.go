package hawkgo

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"regexp"
	"strings"
	"time"

	lz "github.com/Lazarus/lz-string-go"
	http "github.com/useflyent/fhttp"
)

func CFInit(client http.Client, key string, debug bool) (scraper Scraper) {
	// Config Vars
	scraper.Script = "https://%v/cdn-cgi/challenge-platform/h/g/orchestrate/jsch/v1"
	scraper.CaptchaScript = "https://%v/cdn-cgi/challenge-platform/h/g/orchestrate/captcha/v1"
	scraper.ApiDomain = "cf-v2.hwkapi.com"

	scraper.TimeOut = 30
	scraper.ErrorDelay = 0

	// Vars
	scraper.Client = client
	scraper.Debug = debug
	scraper.Key = key
	scraper.AuthParams = make(map[string]string)
	scraper.AuthParams["auth"] = scraper.Key

	scraper.InitHeaders = http.Header{
		"sec-ch-ua":                 {`" Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91"`},
		"sec-ch-ua-mobile":          {"?0"},
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {""},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
		"sec-fetch-site":            {"none"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"accept-encoding":           {"gzip, deflate, br"},
		"accept-language":           {"en-US,en;q=0.9"},
		http.HeaderOrderKey:         {"sec-ch-ua", "sec-ch-ua-mobile", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest", "accept-encoding", "accept-language"},
		http.PHeaderOrderKey:        {":method", ":authority", ":scheme", ":path"},
	}
	scraper.ChallengeHeaders = http.Header{
		"user-agent":         {""},
		"cf-challenge":       {"b6245c8f8a8cb25"},
		"content-type":       {"application/x-www-form-urlencoded"},
		"accept":             {"*/*"},
		"origin":             {"https://www.origin.com"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {"https://www.referer.com/"},
		"accept-encoding":    {"gzip, deflate, br"},
		"accept-language":    {"en-US,en;q=0.9"},
		http.HeaderOrderKey:  {"content-length", "user-agent", "cf-challenge", "content-type", "accept", "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding", "accept-language"},
		http.PHeaderOrderKey: {":method", ":authority", ":scheme", ":path"},
	}
	scraper.SubmitHeaders = http.Header{
		"pragma":                    {"no-cache"},
		"cache-control":             {"max-age=0"},
		"upgrade-insecure-requests": {"1"},
		"origin":                    {"https://www.origin.com"},
		"content-type":              {"application/x-www-form-urlencoded"},
		"user-agent":                {""},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
		"sec-fetch-site":            {"same-origin"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-dest":            {"document"},
		"referer":                   {"https://www.referer.com/"},
		"accept-encoding":           {"gzip, deflate, br"},
		"accept-language":           {"en-US,en;q=0.9"},
		http.HeaderOrderKey:         {"content-length", "pragma", "cache-control", "upgrade-insecure-requests", "origin", "content-type", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding", "accept-language"},
		http.PHeaderOrderKey:        {":method", ":authority", ":scheme", ":path"},
	}

	return
}

func (scraper *Scraper) Injection(response *http.Response, err error) (*http.Response, error) {
	if err != nil {
		return response, err
	}
	var challengePresent bool
	if IsNewIUAMChallenge(response) {
		challengePresent = true
	} else if IsNewCaptchaChallenge(response) {
		scraper.Captcha = true
	} else if IsFingerprintChallenge(response) {
		scraper.FingerprintChallenge = true
		challengePresent = true
	}
	if challengePresent {
		scraper.OriginalRequest = response
		scraper.Domain = scraper.OriginalRequest.Request.URL.Host
		scraper.StartTime = time.Now()
		return scraper.Solve()
	}
	return response, nil
}

func (scraper *Scraper) Solve() (*http.Response, error) {
	if scraper.FingerprintChallenge {
		return scraper.InitiateScript()
	} else {
		// Loading init script
		scraper.SolveRetries = 0
		scraper.SolveMaxRetries = 5

		if scraper.Captcha && scraper.CaptchaFunction == nil {
			return scraper.OriginalRequest, errors.New("captcha is present with nil CaptchaFunction")
		}
		for {
			if scraper.Debug {
				log.Printf("Solving Challenge. (%v/%v)", scraper.SolveRetries, scraper.SolveMaxRetries)
			}
			if scraper.SolveRetries == scraper.SolveMaxRetries {
				return scraper.OriginalRequest, fmt.Errorf("Solving challenge failed after %v retries.", scraper.SolveMaxRetries)
			} else {
				scraper.SolveRetries++
				errFormat := "Failed to request init script: %v"

				// Fetching CF script
				var script string
				if !scraper.Captcha {
					script = fmt.Sprintf(scraper.Script, scraper.Domain)
				} else {
					script = fmt.Sprintf(scraper.CaptchaScript, scraper.Domain)
				}
				req, err := http.NewRequest("GET", script, nil)
				if err != nil {
					scraper.HandleLoopError(errFormat, err)
					continue
				}
				req.Header = scraper.InitHeaders
				req.Header["user-agent"] = scraper.OriginalRequest.Request.Header["user-agent"]
				resp, err := scraper.Client.Do(req)
				if err != nil {
					scraper.HandleLoopError(errFormat, err)
					continue
				}
				defer resp.Body.Close()

				scraper.InitScript = resp
				break
			}
		}
		if scraper.Debug {
			log.Println("Loaded init script.")
		}
		scraper.SolveRetries = 0

		return scraper.ChallengeInitiationPayload()
	}
}

func (scraper *Scraper) ChallengeInitiationPayload() (*http.Response, error) {
	// Fetches payload for challenge iniation from our api

	scraper.InitPayloadRetries = 0
	scraper.InitPayloadMaxRetries = 5
	for {
		if scraper.Debug {
			log.Printf("Fetching payload. (%v/%v)", scraper.InitPayloadRetries, scraper.InitPayloadMaxRetries)
		}
		if scraper.InitPayloadRetries == scraper.InitPayloadMaxRetries {
			return scraper.OriginalRequest, fmt.Errorf("Fetching payload failed after %v retries.", scraper.InitPayloadMaxRetries)
		} else {
			scraper.InitPayloadRetries++

			errFormat := "Failed to parse data needed for init payload: %v"
			// Parsing of the data needed for the api to serve the init payload

			body, err := ReadAndCopyBody(scraper.InitScript)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				// I don't see a point to continue before requesting the payload from the api, should just return an error
				continue
			}
			reg := regexp.MustCompile(`0\.[^('|/)]+`)
			matches := reg.FindStringSubmatch(string(body))
			if len(matches) == 0 {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			urlPart := matches[0]
			reg = regexp.MustCompile(`[\W]?([A-Za-z0-9+\-$]{65})[\W]`)
			matches = reg.FindStringSubmatch(string(body))
			if len(matches) == 0 {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			for _, match := range matches {
				match = strings.ReplaceAll(match, ",", "")
				if strings.Contains(match, "+") && strings.Contains(match, "-") && strings.Contains(match, "$") {
					scraper.KeyStrUriSafe = match
					break
				}
			}
			if scraper.KeyStrUriSafe == "" {
				scraper.HandleLoopError(errFormat, err)
				continue
			}

			// Requesting payload from the api
			errFormat = "Failed submit data to the api: %v\nmake sure that you have your API KEY assigned"

			body, err = ReadAndCopyBody(scraper.OriginalRequest)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			payload, err := json.Marshal(map[string]interface{}{
				"body":    base64.StdEncoding.EncodeToString(body),
				"url":     urlPart,
				"domain":  scraper.Domain,
				"captcha": scraper.Captcha,
				"key":     scraper.KeyStrUriSafe,
			})
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			challengePayload, err := scraper.Client.Post(fmt.Sprintf("https://%v/cf-a/ov1/p1", scraper.ApiDomain)+"?"+CreateParams(scraper.AuthParams), "application/json", bytes.NewBuffer(payload))
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			defer challengePayload.Body.Close()

			var challengePayloadResponse apiResponse
			err = ReadAndUnmarshalBody(challengePayload.Body, &challengePayloadResponse)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			scraper.InitURL = challengePayloadResponse.URL
			scraper.RequestURL = challengePayloadResponse.ResultURL
			scraper.Result = challengePayloadResponse.Result
			scraper.Name = challengePayloadResponse.Name
			scraper.BaseObj = challengePayloadResponse.BaseObj
			scraper.RequestPass = challengePayloadResponse.Pass
			scraper.RequestR = challengePayloadResponse.R
			scraper.TS = challengePayloadResponse.TS
			scraper.Md = challengePayloadResponse.Md

			log.Println("Submitted init payload to the api.")
			return scraper.InitiateCloudflare()
		}

	}

}

func (scraper *Scraper) InitiateCloudflare() (*http.Response, error) {
	// Initiares the cloudflare challenge

	errFormat := "Initiating challenge error: %v"
	scraper.InitChallengeRetries = 0
	scraper.InitChallengeMaxRetries = 5
	for {
		if scraper.Debug {
			log.Printf("Initiating challenge. (%v/%v)", scraper.InitChallengeRetries, scraper.InitChallengeMaxRetries)
		}
		if scraper.InitChallengeRetries == scraper.InitChallengeMaxRetries {
			return scraper.OriginalRequest, fmt.Errorf("Initiating challenge failed after %v retries.", scraper.InitChallengeMaxRetries)
		} else {
			scraper.InitChallengeRetries++

			if scraper.KeyStrUriSafe == "" {
				return scraper.OriginalRequest, errors.New("KeyUri cannot be None.")
			} else {
				resultDecoded, err := base64.StdEncoding.DecodeString(scraper.Result)
				if err != nil {
					scraper.HandleLoopError(errFormat, err)
					continue
				}
				payload := CreateParams(map[string]string{
					scraper.Name: lz.Compress(string(resultDecoded), scraper.KeyStrUriSafe),
				})
				if err != nil {
					scraper.HandleLoopError(errFormat, err)
					continue
				}

				req, err := http.NewRequest("POST", scraper.InitURL, bytes.NewBufferString(payload))
				if err != nil {
					scraper.HandleLoopError(errFormat, err)
					continue
				}
				req.Header = scraper.ChallengeHeaders
				initURLSplit := strings.Split(scraper.InitURL, "/")
				req.Header["cf-challenge"] = []string{initURLSplit[len(initURLSplit)-1]}
				req.Header["referer"] = []string{strings.Split(scraper.OriginalRequest.Request.URL.String(), "?")[0]}
				req.Header["origin"] = []string{"https://" + scraper.Domain}
				req.Header["user-agent"] = scraper.OriginalRequest.Request.Header["user-agent"]
				scraper.ChallengePayload, err = scraper.Client.Do(req)
				if err != nil {
					scraper.HandleLoopError(errFormat, err)
					continue
				}
				defer scraper.ChallengePayload.Body.Close()

				scraper.InitChallengeRetries = 0

				if scraper.Debug {
					log.Println("Initiated challenge.")
				}

				return scraper.SolvePayload()
			}

		}
	}
}

func (scraper *Scraper) SolvePayload() (*http.Response, error) {
	// Fetches main challenge payload from hawk api

	errFormat := "Payload error: %v"
	scraper.FetchingChallengeRetries = 0
	scraper.FetchingChallengeMaxRetries = 5

	for {
		if scraper.Debug {
			log.Printf("Fetching main challenge. (%v/%v)", scraper.FetchingChallengeRetries, scraper.FetchingChallengeMaxRetries)
		}
		if scraper.FetchingChallengeRetries == scraper.FetchingChallengeMaxRetries {
			return scraper.OriginalRequest, fmt.Errorf("Fetching main challenge failed after %v retries.\nThis error is mostlikly related to a wring usage of headers.\nIf this exception occurs on an endpoint which is used to peform a carting or a similiar action note that the solving process shell not work here by cloudflare implementation on sites.\nIf this occurs you need to regen the cookie on a get page request or similiar with resettet headers.\nAfter generation you can assign the headers again and cart again.", scraper.FetchingChallengeMaxRetries)
		} else {
			scraper.FetchingChallengeRetries++

			originalRequestBody, err := ReadAndCopyBody(scraper.OriginalRequest)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			challengePayloadBody, err := ReadAndCopyBody(scraper.ChallengePayload)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			payload, err := json.Marshal(map[string]interface{}{
				"body_home":   base64.RawURLEncoding.EncodeToString(originalRequestBody),
				"body_sensor": base64.RawURLEncoding.EncodeToString(challengePayloadBody),
				"result":      scraper.BaseObj,
				"ts":          scraper.TS,
				"url":         scraper.InitURL,
				"ua":          scraper.OriginalRequest.Request.Header["user-agent"][0],
			})
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}

			cc, err := scraper.Client.Post(fmt.Sprintf("https://%v/cf-a/ov1/p2", scraper.ApiDomain)+"?"+CreateParams(scraper.AuthParams), "application/json", bytes.NewBuffer(payload))
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			defer cc.Body.Close()

			var solvePayloadResponse apiResponse
			err = ReadAndUnmarshalBody(cc.Body, &solvePayloadResponse)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			scraper.Result = solvePayloadResponse.Result

			scraper.FetchingChallengeRetries = 0

			if scraper.Debug {
				log.Println("Fetched challenge payload.")
			}

			return scraper.SendMainPayload()
		}
	}
}

func (scraper *Scraper) SendMainPayload() (*http.Response, error) {
	// Sends the main payload to cf

	errFormat := "Submitting challenge error: %v"
	scraper.SubmitChallengeRetries = 0
	scraper.SubmitChallengeMaxRetries = 5
	for {
		if scraper.Debug {
			log.Printf("Submitting challenge. (%v/%v)", scraper.SubmitChallengeRetries, scraper.SubmitChallengeMaxRetries)
		}
		if scraper.SubmitChallengeRetries == scraper.SubmitChallengeMaxRetries {
			return scraper.OriginalRequest, fmt.Errorf("Submitting challenge failed after %v retries.", scraper.SubmitChallengeMaxRetries)
		} else {
			scraper.SubmitChallengeRetries++

			resultDecoded, err := base64.StdEncoding.DecodeString(scraper.Result)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			payload := CreateParams(map[string]string{
				scraper.Name: lz.Compress(string(resultDecoded), scraper.KeyStrUriSafe),
			})
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}

			req, err := http.NewRequest("POST", scraper.InitURL, bytes.NewBufferString(payload))
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			req.Header = scraper.ChallengeHeaders
			initURLSplit := strings.Split(scraper.InitURL, "/")
			req.Header["cf-challenge"] = []string{initURLSplit[len(initURLSplit)-1]}
			req.Header["referer"] = []string{strings.Split(scraper.OriginalRequest.Request.URL.String(), "?")[0]}
			req.Header["origin"] = []string{"https://" + scraper.Domain}
			req.Header["user-agent"] = scraper.OriginalRequest.Request.Header["user-agent"]
			scraper.MainPayloadResponse, err = scraper.Client.Do(req)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			defer scraper.MainPayloadResponse.Body.Close()

			scraper.SubmitChallengeRetries = 0

			if scraper.Debug {
				log.Println("Submitted challenge.")
			}

			return scraper.GetChallengeResult()
		}

	}
}

func (scraper *Scraper) GetChallengeResult() (*http.Response, error) {
	// Fetching challenge result

	errFormat := "Fetching challenge result error: %v"
	scraper.ChallengeResultRetries = 0
	scraper.ChallengeResultMaxRetries = 5
	for {
		if scraper.Debug {
			log.Printf("Fetching challenge result. (%v/%v)", scraper.ChallengeResultRetries, scraper.ChallengeResultMaxRetries)
		}
		if scraper.ChallengeResultRetries == scraper.ChallengeResultMaxRetries {
			return scraper.OriginalRequest, fmt.Errorf("Fetching challenge result failed after %v retries.", scraper.ChallengeResultMaxRetries)
		} else {
			scraper.ChallengeResultRetries++

			body, err := ReadAndCopyBody(scraper.MainPayloadResponse)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			payload, err := json.Marshal(map[string]interface{}{
				"body_sensor": base64.StdEncoding.EncodeToString(body),
				"result":      scraper.BaseObj,
			})
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			ee, err := scraper.Client.Post(fmt.Sprintf("https://%v/cf-a/ov1/p3", scraper.ApiDomain)+"?"+CreateParams(scraper.AuthParams), "application/json", bytes.NewBuffer(payload))
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			defer ee.Body.Close()

			err = ReadAndUnmarshalBody(ee.Body, &scraper.FinalApi)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}

			scraper.ChallengeResultRetries = 0

			if scraper.Debug {
				log.Println("Fetched challenge response.")
			}

			return scraper.HandleFinalApi()
		}
	}
}

func (scraper *Scraper) HandleFinalApi() (*http.Response, error) {
	// Handle final API result and rerun if needed

	if scraper.FinalApi.Status == "rerun" {
		return scraper.HandleRerun()
	}
	if scraper.FinalApi.Captcha {
		if !scraper.Captcha {
			return scraper.OriginalRequest, errors.New("Cf returned captcha and captcha handling is disabled")
		} else {
			return scraper.HandleCaptcha()
		}
	} else {
		return scraper.SubmitChallenge()
	}

}

func (scraper *Scraper) SubmitChallenge() (*http.Response, error) {
	// Submits the challenge and trys to access target url

	errFormat := "Submitting final challenge error: %v"
	scraper.SubmitFinalChallengeRetries = 0
	scraper.SubmitFinalChallengeMaxRetries = 5
	for {
		if scraper.Debug {
			log.Printf("Submitting final challenge. (%v/%v)", scraper.SubmitFinalChallengeRetries, scraper.SubmitFinalChallengeMaxRetries)
		}
		if scraper.SubmitFinalChallengeRetries == scraper.SubmitFinalChallengeMaxRetries {
			return scraper.OriginalRequest, fmt.Errorf("Submitting final challenge failed after %v retries.", scraper.SubmitFinalChallengeMaxRetries)
		} else {
			scraper.SubmitFinalChallengeRetries++

			payloadMap := map[string]string{
				"r":            scraper.RequestR,
				"jschl_vc":     scraper.FinalApi.JschlVc,
				"pass":         scraper.RequestPass,
				"jschl_answer": scraper.FinalApi.JschlAnswer,
				"cf_ch_verify": "plat",
			}

			// cf added a new flow where they present a 503 followed up by a 403 captcha
			if scraper.FinalApi.CfChCpReturn != "" {
				payloadMap["cf_ch_cp_return"] = scraper.FinalApi.CfChCpReturn
			}

			if scraper.Md != "" {
				payloadMap["md"] = scraper.Md
			}
			payload := CreateParams(payloadMap)

			req, err := http.NewRequest("POST", scraper.RequestURL, bytes.NewBufferString(payload))
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			req.Header = scraper.SubmitHeaders
			req.Header["referer"] = []string{scraper.OriginalRequest.Request.URL.String()}
			req.Header["origin"] = []string{"https://" + scraper.Domain}
			req.Header["user-agent"] = scraper.OriginalRequest.Request.Header["user-agent"]

			if (time.Now().Unix() - scraper.StartTime.Unix()) < 5 {
				// Waiting X amount of sec for CF delay
				if scraper.Debug {
					log.Printf("Sleeping %v sec for cf delay", 5-(time.Now().Unix()-scraper.StartTime.Unix()))
				}
				time.Sleep(time.Duration(5-(time.Now().Unix()-scraper.StartTime.Unix())) * time.Second)
			}
			final, err := scraper.Client.Do(req)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			defer final.Body.Close()

			scraper.SubmitFinalChallengeRetries = 0

			if scraper.Debug {
				log.Println("Submitted final challange.")
			}

			if final.StatusCode == 403 {
				body, err := ReadAndCopyBody(final)
				if err != nil {
					scraper.HandleLoopError(errFormat, err)
					continue
				}
				if CheckForCaptcha(string(body)) {
					// as this was a 403 post we need to get again dont ask why just do it
					req, err := http.NewRequest("GET", scraper.OriginalRequest.Request.URL.String(), nil)
					if err != nil {
						scraper.HandleLoopError(errFormat, err)
						continue
					}
					req.Header = scraper.OriginalRequest.Request.Header
					weirdGetReq, err := scraper.Client.Do(req)
					if err != nil {
						scraper.HandleLoopError(errFormat, err)
						continue
					}
					defer weirdGetReq.Body.Close()

					newScraper := CFInit(scraper.Client, scraper.Key, scraper.Debug)
					newScraper.Captcha = true
					newScraper.OriginalRequest = weirdGetReq
					newScraper.Domain = scraper.OriginalRequest.Request.URL.Host
					newScraper.StartTime = time.Now()
					return newScraper.Solve()
				}
			}

			return final, err
		}
	}
}

func (scraper *Scraper) HandleRerun() (*http.Response, error) {
	// Handling rerun

	errFormat := "Fetching rerun challenge payload error: %v"
	scraper.RerunRetries = 0
	scraper.RerunMaxRetries = 5
	for {
		if scraper.Debug {
			log.Printf("Handling rerun. (%v/%v)", scraper.RerunRetries, scraper.RerunMaxRetries)
		}
		if scraper.RerunRetries == scraper.RerunMaxRetries {
			return scraper.OriginalRequest, fmt.Errorf("Rerun failed after %v retries.", scraper.RerunMaxRetries)
		} else {
			scraper.RerunRetries++

			originalRequestBody, err := ReadAndCopyBody(scraper.OriginalRequest)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			mainPayloadBody, err := ReadAndCopyBody(scraper.MainPayloadResponse)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			payload, err := json.Marshal(map[string]interface{}{
				"body_home":   base64.RawURLEncoding.EncodeToString(originalRequestBody),
				"body_sensor": base64.RawURLEncoding.EncodeToString(mainPayloadBody),
				"result":      scraper.BaseObj,
				"ts":          scraper.TS,
				"url":         scraper.InitURL,
				"rerun":       true,
				"rerun_base":  scraper.Result,
			})
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}

			alternative, err := scraper.Client.Post(fmt.Sprintf("https://%v/cf-a/ov1/p2", scraper.ApiDomain)+"?"+CreateParams(scraper.AuthParams), "application/json", bytes.NewBuffer(payload))
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			defer alternative.Body.Close()

			var handleRerunResponse apiResponse
			err = ReadAndUnmarshalBody(alternative.Body, &handleRerunResponse)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			scraper.Result = handleRerunResponse.Result

			scraper.RerunRetries = 0

			if scraper.Debug {
				log.Println("Handled rerun.")
			}

			return scraper.SendMainPayload()
		}

	}
}

// In Progress
func (scraper *Scraper) HandleCaptcha() (*http.Response, error) {
	/* Handling captcha
	   Note that this function is designed to work with cloudscraper,
	   if you are building your own flow you will need to rework this part a bit.
	*/

	errFormat := "First captcha API call error: %v"
	scraper.CaptchaRetries = 0
	scraper.CaptchaMaxRetries = 5
	for {
		if scraper.Debug {
			log.Printf("Handling captcha. (%v/%v)", scraper.CaptchaRetries, scraper.CaptchaMaxRetries)
		}
		if scraper.CaptchaRetries == scraper.CaptchaMaxRetries {
			return scraper.OriginalRequest, fmt.Errorf("Handling captcha failed after %v retries.", scraper.CaptchaMaxRetries)
		} else {
			scraper.CaptchaRetries++
			var token string
			var err error
			if scraper.FinalApi.Click {
				token = "click"
			} else {
				errFormat := "Failed to get captcha token from cap function: %v"
				if scraper.Debug {
					log.Println("Captcha needed, requesting token.")
				}
				token, err = scraper.CaptchaFunction(scraper.OriginalRequest.Request.URL.String(), scraper.FinalApi.SiteKey)
				if err != nil {
					scraper.HandleLoopError(errFormat, err)
					continue
				}
			}

			payload, err := json.Marshal(map[string]interface{}{
				"result":             scraper.Result,
				"token":              token,
				"h-captcha-response": token,
				"data":               scraper.FinalApi.Result,
			})
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}

			ff, err := scraper.Client.Post(fmt.Sprintf("https://%v/cf-a/ov1/cap1", scraper.ApiDomain)+"?"+CreateParams(scraper.AuthParams), "application/json", bytes.NewBuffer(payload))
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			defer ff.Body.Close()

			var handleCaptchaResponse apiResponse
			err = ReadAndUnmarshalBody(ff.Body, &handleCaptchaResponse)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			scraper.FirstCaptchaResult = handleCaptchaResponse

			errFormat = "Posting to cloudflare challenge endpoint error: %v"
			resultDecoded, err := base64.StdEncoding.DecodeString(scraper.FirstCaptchaResult.Result)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}

			payload = []byte(CreateParams(map[string]string{
				scraper.Name: lz.Compress(string(resultDecoded), scraper.KeyStrUriSafe),
			}))

			req, err := http.NewRequest("POST", scraper.InitURL, bytes.NewBuffer(payload))
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}

			req.Header = scraper.ChallengeHeaders
			initURLSplit := strings.Split(scraper.InitURL, "/")
			req.Header["cf-challenge"] = []string{initURLSplit[len(initURLSplit)-1]}
			req.Header["referer"] = []string{strings.Split(scraper.OriginalRequest.Request.URL.String(), "?")[0]}
			req.Header["origin"] = []string{"https://" + scraper.Domain}
			req.Header["user-agent"] = scraper.OriginalRequest.Request.Header["user-agent"]

			gg, err := scraper.Client.Do(req)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			defer gg.Body.Close()

			errFormat = "Second captcha API call error: %v"

			body, err := ioutil.ReadAll(gg.Body)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}

			payload, err = json.Marshal(map[string]interface{}{
				"body_sensor": base64.StdEncoding.EncodeToString(body),
				"result":      scraper.BaseObj,
			})
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}

			hh, err := scraper.Client.Post(fmt.Sprintf("https://%v/cf-a/ov1/cap2", scraper.ApiDomain)+"?"+CreateParams(scraper.AuthParams), "application/json", bytes.NewBuffer(payload))
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			defer hh.Body.Close()

			handleCaptchaResponse = apiResponse{}
			err = ReadAndUnmarshalBody(hh.Body, &handleCaptchaResponse)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			scraper.CaptchaResponseAPI = handleCaptchaResponse

			scraper.CaptchaRetries = 0

			if scraper.CaptchaResponseAPI.Valid {
				if scraper.Debug {
					log.Println("Captcha is accepted.")
				}
				return scraper.SubmitCaptcha()
			} else {
				return scraper.OriginalRequest, errors.New("Captcha was not accepted - most likly wrong token")
			}

		}

	}
}

func (scraper *Scraper) SubmitCaptcha() (*http.Response, error) {
	// Submits the challenge + captcha and trys to access target url

	errFormat := "Submitting captcha challenge error: %v"
	scraper.SubmitCaptchaRetries = 0
	scraper.SubmitCaptchaMaxRetries = 5
	for {
		if scraper.Debug {
			log.Printf("Submitting captcha challenge. (%v/%v)", scraper.SubmitCaptchaRetries, scraper.SubmitCaptchaMaxRetries)
		}
		if scraper.SubmitCaptchaRetries == scraper.SubmitCaptchaMaxRetries {
			return scraper.OriginalRequest, fmt.Errorf("Submitting captcha challenge failed after %v retries.", scraper.SubmitFinalChallengeMaxRetries)
		} else {
			scraper.SubmitCaptchaRetries++

			payloadMap := map[string]string{
				"r":               scraper.RequestR,
				"cf_captcha_kind": "h",
				"vc":              scraper.RequestPass,
				"captcha_vc":      scraper.CaptchaResponseAPI.JschlVc,
				"captcha_answer":  scraper.CaptchaResponseAPI.JschlAnswer,
				"cf_ch_verify":    "plat",
			}

			if scraper.CaptchaResponseAPI.CfChCpReturn != "" {
				payloadMap["cf_ch_cp_return"] = scraper.CaptchaResponseAPI.CfChCpReturn
			}

			if scraper.Md != "" {
				payloadMap["md"] = scraper.Md
			}

			// "captchka" Spelling mistake?
			payloadMap["h-captcha-response"] = "captchka"

			payload := CreateParams(payloadMap)

			req, err := http.NewRequest("POST", scraper.RequestURL, bytes.NewBufferString(payload))
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			req.Header = scraper.SubmitHeaders
			req.Header["referer"] = []string{scraper.OriginalRequest.Request.URL.String()}
			req.Header["origin"] = []string{"https://" + scraper.Domain}
			req.Header["user-agent"] = scraper.OriginalRequest.Request.Header["user-agent"]

			if (time.Now().Unix() - scraper.StartTime.Unix()) < 5 {
				// Waiting X amount of sec for CF delay
				if scraper.Debug {
					log.Printf("Sleeping %v sec for cf delay", 5-(time.Now().Unix()-scraper.StartTime.Unix()))
				}
				time.Sleep(time.Duration(5-(time.Now().Unix()-scraper.StartTime.Unix())) * time.Second)
			}
			final, err := scraper.Client.Do(req)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			defer final.Body.Close()

			scraper.SubmitCaptchaRetries = 0

			if scraper.Debug {
				log.Println("Submitted captcha challange.")
			}

			return final, err
		}
	}
}

func (scraper *Scraper) InitiateScript() (*http.Response, error) {
	/*
		   iniates the first script from cf fingerprint challenge
			:return:
	*/
	if scraper.Debug {
		log.Println("Receiving fingerprint script")
	}
	body, err := ReadAndCopyBody(scraper.OriginalRequest)
	if err != nil {
		return scraper.OriginalRequest, err
	}
	urlPath := strings.Split(strings.Split(string(body), `<script src="`)[3], `"`)[0]
	scraper.InitURL = "https://" + scraper.Domain + urlPath
	req, err := http.NewRequest("GET", scraper.InitURL, nil)
	if err != nil {
		return scraper.OriginalRequest, err
	}
	resp, err := scraper.Client.Do(req)
	if err != nil {
		return scraper.OriginalRequest, err
	}
	defer resp.Body.Close()

	scraper.InitScript = resp

	return scraper.GetPayloadFromAPI()
}

func (scraper *Scraper) GetPayloadFromAPI() (*http.Response, error) {
	/*
			  Recieve the needed fingerprint data from hawk api
		        :return:
	*/
	body, err := ReadAndCopyBody(scraper.InitScript)
	if err != nil {
		return scraper.OriginalRequest, err
	}
	payload, err := json.Marshal(map[string]string{
		"body": base64.StdEncoding.EncodeToString(body),
		"url":  scraper.InitURL,
	})
	if err != nil {
		return scraper.OriginalRequest, err
	}
	resp, err := scraper.Client.Post("https://cf-v2.hwkapi.com/cf-a/fp/p1"+"?"+CreateParams(scraper.AuthParams), "application/json", bytes.NewReader(payload))
	if err != nil {
		return scraper.OriginalRequest, err
	}
	defer resp.Body.Close()

	var p1Response apiResponse
	err = ReadAndUnmarshalBody(resp.Body, &p1Response)
	if err != nil {
		return scraper.OriginalRequest, err
	}
	scraper.Result = p1Response.Result
	scraper.TargetURL = p1Response.URL
	return scraper.SubmitFingerprintChallenge()
}

func (scraper *Scraper) SubmitFingerprintChallenge() (*http.Response, error) {
	/*
	   Submit the fingerprint data to cloudflare
	          :return:
	*/
	if scraper.Debug {
		log.Println("Submitting fingerprint")
	}
	result, err := scraper.Client.Post(scraper.TargetURL, "", bytes.NewBufferString(scraper.Result))
	if err != nil {
		return scraper.OriginalRequest, err
	}
	defer result.Body.Close()

	if result.StatusCode == 429 {
		return scraper.OriginalRequest, errors.New("FP DATA declined")
	} else if result.StatusCode == 404 {
		return scraper.OriginalRequest, errors.New("Fp ep changed")
	}

	return scraper.GetPage()
}

func (scraper *Scraper) GetPage() (*http.Response, error) {
	/*
			 Perform the original request
		        :return:
	*/
	if scraper.Debug {
		log.Println("Fetching original request target")
	}

	var url string
	if strings.Contains(scraper.OriginalRequest.Request.URL.String(), "?") {
		url = strings.Split(scraper.OriginalRequest.Request.URL.String(), "?")[0]
	} else {
		url = scraper.OriginalRequest.Request.URL.String()
	}
	result, err := scraper.Client.Get(url)
	return result, err
}
func (scraper *Scraper) Do(request *http.Request) (*http.Response, error) {
	return scraper.Injection(scraper.Client.Do(request))
}

func (scraper *Scraper) Get(url string) (resp *http.Response, err error) {
	return scraper.Injection(scraper.Client.Get(url))
}

func (scraper *Scraper) Post(url string, contentType string, body io.Reader) (resp *http.Response, err error) {
	return scraper.Injection(scraper.Client.Post(url, contentType, body))
}
