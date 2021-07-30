package hawk

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"
	"time"

	lz "github.com/Lazarus/lz-string-go"
	http "github.com/useflyent/fhttp"
)

func Init(client http.Client, key string, debug bool) (scraper Scraper) {
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
	scraper.AuthParams["auth"] = scraper.Key

	scraper.InitHeaders = http.Header{
		"Connection":         {"keep-alive"},
		"sec-ch-ua":          {`" Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91"`},
		"sec-ch-ua-mobile":   {"?0"},
		"User-Agent":         {""},
		"Accept":             {"*/*"},
		"Sec-Fetch-Site":     {"same-origin"},
		"Sec-Fetch-Mode":     {"no-cors"},
		"Sec-Fetch-Dest":     {"script"},
		"Referer":            {"https://www.referer.com/"},
		"Accept-Encoding":    {"gzip, deflate, br"},
		"Accept-Language":    {"de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"},
		http.HeaderOrderKey:  {"Connection", "sec-ch-ua", "sec-ch-ua-mobile", "User-Agent", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer", "Accept-Encoding", "Accept-Language"},
		http.PHeaderOrderKey: {":method", ":path", ":authority", ":scheme"},
	}
	scraper.ChallengeHeaders = http.Header{
		"Connection":         {"keep-alive"},
		"sec-ch-ua":          {`" Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91"`},
		"sec-ch-ua-mobile":   {"?0"},
		"User-Agent":         {""},
		"CF-Challenge":       {"b6245c8f8a8cb25"},
		"Content-Type":       {"application/x-www-form-urlencoded"},
		"Accept":             {"*/*"},
		"Origin":             {"https://www.origin.com"},
		"Sec-Fetch-Site":     {"same-origin"},
		"Sec-Fetch-Mode":     {"cors"},
		"Sec-Fetch-Dest":     {"empty"},
		"Referer":            {"https://www.referer.com/"},
		"Accept-Encoding":    {"gzip, deflate, br"},
		"Accept-Language":    {"de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"},
		http.HeaderOrderKey:  {"Connection", "sec-ch-ua", "sec-ch-ua-mobile", "User-Agent", "CF-Challenge", "Content-Type", "Accept", "Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer", "Accept-Encoding", "Accept-Language"},
		http.PHeaderOrderKey: {":method", ":path", ":authority", ":scheme"},
	}
	scraper.SubmitHeaders = http.Header{
		"Connection":                {"keep-alive"},
		"Cache-Control":             {"max-age=0"},
		"sec-ch-ua":                 {`" Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91"`},
		"sec-ch-ua-mobile":          {"?0"},
		"Upgrade-Insecure-Requests": {"1"},
		"Origin":                    {"https://www.origin.com"},
		"Content-Type":              {"application/x-www-form-urlencoded"},
		"User-Agent":                {""},
		"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
		"Sec-Fetch-Site":            {"same-origin"},
		"Sec-Fetch-Mode":            {"navigate"},
		"Sec-Fetch-Dest":            {"document"},
		"Referer":                   {"https://www.referer.com/"},
		"Accept-Encoding":           {"gzip, deflate, br"},
		"Accept-Language":           {"de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"},
		http.HeaderOrderKey:         {"Connection", "Cache-Control", "sec-ch-ua", "sec-ch-ua-mobile", "Upgrade-Insecure-Requests", "Origin", "Content-Type", "User-Agent", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer", "Accept-Encoding", "Accept-Language"},
		http.PHeaderOrderKey:        {":method", ":path", ":authority", ":scheme"},
	}

	return
}

func (scraper *Scraper) Injection(response *http.Response, err error) (*http.Response, error) {
	var challengePresent bool
	if IsNewIUAMChallenge(response) {
		challengePresent = true
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
	return scraper.OriginalRequest, nil
}

func (scraper *Scraper) Solve() (*http.Response, error) {
	if scraper.FingerprintChallenge {
		return scraper.InitiateScript()
	} else {
		// Loading init script
		scraper.SolveRetries = 0
		scraper.SolveMaxRetries = 5
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
				req.Header.Set("Referer", scraper.OriginalRequest.Request.URL.String())
				resp, err := scraper.Client.Do(req)
				if err != nil {
					scraper.HandleLoopError(errFormat, err)
					continue
				}
				scraper.InitScript = resp
				break
			}
		}
		if scraper.Debug {
			log.Println("Loaded init script.")
		}
		scraper.SolveRetries = 0
	}
	return scraper.OriginalRequest, nil
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
			payload, err := json.Marshal(map[string]string{
				"body":    base64.RawStdEncoding.EncodeToString(body),
				"url":     urlPart,
				"domain":  scraper.Domain,
				"captcha": fmt.Sprint(scraper.Captcha),
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
				resultDecoded, err := base64.RawStdEncoding.DecodeString(scraper.Result)
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
				req.Header.Set("CF-Challenge", initURLSplit[len(initURLSplit)-1])
				req.Header.Set("Referer", strings.Split(scraper.OriginalRequest.Request.URL.String(), "?")[0])
				req.Header.Set("Origin", "https://"+scraper.Domain)
				scraper.ChallengePayload, err = scraper.Client.Do(req)
				if err != nil {
					scraper.HandleLoopError(errFormat, err)
					continue
				}

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

	errFormat := "Paload error: %v"
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
				"ua":          scraper.OriginalRequest.Request.UserAgent(),
			})

			cc, err := scraper.Client.Post(fmt.Sprintf("https://%v/cf-a/ov1/p2", scraper.ApiDomain)+"?"+CreateParams(scraper.AuthParams), "application/json", bytes.NewBuffer(payload))
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
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

			resultDecoded, err := base64.RawStdEncoding.DecodeString(scraper.Result)
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
			req.Header.Set("CF-Challenge", initURLSplit[len(initURLSplit)-1])
			req.Header.Set("Referer", strings.Split(scraper.OriginalRequest.Request.URL.String(), "?")[0])
			req.Header.Set("Origin", "https://"+scraper.Domain)
			scraper.MainPayloadResponse, err = scraper.Client.Do(req)
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}

			scraper.SubmitChallengeRetries = 0

			if scraper.Debug {
				log.Println("Submitted challenge.")
			}
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
		// TODO: HandleRerun()
		//return scraper.HandleRerun()
	}
	if scraper.FinalApi.Captcha {
		if !scraper.Captcha {
			return scraper.OriginalRequest, errors.New("Cf returned captcha and captcha handling is disabled")
		} else {
			// TODO: HandleCaptcha()
			//return scraper.HandleCaptcha()
		}

	}
	return scraper.SubmitChallenge()

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

			if scraper.FinalApi.CfChCpReturn != "" {
				payloadMap["cf_ch_cp_return"] = scraper.FinalApi.CfChCpReturn
			}

			if scraper.Md != "" {
				payloadMap["md"] = scraper.Md
			}
			payload := CreateParams(payloadMap)

			req, err := http.NewRequest("POST", fmt.Sprintf("https://%v/cf-a/ov1/p3", scraper.ApiDomain)+"?"+CreateParams(scraper.AuthParams), bytes.NewBufferString(payload))
			if err != nil {
				scraper.HandleLoopError(errFormat, err)
				continue
			}
			req.Header = scraper.SubmitHeaders
			req.Header.Set("referer", scraper.OriginalRequest.Request.URL.String())
			req.Header.Set("origin", "https://"+scraper.Domain)

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

			scraper.SubmitFinalChallengeRetries = 0

			if scraper.Debug {
				log.Println("Submitted final challange.")
			}

			if final.StatusCode == 403 {
				// TODO: Deal with captcha
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
