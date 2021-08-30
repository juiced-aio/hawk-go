package hawkgo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func PXInit(client http.Client, domain, key string) (PX, error) {
	var pxID string
	var ok bool
	if pxID, ok = SITE_IDS[domain]; !ok {
		return PX{}, errors.New("invalid domain")
	}
	px := PX{
		Domain:     domain,
		PXID:       pxID,
		Client:     client,
		Captcha:    true,
		USER_AGENT: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
	}

	px.Params = map[string]string{
		"auth":  key,
		"appId": px.PXID,
	}

	px.MetaPayload = map[string]interface{}{
		"ua": px.USER_AGENT,
	}

	px.URLBase = fmt.Sprintf("https://collector-%v.px-cloud.net", strings.ToLower(px.PXID))

	return px, nil

}

func (px *PX) GetUserAgent() (string, error) {
	var r *http.Response
	var ua string
	for r == nil {
		var err error
		errText := "ERROR WHILE GETTING USER-AGENT: "
		r, err = px.Client.Post(px_ua_ep+"?"+CreateParams(px.Params), "", nil)
		if err != nil {
			fmt.Println(errText + err.Error())
			continue
		}
		body, err := ReadAndCloseBody(r.Body)
		if err != nil {
			fmt.Println(errText + err.Error())
			continue
		}
		ua = string(body)
	}
	return ua, nil
}

func (px *PX) UpdateUserAgent(ua string) {
	px.USER_AGENT = ua
}

func (px *PX) GetPayload(endpoint int, token ...string) error {
	url := EP_MAPPING[endpoint]

	errText := "ERROR WHILE GETTING PAYLOAD: "

	px.Params["domain"] = px.URL

	if len(token) != 0 {
		px.Params["token"] = token[0]
	}

	var r *http.Response
	data, err := json.Marshal(px.MetaPayload)
	if err == nil {
		for r == nil {
			req, _ := http.NewRequest("POST", url+"?"+CreateParams(px.Params), bytes.NewBuffer(data))
			if endpoint == 2 {
				req.Header.Set("Content-Type", "application/json")
			}
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Connection", "keep-alive")
			r, err = px.Client.Do(req)
			if err != nil {
				fmt.Println(errText + err.Error())
				continue
			}
			body, err := ReadAndCloseBody(r.Body)
			if err != nil {
				fmt.Println(errText + err.Error())
				continue
			}

			var jsonMap map[string]interface{}
			err = json.Unmarshal(body, &jsonMap)
			if err != nil {
				fmt.Println(errText + err.Error())
				continue
			}
			fmt.Println(jsonMap)
			px.CurrentPayload = jsonMap["result"].(string)
			px.MetaPayload = jsonMap["meta"].(map[string]interface{})

			if delay, ok := px.MetaPayload["delay"]; ok {
				px.Delay = delay.(int64)
			}

		}
	} else {
		return errors.New(errText + err.Error())
	}

	return nil
}

func (px *PX) PostPayloadToPX(isGet ...bool) error {
	if len(isGet) != 0 {
		px.PxHeaders = http.Header{
			"sec-ch-ua":        {`" Not A;Brand";v="99", "Chromium";v="90", "Google Chrome";v="90"`},
			"sec-ch-ua-mobile": {"?0"},
			"user-agent":       {px.USER_AGENT},
			"accept":           {"*/*"},
			"sec-fetch-site":   {"same-origin"},
			"sec-fetch-mode":   {"no-cors"},
			"sec-fetch-dest":   {"script"},
			"referer":          {fmt.Sprintf("https://%v/login", px.Domain)},
			"accept-encoding":  {"gzip, deflate, br"},
			"accept-language":  {"en,de-DE;q=0.9,de;q=0.8,en-US;q=0.7"},
		}
	} else {
		px.PxHeaders = http.Header{
			"content-length":   {""},
			"sec-ch-ua":        {`" Not A;Brand";v="99", "Chromium";v="90", "Google Chrome";v="90"`},
			"sec-ch-ua-mobile": {"?0"},
			"user-agent":       {px.USER_AGENT},
			"content-type":     {"application/x-www-form-urlencoded"},
			"accept":           {"*/*"},
			"origin":           {fmt.Sprintf("https://%v", px.Domain)},
			"sec-fetch-site":   {"same-origin"},
			"sec-fetch-mode":   {"cors"},
			"sec-fetch-dest":   {"empty"},
			"referer":          {fmt.Sprintf("https://%v/login", px.Domain)},
			"accept-encoding":  {"gzip, deflate, br"},
			"accept-language":  {"en-US,en;q=0.9"},
		}
	}

	var r *http.Response
	for r == nil {
		errText := "ERROR WHILE POSTING PX PAYLOAD: "
		if len(isGet) != 0 {
			req, err := http.NewRequest("GET", px.PXEp+"?"+px.CurrentPayload, nil)
			if err != nil {
				fmt.Println(errText + err.Error())
				continue
			}
			req.Header = px.PxHeaders
			r, err = px.Client.Do(req)
			if err != nil {
				fmt.Println(errText + err.Error())
				continue
			}

		} else {
			req, err := http.NewRequest("POST", px.PXEp, bytes.NewBufferString(px.CurrentPayload))
			if err != nil {
				fmt.Println(errText + err.Error())
				continue
			}
			req.Header = px.PxHeaders
			r, err = px.Client.Do(req)
			if err != nil {
				fmt.Println(errText + err.Error())
				continue
			}
		}
	}

	err := ReadAndUnmarshalBody(r.Body, &px.PXResponse)
	if err != nil {
		fmt.Println("ERROR WHILE PARSING PX RESPONSE: " + err.Error())
	}
	r.Body.Close()

	return nil
}

func (px *PX) Reset() {
	px.MetaPayload = map[string]interface{}{
		"ua": px.USER_AGENT,
	}
}

func (px *PX) ParsePXResponse(captcha ...bool) map[string]string {
	cookieDict := map[string]string{}

	px.CaptchaSuccess = false

	for _, cookie := range px.PXResponse.Do {
		splitCookie := strings.Split(cookie, "|")
		if splitCookie[0] == "bake" || splitCookie[1] == "_pxde" {
			cookieDict[splitCookie[1]] = splitCookie[3]
		}

		if len(captcha) != 0 {
			if cookie == "cv|0" {
				px.CaptchaSuccess = true
			}
		}
	}
	return cookieDict
}

func (px *PX) ParseGoogleSiteKey() (string, error) {
	errText := "ERROR WHILE PARSING GOOGLE SITEKEY: "

	var siteKey string

	request, err := http.NewRequest("GET", fmt.Sprintf("http://captcha.px-cdn.net/%v/captcha.js", px.PXID), nil)
	if err != nil {
		return siteKey, errors.New(errText + err.Error())

	}
	request.Header = px.PxHeaders
	response, err := px.Client.Do(request)
	if err != nil {
		return siteKey, errors.New(errText + err.Error())
	}
	body, err := ReadAndCloseBody(response.Body)
	if err != nil {
		return siteKey, errors.New(errText + err.Error())

	}

	reg := regexp.MustCompile(`="(\S{40})",`)
	subMatches := reg.FindStringSubmatch(string(body))
	if len(subMatches) == 0 {
		return siteKey, errors.New(errText + "could not find key in response")

	}
	siteKey = subMatches[0]

	return siteKey, nil
}

func (px *PX) PX1Solve() error {
	err := px.GetPayload(1)
	if err != nil {
		return err
	}
	err = px.PostPayloadToPX()
	if err != nil {
		return err
	}
	px.MetaPayload["a"] = px.PXResponse
	return nil
}

func (px *PX) PX2Solve() error {
	err := px.GetPayload(2)
	if err != nil {
		return err
	}
	return px.PostPayloadToPX()
}

func (px *PX) PX15Solve() error {
	err := px.GetPayload(3)
	if err != nil {
		return err
	}
	px.PXEp = px.PXEp + px.URLBase + "/b/g"
	err = px.PostPayloadToPX(true)
	if err != nil {
		return err
	}
	px.PXEp = px.PXEp + px.URLBase + "/assets/js/bundle"
	return nil
}

func (px *PX) PXHoldSolve() error {
	err := px.GetPayload(4)
	if err != nil {
		return err
	}

	time.Sleep(time.Duration(px.Delay) * time.Second)

	err = px.PostPayloadToPX()
	if err != nil {
		return err
	}
	return nil
}

func (px *PX) PXGoogleSolve() error {
	token, err := px.GetCaptcha(px.Domain)
	if err != nil {
		return err
	}
	err = px.GetPayload(5, token)
	if err != nil {
		return err
	}
	return px.PostPayloadToPX()
}

func (px *PX) SolveNormal(url string) (SolveResponse, error) {
	var solveResponse SolveResponse

	px.URL = url

	px.PXEp = px.URLBase + "/api/v2/collector"

	err := px.PX1Solve()
	if err != nil {
		return solveResponse, err
	}
	err = px.PX2Solve()
	if err != nil {
		return solveResponse, err
	}

	solveResponse.Result = px.ParsePXResponse()
	solveResponse.CaptchaSuccess = nil
	return solveResponse, nil
}

func (px *PX) SolveHold(url string) (SolveResponse, error) {
	var solveResponse SolveResponse

	px.URL = url

	px.Params["captcha"] = "hold"
	px.PXEp = px.URLBase + "/assets/js/bundle"

	err := px.PX1Solve()
	if err != nil {
		return solveResponse, err
	}
	err = px.PX15Solve()
	if err != nil {
		return solveResponse, err
	}
	err = px.PX2Solve()
	if err != nil {
		return solveResponse, err
	}
	err = px.PXHoldSolve()
	if err != nil {
		return solveResponse, err
	}

	solveResponse.Result = px.ParsePXResponse(true)
	solveResponse.CaptchaSuccess = px.CaptchaSuccess
	return solveResponse, nil
}

func (px *PX) SolveGoogle(url string) (SolveResponse, error) {
	var solveResponse SolveResponse

	px.URL = url

	px.Params["captcha"] = "google"
	px.PXEp = px.URLBase + "/assets/js/bundle"

	err := px.PX1Solve()
	if err != nil {
		return solveResponse, err
	}
	err = px.PX15Solve()
	if err != nil {
		return solveResponse, err
	}
	err = px.PX2Solve()
	if err != nil {
		return solveResponse, err
	}
	err = px.PXGoogleSolve()
	if err != nil {
		return solveResponse, err
	}

	solveResponse.Result = px.ParsePXResponse(true)
	solveResponse.CaptchaSuccess = px.CaptchaSuccess
	return solveResponse, nil
}
