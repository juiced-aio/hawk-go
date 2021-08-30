package hawkgo

import (
	"net/http"
	"time"

	fhttp "github.com/useflyent/fhttp"
)

/*

	Cloudflare

*/
type Scraper struct {
	Client                         fhttp.Client
	CaptchaFunction                func(originalURL, siteKey string) (string, error)
	FingerprintChallenge           bool
	Script                         string
	InitScript                     *fhttp.Response
	ChallengePayload               *fhttp.Response
	MainPayloadResponse            *fhttp.Response
	InitURL                        string
	RequestURL                     string
	CaptchaScript                  string
	ApiDomain                      string
	TimeOut                        int
	ErrorDelay                     int
	InitHeaders                    fhttp.Header
	ChallengeHeaders               fhttp.Header
	SubmitHeaders                  fhttp.Header
	OriginalRequest                *fhttp.Response
	Domain                         string
	Debug                          bool
	Key                            string
	AuthParams                     map[string]string
	Md                             string
	Captcha                        bool
	StartTime                      time.Time
	SolveRetries                   int
	SolveMaxRetries                int
	Result                         string
	Name                           string
	BaseObj                        string
	RequestPass                    string
	RequestR                       string
	TS                             int
	TargetURL                      string
	InitPayloadRetries             int
	InitPayloadMaxRetries          int
	KeyStrUriSafe                  string
	InitChallengeRetries           int
	InitChallengeMaxRetries        int
	FetchingChallengeRetries       int
	FetchingChallengeMaxRetries    int
	SubmitChallengeRetries         int
	SubmitChallengeMaxRetries      int
	ChallengeResultRetries         int
	ChallengeResultMaxRetries      int
	FinalApi                       apiResponse
	SubmitFinalChallengeRetries    int
	SubmitFinalChallengeMaxRetries int
	RerunRetries                   int
	RerunMaxRetries                int
	CaptchaRetries                 int
	CaptchaMaxRetries              int
	FirstCaptchaResult             apiResponse
	CaptchaResponseAPI             apiResponse
	SubmitCaptchaRetries           int
	SubmitCaptchaMaxRetries        int
}

type apiResponse struct {
	URL          string `json:"url"`
	ResultURL    string `json:"result_url"`
	Result       string `json:"result"`
	Name         string `json:"name"`
	BaseObj      string `json:"baseobj"`
	Pass         string `json:"pass"`
	R            string `json:"r"`
	TS           int    `json:"ts"`
	Md           string `json:"md"`
	Status       string `json:"status"`
	Captcha      bool   `json:"captcha"`
	JschlVc      string `json:"jschl_vc"`
	JschlAnswer  string `json:"jschl_answer"`
	CfChCpReturn string `json:"cf_ch_cp_return"`
	SiteKey      string `json:"sitekey"`
	Click        bool   `json:"click"`
	Valid        bool   `json:"valid"`
}

/*

	PerimeterX

*/

type PX struct {
	Domain         string
	PXID           string
	Client         http.Client
	Captcha        bool
	Gcap           bool
	CurrentPayload string
	Delay          int64
	PXResponse     PXResponse
	CaptchaSuccess bool
	PXEp           string
	URL            string
	PxHeaders      http.Header
	USER_AGENT     string
	Params         map[string]string
	MetaPayload    map[string]interface{}
	URLBase        string
	GetCaptcha     func(domain string) (string, error)
}

var SITE_IDS = map[string]string{
	"www.hibbett.com": "PXAJDckzHD",
	"www.solebox.com": "PXuR63h57Z",
	"www.snipes.com":  "PX6XNN2xkk",
	"www.onygo.com":   "PXJ1N025xg",
	"www.revolve.com": "PX78VMO82C",
	"www.walmart.com": "PXu6b0qd2S",
	"www.ssense.com":  "PX58Asv359",
}

const px_ua_ep = "https://px.hwkapi.com/px/ua"
const px_1_ep = "https://px.hwkapi.com/px/1"
const px_2_ep = "https://px.hwkapi.com/px/2"
const px_cap_15_ep = "https://px.hwkapi.com/px/captcha/15"
const px_cap_hold_ep = "https://px.hwkapi.com/px/captcha/hold"
const px_cap_google_ep = "https://px.hwkapi.com/px/captcha/google"

var EP_MAPPING = map[int]string{
	1: px_1_ep,
	2: px_2_ep,
	3: px_cap_15_ep,
	4: px_cap_hold_ep,
	5: px_cap_google_ep,
}

type PXResponse struct {
	Do []string `json:"do"`
}

type SolveResponse struct {
	Result         map[string]string `json:"result"`
	CaptchaSuccess interface{}       `json:"captchaSuccess"`
}
