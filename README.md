# hawk-go
Port of HawkAPI's cloudscraper

Everything is exposed to give access to modification, this is subject to change.

Installation:
`go get github.com/juiced-aio/hawk-go`

Example:
```go
import (
    "github.com/useflyent/fhttp/cookiejar"
    hawk "github.com/juiced-aio/hawk-go"
    http "github.com/useflyent/fhttp"
)

// Client has to be from fhttp and up to CloudFlare's standards, this can include ja3 fingerprint/http2 settings.

// Client also will need a cookie jar.
cookieJar, _: = cookiejar.New(nil)
client.Jar = cookieJar
scraper: = hawk.Init(client, "YOUR_KEY_HERE", true)

// You will have to create your own function if you want to solve captchas.
scraper.CaptchaFunction = func(originalURL string, siteKey string) (string, error) {
  // CaptchaFunction should return the token as a string.
  return "", nil
}

req, _: = http.NewRequest("GET", "https://www.nakedcph.com/en/product/9468/nike-sportswear-dunk-low-disrupt-ck6654-001", nil)

req.Header = http.Header{
  "sec-ch-ua":                 {`"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"`},
  "sec-ch-ua-mobile":          {`?0`},
  "upgrade-insecure-requests": {`1`},
  "user-agent":                {`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36`},
  "accept":                    {`text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9`},
  "sec-fetch-site":            {`none`},
  "sec-fetch-mode":            {`navigate`},
  "sec-fetch-user":            {`?1`},
  "sec-fetch-dest":            {`document`},
  "accept-encoding":           {`gzip, deflate`},
  "accept-language":           {`en-US,en;q=0.9`},
  http.HeaderOrderKey:         {"sec-ch-ua", "sec-ch-ua-mobile", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language"},
  http.PHeaderOrderKey:        {":method", ":authority", ":scheme", ":path"},
}

resp, err := scraper.Do(req)

```

All of the logic is based off of HawkAPIs cloudscraper.

Thanks to [zMrKrabz](https://github.com/zMrKrabz) for [fhttp](https://github.com/useflyent/fhttp)

For most questions I'd make a ticket in HawkAPI's discord server but if needed my discord is `Humphreyyyy#0088`.
