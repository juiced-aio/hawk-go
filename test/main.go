package main

import (
	"fmt"
	"net/http"

	cclient "github.com/IHaveNothingg/cclientwtf"
	tls "github.com/Titanium-ctrl/utls"
	hawkgo "github.com/juiced-aio/hawk-go"
)

func main() {
	client, err := cclient.NewClient(tls.HelloChrome_83, "http://localhost:8888")
	if err != nil {
		fmt.Println(err)
		return
	}
	px, err := hawkgo.PXInit(client, "www.walmart.com", "key_here")
	if err != nil {
		fmt.Println(err)
		return
	}

	req, _ := http.NewRequest("GET", "https://www.walmart.com", nil)
	req.RawHeader = http.RawHeader{
		{"sec-ch-ua", `"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"`},
		{"sec-ch-ua-mobile", `?0`},
		{"upgrade-insecure-requests", `1`},
		{"user-agent", `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36`},
		{"accept", `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9`},
		{"sec-fetch-site", `none`},
		{"sec-fetch-mode", `navigate`},
		{"sec-fetch-user", `?1`},
		{"sec-fetch-dest", `document`},
		{"accept-encoding", `gzip, deflate, br`},
		{"accept-language", `en-US,en;q=0.9`},
	}

	resp, _ := client.Do(req)
	fmt.Println(resp.StatusCode)

	fmt.Println(px.SolveNormal("https://www.walmart.com"))
}
