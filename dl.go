package main

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"

	digestAuth "github.com/ericbear/http-digest-auth-client"

	"log"
)

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func httpGet(url string, digestHeaders *digestAuth.DigestHeaders) string {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("GET", url, nil)
	digestHeaders.ApplyAuth(req)
	
	check(err)
	
	resp, err := client.Do(req)
	
	check(err)
	
	//determine auth or not
	if resp.StatusCode == 401 {
		updateAuth(digestHeaders, user, pass, url)
		
		return httpGet(url, digestHeaders)
	} else {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)

		check(err)

		return string(body)
	}
}

func isSvnList(body string) bool {
	return strings.Contains(body, "Powered by <a href=\"http://subversion.apache.org/\">Apache Subversion</a>")
}

func isSvnLink(body string) (bool, string) {
	reg, _ := regexp.Compile("<li><a href=\"(.*)\">(.*)</a></li>")
	match := reg.MatchString(body)

	if match {
		return true, strings.TrimSpace(reg.ReplaceAllString(body, "$2"))
	} else {
		return false, ""
	}
}

func saveFile(fileName string, data string) {
	basePath := path.Dir(fileName)

	if os.MkdirAll(basePath, 0755) != nil {
		log.Fatal("can't MkdirAll: " + basePath)
	}

	saveFile, err := os.Create(fileName)
	
	if err != nil {
		log.Println(err)
	} else {
		saveFile.WriteString(data)
		defer saveFile.Close()
	}
}

func downloadSvn(url string, fileName string, digestHeaders *digestAuth.DigestHeaders) {
	data := httpGet(url, digestHeaders)

	if isSvnList(data) {
		lines := strings.Split(data, "\n")
		
		list := make(map[string]string)

		//find out which line is candidate
		for _, line := range lines {
			match, replacement := isSvnLink(line)

			if strings.EqualFold(replacement, "..") {
				match = false
			}

			if match {
				//save url into map
				list[fileName+replacement] = url+replacement
			}
		}
		
		for _file, _url := range list {
			downloadSvn(_url, _file, digestHeaders)
		}
	} else {
		saveFile(fileName, data)

		log.Println("save: " + fileName + " <- " + url)
	}
}

func updateAuth(digestHeaders *digestAuth.DigestHeaders, _user string, _pass string, _url string) {
	log.Println("require auth")
	
	_digestHeaders, err := digestHeaders.Auth(_user, _pass, _url, true)

	check(err)

	//copy auth info into original one
	digestHeaders.Path = _digestHeaders.Path
	digestHeaders.Realm = _digestHeaders.Realm
	digestHeaders.Qop = _digestHeaders.Qop
	digestHeaders.Nonce = _digestHeaders.Nonce
	digestHeaders.Opaque = _digestHeaders.Opaque
	digestHeaders.Algorithm = _digestHeaders.Algorithm
	digestHeaders.Nc = _digestHeaders.Nc
	digestHeaders.Username = _digestHeaders.Username
	digestHeaders.Password = _digestHeaders.Password
}

var user string
var pass string

func main() {
	if len(os.Args) != 4 {
		log.Fatal("missing arguments. [script] [user] [pass] [url]")
	}

	user = os.Args[1]
	pass = os.Args[2]
	var url string = os.Args[3]

	digestHeaders := &digestAuth.DigestHeaders{}

	downloadSvn(url, "", digestHeaders)
}
