### SVN Downloader for svn web server ###

it is a practice for Golang. The story is based on a svn web server which are used self-sign cert as https and digest auth. This tool can help you to download all files under specified folder. 

#### Prerequisite ####
fork the original and support self-sign cert

`go get github.com/ericbear/http-digest-auth-client/auth.go`

#### Usage ####

`go run dl.go [USER_NAME] [PASSWORD] [HTTPS SVN LINK]`
