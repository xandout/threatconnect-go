package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/xandout/threatconnect-go/config"
	"github.com/xandout/threatconnect-go/resource"
)

func computeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Signature defines the various parts of an HMAC signature for TC
type Signature struct {
	Timestamp int64
	Unsigned  string
	Signed    string
}

// Sign creates an HMAC signature for TC API calls
func Sign(config config.Config, resource resource.Resource) *Signature {
	s := new(Signature)
	fullURLString := fmt.Sprintf("%s%s", config.APIURL, resource.EndPoint)
	url, err := url.Parse(fullURLString)
	if err != nil {
		log.Fatal(err)
	}
	requestURI := url.RequestURI()
	template := "%s:%s:%d"
	signature := fmt.Sprintf(template, requestURI, resource.Method, time.Now().Unix())
	signed := computeHmac256(signature, config.APISecret)
	s.Timestamp = time.Now().Unix()
	s.Unsigned = fmt.Sprintf("TC %s:%s", config.APIID, signature)
	s.Signed = fmt.Sprintf("TC %s:%s", config.APIID, signed)
	return s
}
