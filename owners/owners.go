package owners

// SingleOwner is the base Owner structure
type SingleOwner struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// Result represents the JSON returned from /v2/owners
type Result struct {
	Status string `json:"status"`
	Data   struct {
		ResultCount int           `json:"resultCount"`
		Owners      []SingleOwner `json:"owner"`
	} `json:"data"`
}

// Owner represents a single owner
type Owner struct {
	Status string `json:"status"`
	Data   struct {
		ResultCount int         `json:"resultCount"`
		Owner       SingleOwner `json:"owner"`
	} `json:"data"`
}
