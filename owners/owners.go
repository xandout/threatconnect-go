package owners

// Result represents the JSON returned from /v2/owners
type Result struct {
	Status string `json:"status"`
	Data   struct {
		ResultCount int `json:"resultCount"`
		Owners      []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"owner"`
	} `json:"data"`
}

// Owner represents a single owner
type Owner struct {
	Status string `json:"status"`
	Data   struct {
		ResultCount int `json:"resultCount"`
		Owner       struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"owner"`
	} `json:"data"`
}
