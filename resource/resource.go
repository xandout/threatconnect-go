package resource

// Resource struct containing the desired endpoint and HTTP method
type Resource struct {
	EndPoint string
	Method   string
}

// NewResource creates a new Resource
func NewResource(endpoint string, method string) *Resource {
	r := new(Resource)
	r.EndPoint = endpoint
	r.Method = method
	return r
}
