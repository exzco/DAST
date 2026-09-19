package fingerprint

type ProductRegistry struct {}

func NewProductRegistry(path string) (*ProductRegistry, error) {
    return &ProductRegistry{}, nil
}

func (r *ProductRegistry) MatchBanner(banner string) string {
    //todo...
    return ""
}
