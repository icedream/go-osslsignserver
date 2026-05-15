package osslsigncode

import "fmt"

type osslsigncodeParam struct {
	Key    string
	Value  string
	Switch bool
}

func (p osslsigncodeParam) Args() []string {
	a := []string{}
	if len(p.Key) > 0 {
		a = append(a, fmt.Sprintf("-%s", p.Key))
	}
	if !p.Switch {
		a = append(a, p.Value)
	}
	return a
}

type osslsigncodeParams []osslsigncodeParam

func (p *osslsigncodeParams) Add(key string, value string) {
	*p = append(*p, osslsigncodeParam{
		Key:   key,
		Value: value,
	})
}

func (p *osslsigncodeParams) AddSwitch(key string, value bool) {
	if !value {
		return
	}
	*p = append(*p, osslsigncodeParam{
		Key:    key,
		Switch: true,
	})
}

func (p *osslsigncodeParams) AddOptional(key string, value string) {
	if len(value) == 0 {
		return
	}
	p.Add(key, value)
}

func (p *osslsigncodeParams) AddMultiple(key string, values ...string) {
	for _, value := range values {
		p.Add(key, value)
	}
}

func (p *osslsigncodeParams) Append(p2 osslsigncodeParams) {
	*p = append(*p, p2...)
}

func (p osslsigncodeParams) Args() []string {
	a := []string{}
	for _, param := range p {
		a = append(a, param.Args()...)
	}
	return a
}

func (p osslsigncodeParams) Get(key string) osslsigncodeParams {
	r := osslsigncodeParams{}
	for _, param := range p {
		if param.Key == key {
			r = append(r, param)
		}
	}
	return r
}
