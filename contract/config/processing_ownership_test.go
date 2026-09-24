package config_test

import (
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

func TestProcessingPlanViewsCannotChangeCompiledValues(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*config.ProcessingPlan)
	}{
		{"pipeline", func(p *config.ProcessingPlan) { p.Pipelines()[0].Input = "observation" }},
		{"sink", func(p *config.ProcessingPlan) { p.Pipelines()[0].Sinks[0] = "other" }},
		{"slot", func(p *config.ProcessingPlan) { p.Pipelines()[0].Slots[0].Implementation = config.ReplaceHeaderValues }},
		{"arguments", func(p *config.ProcessingPlan) { p.Pipelines()[0].Slots[0].Arguments.Headers[0] = "cookie" }},
		{"route", func(p *config.ProcessingPlan) { p.Routes()[0].Sink = "other" }},
		{"exclusion", func(p *config.ProcessingPlan) { p.Exclusions()[0].Header = "cookie" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := acceptedProcessing(t, protectedProcessing(t))
			tc.change(p)
			pipe := p.Pipelines()[0]
			if pipe.Input != "reconstruction" || pipe.Sinks[0] != "account" || pipe.Slots[0].Implementation != config.RemoveHeaders || pipe.Slots[0].Arguments.Headers[0] != "authorization" || p.Routes()[0].Sink != "account" || p.Exclusions()[0].Header != "authorization" {
				t.Fatalf("executor view changed frozen configuration: pipelines=%+v routes=%+v exclusions=%+v", p.Pipelines(), p.Routes(), p.Exclusions())
			}
		})
	}
}

func TestProcessingEnabledExternalComponentRefusal(t *testing.T) {
	c := processingConfiguration(t)
	p := processingPack()
	p.Components = []config.Component{independentProcessor("external", config.ExecutionExternal)}
	p.Components[0].Input.Types = []string{"reconstruction"}
	p.Components[0].Output.Records = []string{"reconstruction"}
	// Supplying this structurally valid pack alone does not enable its code.
	acceptedProcessing(t, c, p)
	c.Packs = []string{p.Name}
	refusedProcessing(t, c, config.UnsupportedComponent, p)
}
