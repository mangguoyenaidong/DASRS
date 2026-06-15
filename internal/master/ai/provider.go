package ai

import "context"

// Provider defines the AI capabilities exposed to the DASRS master.
type Provider interface {
	GenerateRule(ctx context.Context, input RuleGenInput) (*RuleGenResult, error)
	AnalyzeAlert(ctx context.Context, input AlertAnalysisInput) (*AlertAnalysisResult, error)
}

// ChatProvider exposes a generic operations chat capability for AI providers.
type ChatProvider interface {
	Chat(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}
