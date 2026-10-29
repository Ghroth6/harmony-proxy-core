package bridge

import "github.com/metacubex/mihomo/config"

func SetPolicyReady(ready func(uint64, *config.Config) error) {
	mobileRuntimeManager.SetPolicyReady(ready)
}
func WithActivePolicy(generation uint64, instance, candidate string, action func(*config.Config) error) error {
	return mobileRuntimeManager.WithActivePolicy(generation, instance, candidate, action)
}
