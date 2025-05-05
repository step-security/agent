package main

import (
	"errors"
	"fmt"
	"sync"
)

const (
	AgentTypeOSS = "agent-oss"
)

type GlobalFeatureFlags struct {
	AgentType    string `json:"agent_type"`
	EnableArmour bool   `json:"enable_armour"`
}

// GlobalFeatureFlagManager manages fetching and caching of global feature flags.
type GlobalFeatureFlagManager struct {
	apiURL    string
	flags     GlobalFeatureFlags
	mutex     sync.RWMutex
	apiClient *ApiClient
}

// Global manager instance
var globalManager *GlobalFeatureFlagManager
var globalOnce sync.Once

// InitGlobalFeatureFlags initializes the global feature flag manager.
// Call this function once in your main function or before accessing the flags.
func InitGlobalFeatureFlags(apiURL string, apiClient *ApiClient) {
	globalOnce.Do(func() {
		globalManager = &GlobalFeatureFlagManager{
			apiURL:    apiURL,
			flags:     GlobalFeatureFlags{}, // Default values
			apiClient: apiClient,
		}
		// Fetch initial flags and handle errors gracefully
		err := globalManager.refresh()
		if err != nil {
			// Log error and continue with default flags
			WriteLog(fmt.Sprintf("Error initializing global feature flags: %v", err))
		}
	})
}

// refresh makes an HTTPS call to fetch global feature flags and updates the manager.
func (manager *GlobalFeatureFlagManager) refresh() error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	flags := manager.apiClient.getGlobalFeatureFlags()
	WriteLog(fmt.Sprintf("Global feature flags: %+v", flags))
	manager.flags = flags
	return nil
}

// RefreshGlobalFeatureFlags updates the global feature flags manually.
func RefreshGlobalFeatureFlags() error {
	if globalManager == nil {
		return errors.New("global feature flag manager is not initialized")
	}
	return globalManager.refresh()
}

// GetGlobalFeatureFlags returns the current global feature flags.
// This method never returns nil. It returns a default-initialized struct if manager is not initialized.
func GetGlobalFeatureFlags() GlobalFeatureFlags {
	if globalManager == nil {
		return GlobalFeatureFlags{} // Return default-initialized struct
	}
	globalManager.mutex.RLock()
	defer globalManager.mutex.RUnlock()
	return globalManager.flags
}

func IsArmourEnabled() bool {
	flags := GetGlobalFeatureFlags()
	return flags.EnableArmour
}
