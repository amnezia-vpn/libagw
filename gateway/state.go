package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
)

type persistedState struct {
	Version      int                 `json:"version"`
	WorkingProxy string              `json:"working_proxy,omitempty"`
	ProxyLists   map[string][]string `json:"proxy_lists,omitempty"`
}

const stateVersion = 1

// ExportState snapshots the failover caches. The blob lists censorship-bypass
// endpoints, so hosts must keep it in protected storage.
func (c *Client) ExportState() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	lists := make(map[string][]string, len(c.proxyLists))
	for k, v := range c.proxyLists {
		lists[k] = append([]string(nil), v...)
	}
	out, _ := json.Marshal(persistedState{
		Version:      stateVersion,
		WorkingProxy: c.workingProxy,
		ProxyLists:   lists,
	})
	return out
}

// ImportState restores a blob produced by ExportState.
func (c *Client) ImportState(data []byte) error {
	var st persistedState
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	if st.Version != stateVersion {
		return fmt.Errorf("unsupported state version %d", st.Version)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.workingProxy = st.WorkingProxy
	c.proxyLists = map[string][]string{}
	for k, v := range st.ProxyLists {
		c.proxyLists[k] = append([]string(nil), v...)
	}
	return nil
}

func isInvalidKeyErr(err error) bool {
	return errors.Is(err, errInvalidPublicKey)
}
