package server

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRolloutController_MatchesAllowlistItems(t *testing.T) {
	rc := NewRolloutController(0, []string{"1", "2"}).WithEnabled(true)

	assert.True(t, rc.RequestUsesRolloutGroup(&http.Request{Header: http.Header{"Cookie": []string{"kamal-rollout=1"}}}))
	assert.True(t, rc.RequestUsesRolloutGroup(&http.Request{Header: http.Header{"Cookie": []string{"kamal-rollout=2"}}}))

	assert.False(t, rc.RequestUsesRolloutGroup(&http.Request{Header: http.Header{"Cookie": []string{"kamal-rollout=3"}}}))
	assert.False(t, rc.RequestUsesRolloutGroup(&http.Request{}))
}

func TestRolloutController_PercentageSplit(t *testing.T) {
	rc := NewRolloutController(60, []string{}).WithEnabled(true)

	usedRolloutGroup := 0
	for i := range 1000 {
		req := &http.Request{Header: http.Header{"Cookie": []string{fmt.Sprintf("kamal-rollout=%05d", i)}}}
		if rc.RequestUsesRolloutGroup(req) {
			usedRolloutGroup++
		}
	}

	assert.InDelta(t, 600, usedRolloutGroup, 20)

	assert.False(t, rc.RequestUsesRolloutGroup(&http.Request{}))
}

func TestRolloutController_AllowListAndPercentageTogether(t *testing.T) {
	rc := NewRolloutController(10, []string{"00001", "00002"}).WithEnabled(true)

	usedRolloutGroup := 0
	for i := range 1000 {
		req := &http.Request{Header: http.Header{"Cookie": []string{fmt.Sprintf("kamal-rollout=%05d", i)}}}
		if rc.RequestUsesRolloutGroup(req) {
			usedRolloutGroup++
		}
	}

	assert.InDelta(t, 100, usedRolloutGroup, 20)

	assert.True(t, rc.RequestUsesRolloutGroup(&http.Request{Header: http.Header{"Cookie": []string{"kamal-rollout=00001"}}}))
	assert.True(t, rc.RequestUsesRolloutGroup(&http.Request{Header: http.Header{"Cookie": []string{"kamal-rollout=00002"}}}))

	assert.False(t, rc.RequestUsesRolloutGroup(&http.Request{}))
}

func TestRolloutController_DisabledByDefault(t *testing.T) {
	rc := NewRolloutController(100, []string{"1"})
	req := &http.Request{Header: http.Header{"Cookie": []string{"kamal-rollout=1"}}}

	assert.False(t, rc.RequestUsesRolloutGroup(req))
	assert.True(t, rc.WithEnabled(true).RequestUsesRolloutGroup(req))
}

func TestRolloutController_ZeroSplitMatchesNothing(t *testing.T) {
	rc := NewRolloutController(0, []string{}).WithEnabled(true)

	for i := range 1000 {
		req := &http.Request{Header: http.Header{"Cookie": []string{fmt.Sprintf("kamal-rollout=%05d", i)}}}
		assert.False(t, rc.RequestUsesRolloutGroup(req))
	}
}

func TestRolloutController_WithSplitAndWithEnabledKeepOtherFields(t *testing.T) {
	rc := NewRolloutController(10, []string{"1"}).WithEnabled(true)

	updated := rc.WithSplit(20, []string{"2"})
	assert.True(t, updated.Enabled)
	assert.Equal(t, 20, updated.Percentage)
	assert.Equal(t, []string{"2"}, updated.Allowlist)

	disabled := updated.WithEnabled(false)
	assert.False(t, disabled.Enabled)
	assert.Equal(t, 20, disabled.Percentage)
	assert.Equal(t, []string{"2"}, disabled.Allowlist)

	assert.True(t, rc.Enabled)
	assert.Equal(t, 10, rc.Percentage)
}
