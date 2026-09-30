package merge_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	merge "zolana/prover/circuits/spp_merge"
)

// padFixtureCompact publishes 0 for every dummy slot of the fixture: compact
// padding, which SPP leaves out of the instruction (spec: Compact padding).
func padFixtureCompact(t *testing.T, fixture *mergeWitnessFixture) {
	t.Helper()
	for slot := 2; slot < len(fixture.public.Nullifiers); slot++ {
		fixture.public.Nullifiers[slot] = big.NewInt(0)
	}
	refreshDefaultPublicInputHash(t, fixture)
}

func TestMergeCompactPaddingSolves(t *testing.T) {
	assert := test.NewAssert(t)
	fixture := buildMergeFixture(t, mergeFixtureOptions{})
	padFixtureCompact(t, fixture)
	assert.SolvingSucceeded(merge.NewMergeCircuit(defaultFixtureInputs), fixture.defaultCircuit(), test.WithCurves(ecc.BN254))
}

// Compact padding inserts no nullifier, so the tree-capacity gate does not
// apply to it.
func TestMergeCompactPaddingSolvesWhenDummyInputsDisallowed(t *testing.T) {
	assert := test.NewAssert(t)
	fixture := buildMergeFixture(t, mergeFixtureOptions{allowDummyInputs: big.NewInt(0)})
	padFixtureCompact(t, fixture)
	assert.SolvingSucceeded(merge.NewMergeCircuit(defaultFixtureInputs), fixture.defaultCircuit(), test.WithCurves(ecc.BN254))
}

// A real input that publishes nullifier 0 would skip its nullifier insertion.
func TestMergeRejectsZeroNullifierOnRealSlot(t *testing.T) {
	assert := test.NewAssert(t)
	fixture := buildMergeFixture(t, mergeFixtureOptions{})
	fixture.public.Nullifiers[1] = big.NewInt(0)
	refreshDefaultPublicInputHash(t, fixture)
	assert.SolvingFailed(merge.NewMergeCircuit(defaultFixtureInputs), fixture.defaultCircuit(), test.WithCurves(ecc.BN254))
}
