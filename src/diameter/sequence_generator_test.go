package diameter

import (
	"testing"
)

func TestUint32RandomSeedSequenceGenerator(t *testing.T) {
	g, err := newUint32RandSeedSequenceNumberGenerator()

	if err != nil {
		t.Fatalf("newUint32RandSeedSequenceNumberGenerator() generated error: %s", err)
	}

	ival := g.NextSequenceValue()

	for i := uint32(1); i < 100; i++ {
		nval := g.NextSequenceValue()

		if nval != ival+i {
			t.Errorf("For start value [%d], iteration [%d], NextSequenceValue() expect [%d], got [%d]", ival, i, ival+i, nval)
		}
	}
}

func TestUint32FixedSeedSequenceGenerator(t *testing.T) {
	g := newUint32FixedSeedSequenceNumberGenerator(1000)

	for i := uint32(1000); i < 1100; i++ {
		nval := g.NextSequenceValue()

		if nval != i {
			t.Errorf("For start value [1000], NextSequenceValue() expect [%d], got [%d]", i, nval)
		}
	}

	// testing uint32 counter wrap
	g = newUint32FixedSeedSequenceNumberGenerator(0xfffffff0)

	for i := uint32(0xfffffff0); i < 0xffffffff; i++ {
		nval := g.NextSequenceValue()

		if nval != i {
			t.Errorf("For start value [0xfffffff0], NextSequenceValue() expect [%08x], got [%08x]", i, nval)
		}
	}

	nval := g.NextSequenceValue()
	if nval != uint32(0xffffffff) {
		t.Errorf("For start value [0xfffffff0], NextSequenceValue() expect [ffffffff], got [%08x]", nval)
	}

	for i := uint32(0); i < 10; i++ {
		nval := g.NextSequenceValue()

		if nval != i {
			t.Errorf("For start value [0xfffffff0], NextSequenceValue() expect [%08x], got [%08x]", i, nval)
		}
	}
}
