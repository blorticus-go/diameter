package diameter

import (
	"crypto/rand"
	"math/big"
	"time"
)

type uint32SequenceNumberGeneratorType interface {
	NextSequenceValue() uint32
}

type uint32SequenceNumberGenerator struct {
	valChan chan uint32
}

func newUint32FixedSeedSequenceNumberGenerator(seed uint32) *uint32SequenceNumberGenerator {
	c := make(chan uint32)

	go func(seed uint32, c chan uint32) {
		for nextval := seed; ; nextval++ {
			c <- nextval
		}
	}(seed, c)

	return &uint32SequenceNumberGenerator{c}
}

func newUint32RandSeedSequenceNumberGenerator() (*uint32SequenceNumberGenerator, error) {
	seed, err := rand.Int(rand.Reader, big.NewInt(0xffffffffffffffff>>1))

	if err != nil {
		return nil, err
	}

	return newUint32FixedSeedSequenceNumberGenerator(uint32(seed.Uint64())), nil
}

func newUint32TimeSplitSeedSequenceNumberGenerator() (*uint32SequenceNumberGenerator, error) {
	baseSeed, err := rand.Int(rand.Reader, big.NewInt(0xffffffffffffffff>>1))

	if err != nil {
		return nil, err
	}

	// 18 bits worth of milliseconds, which is large enough to hold 240,000 milliseconds,
	// which is 4 minutes
	time := uint32(time.Now().UnixNano()/int64(1e6)) << 14

	seed := time | (uint32(baseSeed.Uint64()) & uint32(0x0004ffff))

	return newUint32FixedSeedSequenceNumberGenerator(seed), nil
}

func (generator *uint32SequenceNumberGenerator) NextSequenceValue() uint32 {
	return <-generator.valChan
}
