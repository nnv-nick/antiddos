package actuator

type EMABaseline struct {
	alpha       float64
	ConnRate    float64
	initialized bool
}

func NewEMABaseline(alpha float64) *EMABaseline {
	return &EMABaseline{alpha: alpha}
}

func (b *EMABaseline) Update(connRate float64) {
	if !b.initialized {
		b.ConnRate = connRate
		b.initialized = true
		return
	}
	b.ConnRate = b.alpha*connRate + (1-b.alpha)*b.ConnRate
}

func (b *EMABaseline) Initialized() bool {
	return b.initialized
}
