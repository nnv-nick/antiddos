package actuator

// EMABaseline отслеживает экспоненциальное скользящее среднее метрик коллектора
// в периоды отсутствия атак (AttackNone).
// Инициализируется первым поступившим значением — без раскачки.
type EMABaseline struct {
	alpha       float64
	ConnRate    float64
	initialized bool
}

// NewEMABaseline создаёт трекер с коэффициентом сглаживания α ∈ (0, 1].
func NewEMABaseline(alpha float64) *EMABaseline {
	return &EMABaseline{alpha: alpha}
}

// Update обновляет базовую линию по новому значению ConnRate.
// Должен вызываться только при Decision.Attack == AttackNone.
func (b *EMABaseline) Update(connRate float64) {
	if !b.initialized {
		b.ConnRate = connRate
		b.initialized = true
		return
	}
	b.ConnRate = b.alpha*connRate + (1-b.alpha)*b.ConnRate
}

// Initialized возвращает true, если базовая линия уже получила хотя бы одно значение.
func (b *EMABaseline) Initialized() bool {
	return b.initialized
}
