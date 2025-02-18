package analysis

import (
	"math"
	"sync"
)

var (
	lastX, lastY, lastTime, lastVelocity float64
	mu                                   sync.Mutex
)

func ClipAndScale(value, min, max, scaleMin, scaleMax float64) float64 {
	valAbs := math.Abs(value)
	clipped := math.Min(math.Max(valAbs, min), max)
	return scaleMin + (scaleMax-scaleMin)*(clipped/max)
}

func AnalyzeGazeData(time, x, y float64) (varianceNorm, accelerationNorm, probability float64) {
	mu.Lock()
	defer mu.Unlock()

	if lastTime == 0 {
		lastX, lastY, lastTime, lastVelocity = x, y, time, 0.0
		return 0.0, 0.0, 0.05 // default for first detection
	}

	dt := time - lastTime
	if dt <= 0.0 {
		return 0.0, 0.0, 0.05 // No forward time => return middle prob
	}

	dx := x - lastX
	dy := y - lastY
	variance := dx*dx + dy*dy
	velocity := math.Sqrt(variance) / dt

	// Guard against small dt for stability
	const epsilon = 1e-6
	acceleration := 0.0
	if dt > epsilon {
		acceleration = (velocity - lastVelocity) / dt
	}

	varianceNorm = ClipAndScale(variance, 4.5e-07, 0.00013, 0.01, 0.95)
	accelerationNorm = ClipAndScale(acceleration, 0.3, 10.0, 0.01, 0.95)

	probability = (varianceNorm + accelerationNorm) / 2.0

	lastX, lastY, lastTime, lastVelocity = x, y, time, velocity
	return varianceNorm, accelerationNorm, probability
}
