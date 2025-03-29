package analysis

import (
	"math"
	"sync"
)

var (
	lastX, lastY, lastTime, lastVelocity float64
	mu                                   sync.Mutex
	// Create a map to hold locks for each user
	userLocks sync.Map // sync.Map for user-specific locks
)

// ClipAndScale ensures values are clipped and normalized for output
func ClipAndScale(value, min, max, scaleMin, scaleMax float64) float64 {
	valAbs := math.Abs(value)
	clipped := math.Min(math.Max(valAbs, min), max)
	return scaleMin + (scaleMax-scaleMin)*(clipped/max)
}

// AnalyzeGazeData processes gaze data and computes movement metrics
// sensitivity is a value between 0.75 and 1.25
func AnalyzeGazeData(time, x, y, sensitivity float64) (varianceNorm, accelerationNorm, probability float64) {
	// Use a user-specific lock
	userLock, _ := userLocks.LoadOrStore("user", &sync.Mutex{})
	userLock.(*sync.Mutex).Lock()
	defer userLock.(*sync.Mutex).Unlock()

	// Validate sensitivity value (between 0.75 and 1.25). If invalid, use default 1.0
	if sensitivity < 0.75 || sensitivity > 1.25 || math.IsNaN(sensitivity) || math.IsInf(sensitivity, 0) {
		sensitivity = 1.0 // Default sensitivity value
	}

	// Reset tracking if time goes backward (possible page refresh)
	if time < lastTime {
		lastX, lastY, lastTime, lastVelocity = 0, 0, 0, 0
	}

	// Initialize on first valid input
	if lastTime == 0 {
		lastX, lastY, lastTime, lastVelocity = x, y, time, 0.0
		return 0.0, 0.0, 0.05 // Default for first detection
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

	// Use sensitivity to adjust scaling of varianceNorm and accelerationNorm
	varianceNorm = ClipAndScale(variance, 4.5e-07, 0.00013, 0.01, 0.95)
	accelerationNorm = ClipAndScale(acceleration, 0.3, 10.0, 0.01, 0.95)

	// Calculate probability as average of normalized variance and acceleration
	probability = (varianceNorm + accelerationNorm) / 2.0

	// Apply sensitivity factor to adjust probability
	probability = probability * sensitivity

	// Ensure probability stays within [0, 1] range
	if probability < 0.0 {
		probability = 0.0
	} else if probability > 1.0 {
		probability = 1.0
	}

	lastX, lastY, lastTime, lastVelocity = x, y, time, velocity
	return varianceNorm, accelerationNorm, probability
}
