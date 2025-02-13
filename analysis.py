from flask import Flask, request, jsonify
import numpy as np

app = Flask(__name__)

# Global variables to keep track of previous gaze data for velocity and acceleration
last_x = None
last_y = None
last_time = None
last_velocity = 0.0

def single_update(t, x, y):
    global last_x, last_y, last_time, last_velocity
    
    # If this is the first frame, not enough data for velocity/variance:
    if last_time is None:
        last_x = x
        last_y = y
        last_time = t
        last_velocity = 0.0
        return (0.0, 0.0, 0.05)  # default for first detection
    
    # Time delta
    dt = t - last_time
    if dt <= 0.0:
        return (0.0, 0.0, 0.05)  # No forward time => return middle prob
    
    # 1) "Variance" ~ squared distance to last point
    dx = x - last_x
    dy = y - last_y
    variance = dx * dx + dy * dy  # This is an approximation of "variance"

    # 2) Velocity
    velocity = np.sqrt(variance) / dt

    # 3) Acceleration => (velocity - last_velocity)/dt
    acceleration = 0.0
    if dt > 0:
        acceleration = (velocity - last_velocity) / dt

    # 4) Clip each to [0..10], scale to [0.01..0.99]
    def clip_and_scale(value, MIN, MAX):
        val_abs = abs(value)
        clipped = min(max(val_abs, MIN), MAX)
        return 0.01 + 0.95 * (clipped / MAX)

    variance_norm = clip_and_scale(variance, 4.5e-07, 0.00013)
    # velocity_norm = clip_and_scale(velocity, 0.0, 10.0)
    acceleration_norm = clip_and_scale(acceleration, 0.3, 10.0)

    # A simple approach: average the scaled "variance" + scaled "accel"
    # or we could weigh them however we want. We'll do an average of all three.
    # You can pick just variance+acc or variance+velocity, etc.
    probability = (variance_norm + acceleration_norm) / 2.0

    # Update last_x, last_y, last_time, velocity
    last_x = x
    last_y = y
    last_time = t
    last_velocity = velocity

    return variance_norm, acceleration_norm, probability

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    time = data['time']
    x = data['x']
    y = data['y']

    # Process the gaze data with the single_update function
    variance_norm, acceleration_norm, probability = single_update(time, x, y)

    # Return the analysis result as JSON
    return jsonify({
        'variance': variance_norm,
        'acceleration': acceleration_norm,
        'probability': probability
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # Make sure to run on port 5000
