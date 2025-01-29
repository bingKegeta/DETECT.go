import sys
import json
import random

def generate_random_constants():
    return {
        "constOne": random.uniform(0, 1),
        "constTwo": random.uniform(0, 1),
        "constThree": random.uniform(0, 1)
    }

def main():
    if len(sys.argv) < 2:
        print("Error: No config.json file provided")
        sys.exit(1)

    config_file = sys.argv[1]

    try:
        with open(config_file, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading config.json: {e}")
        sys.exit(1)

    result = generate_random_constants()

    print(json.dumps(result))

if __name__ == "__main__":
    main()
