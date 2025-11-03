#!/bin/bash

# Run capture.py in background with defaults (or pass args if needed)
python app.py --iface=all --capture_duration=60 &

# Run predict.py in foreground (it will loop indefinitely)
python predict.py
