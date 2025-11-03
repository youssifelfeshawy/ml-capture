To Build: sudo docker build -t my-capture-image .
To Run: sudo docker run --net=host --cap-add=NET_RAW -v $HOME/Downloads:/output my-capture-image python capture.py --iface=all --timeout=60 --output=/output/my_custom_capture.csv
