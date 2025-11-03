Here’s a clean, professional, and easy-to-read **`README.md`** version of your Docker instructions:

---

# 🐳 Packet Capture Tool

This project provides a simple Dockerized setup for capturing network traffic and exporting it as a CSV file for analysis.

---

## 📦 Build the Docker Image

To build the image, run the following command in the project directory (where the `Dockerfile` is located):

```bash
sudo docker build -t my-capture-image .
```

This will create a Docker image named **`my-capture-image`**.

---

## 🚀 Run the Capture Tool

Use the following command to run the container and start capturing packets:

```bash
sudo docker run --net=host --cap-add=NET_RAW -v $HOME/Downloads:/output my-capture-image \
python capture.py --iface=all --timeout=60 --output=/output/my_custom_capture.csv
```

### 🔍 Command Breakdown

| Option                                   | Description                                                                                      |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `--net=host`                             | Grants the container direct access to the host’s network interfaces.                             |
| `--cap-add=NET_RAW`                      | Allows the container to capture raw network packets.                                             |
| `-v $HOME/Downloads:/output`             | Mounts your local **Downloads** directory into the container’s `/output` folder to save results. |
| `python capture.py`                      | Runs the Python script responsible for packet capture.                                           |
| `--iface=all`                            | Captures packets on all available network interfaces.                                            |
| `--timeout=60`                           | Capture duration in seconds (you can change this value).                                         |
| `--output=/output/my_custom_capture.csv` | Path and name of the output CSV file.                                                            |

---

## 🗂 Output

After the capture completes, you’ll find the output file in your **Downloads** directory:

```
~/Downloads/my_custom_capture.csv
```

You can open it using Excel, Python (pandas), or any data analysis tool.

---

## ⚙️ Customization

You can modify the command parameters:

* Change `--timeout` to control capture duration.
* Replace `--iface=all` with a specific interface name (e.g., `eth0`).
* Update the output file path or name.

---

## 🧹 Cleanup

To remove the container after running:

```bash
sudo docker ps -a
sudo docker rm <container_id>
```

To remove the image (optional):

```bash
sudo docker rmi my-capture-image
```
