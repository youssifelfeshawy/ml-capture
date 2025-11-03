# 🐳 Packet Capture Tool

This project provides a simple **Dockerized setup** for continuously capturing network traffic and exporting it as CSV files for analysis using **Scapy**.

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
sudo docker run --net=host --cap-add=NET_RAW -v /tmp/captures:/tmp/captures my-capture-image
```

The container will automatically execute the **`capture.py`** script, continuously capturing live traffic and generating timestamped CSV files inside `/tmp/captures`.

---

### 🔍 Command Breakdown

| Option                           | Description                                                                     |
| -------------------------------- | ------------------------------------------------------------------------------- |
| `--net=host`                     | Grants the container direct access to the host’s network interfaces.            |
| `--cap-add=NET_RAW`              | Allows the container to capture raw network packets.                            |
| `-v /tmp/captures:/tmp/captures` | Mounts the host’s `/tmp/captures` directory into the container to save results. |
| `my-capture-image`               | The Docker image that contains the capture script and dependencies.             |

---

## 🗂 Output

After the capture completes, you’ll find the generated CSV files inside:

```
/tmp/captures/
```

Each file is automatically named based on the timestamp of the capture (e.g., `capture_20251103_153045.csv`).

You can open them using:

* Excel or LibreOffice Calc
* Python libraries like **pandas**
* Any data analysis tool that supports CSV

---

## ⚙️ Customization

You can modify capture parameters directly in the command:

* Change `--capture_duration` to control capture duration (default: 60 seconds).
* Replace `--iface=all` with a specific interface name (e.g., `eth0`).
* Adjust the output directory if you want to store captures elsewhere.

Example:

```bash
sudo docker run --net=host --cap-add=NET_RAW -v /tmp/captures:/tmp/captures my-capture-image \
python capture.py --iface=eth0 --capture_duration=120 --output_dir=/tmp/captures
```

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

---

✅ **Notes:**

* The `/tmp/captures` folder will be **deleted after every reboot**, so save your CSVs elsewhere if needed.
* Make sure you run Docker with **sudo** or root privileges to enable packet capturing.
