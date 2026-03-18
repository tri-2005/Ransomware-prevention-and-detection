import time
import os
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import deque

# -------- CONFIG -------- #
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MONITOR_FOLDER = os.path.join(BASE_DIR, "../test_files")
LOG_FILE = os.path.join(BASE_DIR, "../logs/detection.log")
ALERT_FLAG = os.path.join(BASE_DIR, "../logs/alert.flag")

SUSPICIOUS_EXTENSION = ".locked"
MAX_EVENTS = 3
TIME_WINDOW = 5

RANSOMWARE_PROCESS_NAME = "ransomware_simulator.py"
# ------------------------ #

event_times = deque()
alert_triggered = False


class RansomwareDetector(FileSystemEventHandler):

    def on_created(self, event):
        if not event.is_directory:
            self.process_event(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_event(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.process_event(event.dest_path)

    def process_event(self, file_path):
        global alert_triggered

        current_time = time.time()
        event_times.append(current_time)

        while event_times and current_time - event_times[0] > TIME_WINDOW:
            event_times.popleft()

        if file_path.endswith(SUSPICIOUS_EXTENSION):
            print(f"[DEBUG] Encrypted file detected: {file_path}")

            if len(event_times) >= MAX_EVENTS and not alert_triggered:
                alert_triggered = True
                self.alert()
                terminate_ransomware_process()

    def alert(self):
        with open(LOG_FILE, "a") as log:
            log.write(f"[DETECTION_TIME] Detection at {time.time()}\n")

        with open(LOG_FILE, "a") as log:
            log.write(
                f"[ALERT] Ransomware detected at {time.ctime()}\n"
            )
        print("\n🚨 ALERT: RANSOMWARE DETECTED 🚨")
        print("Action: Process termination initiated\n")

        

        # Create alert flag for GUI
        with open(ALERT_FLAG, "w") as f:
            f.write("RANSOMWARE_DETECTED")


def terminate_ransomware_process():
    print("[ACTION] Attempting to terminate ransomware process...")

    for proc in psutil.process_iter(['pid', 'cmdline']):
        try:
            cmdline = proc.info['cmdline']
            if cmdline and RANSOMWARE_PROCESS_NAME in " ".join(cmdline):
                proc.kill()
                print(f"[SUCCESS] Terminated process PID {proc.pid}")

                with open(LOG_FILE, "a") as log:
                    log.write(
                        f"[RESPONSE] Process  terminated  at {time.ctime()}\n"
                    )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def start_detector():
    print("[INFO] Ransomware detector started")
    print("[INFO] Monitoring folder:", os.path.abspath(MONITOR_FOLDER))

    event_handler = RansomwareDetector()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_FOLDER, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Detector stopped")
        observer.stop()

    observer.join()


if __name__ == "__main__":
    start_detector()
