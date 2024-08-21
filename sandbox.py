import subprocess
import psutil
import time
import os

# Function to execute the potentially malicious code
def execute_code(code_path):
    process = subprocess.Popen(["python3", code_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process

# Function to monitor the process
def monitor_process(process):
    try:
        p = psutil.Process(process.pid)
        with open('process_log.txt', 'w') as log_file:
            while True:
                cpu_usage = p.cpu_percent(interval=1)
                memory_info = p.memory_info()
                network_info = p.connections()
                log_file.write(f"CPU Usage: {cpu_usage}%\n")
                log_file.write(f"Memory Info: {memory_info}\n")
                log_file.write(f"Network Info: {network_info}\n")
                log_file.write('-' * 20 + '\n')

                if process.poll() is not None:  # Check if the process has finished
                    break

                time.sleep(1)
    except psutil.NoSuchProcess:
        print("Process finished or not found.")

# Main function to setup the sandbox
def sandbox(code_path):
    process = execute_code(code_path)
    monitor_process(process)
    stdout, stderr = process.communicate()
    print("Standard Output:", stdout.decode())
    print("Standard Error:", stderr.decode())

if __name__ == "__main__":
    code_path = "malicious_test.py"  # Ensure this path is correct
    sandbox(code_path)

