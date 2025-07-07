import subprocess
import psutil
import time
import os
import sys
import logging
import ast
import json
import asyncio
from typing import Optional, Tuple
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QTextEdit, QLabel, QTabWidget,
    QTableWidget, QTableWidgetItem, QComboBox, QMessageBox, QLineEdit
)
from PyQt6.QtCore import QTimer, Qt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt
import numpy as np

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('process_log.txt'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SandboxGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Python Sandbox")
        self.setGeometry(100, 100, 1000, 700)
        self.process: Optional[subprocess.Popen] = None
        self.psutil_process: Optional[psutil.Process] = None
        self.running = False
        self.cpu_data = []
        self.memory_data = []
        self.disk_data = []
        self.max_data_points = 60
        self.resource_limits = {'cpu': 80.0, 'memory': 500.0}  # % and MB
        self.theme = "light"
        self.init_plots()
        self.init_ui()
        self.setup_timer()

    def init_ui(self):
        """Initialize the GUI components."""
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # Tabs for different views
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Execution Tab
        execution_widget = QWidget()
        execution_layout = QVBoxLayout(execution_widget)

        # File selection
        file_layout = QHBoxLayout()
        self.file_label = QLabel("No file selected")
        self.select_button = QPushButton("Select Script")
        self.select_button.clicked.connect(self.select_file)
        file_layout.addWidget(self.file_label)
        file_layout.addWidget(self.select_button)
        execution_layout.addLayout(file_layout)

        # Control buttons
        control_layout = QHBoxLayout()
        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.start_sandbox)
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_sandbox)
        self.stop_button.setEnabled(False)
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        execution_layout.addLayout(control_layout)

        # Log display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        execution_layout.addWidget(QLabel("Process Log:"))
        execution_layout.addWidget(self.log_display)

        # Settings Tab
        settings_widget = QWidget()
        settings_layout = QVBoxLayout(settings_widget)

        # Theme and resource limits
        theme_layout = QHBoxLayout()
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark"])
        self.theme_combo.currentTextChanged.connect(self.toggle_theme)
        theme_layout.addWidget(QLabel("Theme:"))
        theme_layout.addWidget(self.theme_combo)
        settings_layout.addLayout(theme_layout)

        # Resource limits
        cpu_limit_layout = QHBoxLayout()
        self.cpu_limit_input = QLineEdit(str(self.resource_limits['cpu']))
        cpu_limit_layout.addWidget(QLabel("Max CPU (%):"))
        cpu_limit_layout.addWidget(self.cpu_limit_input)
        settings_layout.addLayout(cpu_limit_layout)

        mem_limit_layout = QHBoxLayout()
        self.mem_limit_input = QLineEdit(str(self.resource_limits['memory']))
        mem_limit_layout.addWidget(QLabel("Max Memory (MB):"))
        mem_limit_layout.addWidget(self.mem_limit_input)
        settings_layout.addLayout(mem_limit_layout)

        apply_button = QPushButton("Apply Settings")
        apply_button.clicked.connect(self.apply_settings)
        settings_layout.addWidget(apply_button)

        # Monitoring Tab
        monitoring_widget = QWidget()
        monitoring_layout = QVBoxLayout(monitoring_widget)
        self.canvas = FigureCanvas(self.figure)
        monitoring_layout.addWidget(self.canvas)

        # Network activity table
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(4)
        self.network_table.setHorizontalHeaderLabels(["Local Address", "Remote Address", "Status", "Type"])
        monitoring_layout.addWidget(QLabel("Network Activity:"))
        monitoring_layout.addWidget(self.network_table)

        self.tabs.addTab(execution_widget, "Execution")
        self.tabs.addTab(monitoring_widget, "Monitoring")
        self.tabs.addTab(settings_widget, "Settings")

        # Export button
        export_button = QPushButton("Export Log as JSON")
        export_button.clicked.connect(self.export_log)
        layout.addWidget(export_button)

    def init_plots(self):
        """Initialize Matplotlib plots for resource monitoring."""
        self.figure, (self.ax_cpu, self.ax_mem) = plt.subplots(2, 1, figsize=(8, 4))
        self.ax_cpu.set_title("CPU Usage (%)")
        self.ax_mem.set_title("Memory Usage (MB)")
        self.ax_cpu.grid(True)
        self.ax_mem.grid(True)
        self.figure.tight_layout()

    def setup_timer(self):
        """Setup timer for real-time monitoring."""
        self.timer = QTimer()
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.update_monitoring)

    def toggle_theme(self, theme: str):
        """Toggle between light and dark themes."""
        self.theme = theme.lower()
        if self.theme == "dark":
            self.setStyleSheet("background-color: #2E2E2E; color: #FFFFFF;")
            plt.style.use('dark_background')
        else:
            self.setStyleSheet("background-color: #FFFFFF; color: #000000;")
            plt.style.use('default')
        self.figure.canvas.draw()
        logger.info(f"Theme changed to {theme}")

    def apply_settings(self):
        """Apply resource limit settings."""
        try:
            self.resource_limits['cpu'] = float(self.cpu_limit_input.text())
            self.resource_limits['memory'] = float(self.mem_limit_input.text())
            logger.info(f"Updated resource limits: {self.resource_limits}")
            QMessageBox.information(self, "Settings", "Settings applied successfully.")
        except ValueError:
            logger.error("Invalid resource limit values.")
            QMessageBox.critical(self, "Error", "Please enter valid numeric values for resource limits.")

    def select_file(self):
        """Open file dialog to select Python script."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Python Script", "", "Python Files (*.py)"
        )
        if file_path:
            self.file_label.setText(file_path)
            logger.info(f"Selected file: {file_path}")

    def analyze_code(self, code_path: str) -> bool:
        """Analyze code for potential malicious patterns."""
        try:
            with open(code_path, 'r') as f:
                code = f.read()
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['os.system', 'subprocess.run', 'eval', 'exec']:
                            logger.warning(f"Potentially dangerous call detected: {node.func.id}")
                            return False
            return True
        except Exception as e:
            logger.error(f"Code analysis failed: {e}")
            return False

    async def execute_code(self, code_path: str) -> Tuple[subprocess.Popen, str, str]:
        """Execute the Python script in a subprocess."""
        try:
            process = subprocess.Popen(
                ["python", code_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = await asyncio.get_event_loop().run_in_executor(None, process.communicate)
            logger.info(f"Started process with PID {process.pid}")
            return process, stdout, stderr
        except Exception as e:
            logger.error(f"Failed to start process: {e}")
            self.log_display.append(f"Error: {e}")
            raise

    def update_network_table(self, connections):
        """Update the network activity table."""
        self.network_table.setRowCount(len(connections))
        for i, conn in enumerate(connections):
            self.network_table.setItem(i, 0, QTableWidgetItem(f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""))
            self.network_table.setItem(i, 1, QTableWidgetItem(f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""))
            self.network_table.setItem(i, 2, QTableWidgetItem(conn.status))
            self.network_table.setItem(i, 3, QTableWidgetItem(conn.type.name))

    def monitor_process(self):
        """Monitor the running process and update GUI."""
        if not self.psutil_process:
            return

        try:
            cpu_usage = self.psutil_process.cpu_percent(interval=0.1)
            memory_info = self.psutil_process.memory_info()
            memory_usage = memory_info.rss / 1024 / 1024
            disk_io = self.psutil_process.io_counters() if hasattr(self.psutil_process, 'io_counters') else None
            network_info = self.psutil_process.connections()

            # Check resource limits
            if cpu_usage > self.resource_limits['cpu']:
                self.log_display.append(f"Warning: CPU usage ({cpu_usage:.2f}%) exceeds limit!")
                logger.warning(f"CPU usage ({cpu_usage:.2f}%) exceeds limit!")
            if memory_usage > self.resource_limits['memory']:
                self.log_display.append(f"Warning: Memory usage ({memory_usage:.2f} MB) exceeds limit!")
                logger.warning(f"Memory usage ({memory_usage:.2f} MB) exceeds limit!")

            # Update data for plots
            self.cpu_data.append(cpu_usage)
            self.memory_data.append(memory_usage)
            if disk_io:
                self.disk_data.append(disk_io.write_bytes / 1024 / 1024)
            if len(self.cpu_data) > self.max_data_points:
                self.cpu_data.pop(0)
                self.memory_data.pop(0)
                if disk_io:
                    self.disk_data.pop(0)

            # Update plots
            self.ax_cpu.clear()
            self.ax_mem.clear()
            self.ax_cpu.plot(self.cpu_data, label="CPU Usage (%)")
            self.ax_mem.plot(self.memory_data, label="Memory Usage (MB)")
            self.ax_cpu.legend()
            self.ax_mem.legend()
            self.ax_cpu.grid(True)
            self.ax_mem.grid(True)
            self.ax_cpu.set_title("CPU Usage (%)")
            self.ax_mem.set_title("Memory Usage (MB)")
            self.figure.canvas.draw()

            # Update network table
            self.update_network_table(network_info)

            # Log to GUI and file
            log_message = (
                f"CPU Usage: {cpu_usage:.2f}%\n"
                f"Memory Usage: {memory_usage:.2f} MB\n"
                f"Disk Write: {disk_io.write_bytes / 1024 / 1024:.2f} MB\n" if disk_io else ""
                f"Network Connections: {len(network_info)}\n"
                f"{'-' * 20}\n"
            )
            self.log_display.append(log_message)
            logger.info(log_message.strip())

        except psutil.NoSuchProcess:
            self.log_display.append("Process finished or not found.")
            logger.info("Process finished or not found.")
            self.stop_sandbox()

    async def start_sandbox(self):
        """Start the sandboxed execution."""
        code_path = self.file_label.text()
        if not code_path or not os.path.exists(code_path):
            self.log_display.append("Error: Please select a valid Python script.")
            logger.error("Invalid or no file selected.")
            return

        if not self.analyze_code(code_path):
            self.log_display.append("Error: Potentially dangerous code detected.")
            logger.error("Potentially dangerous code detected.")
            QMessageBox.critical(self, "Error", "Code contains potentially dangerous calls.")
            return

        try:
            self.process, stdout, stderr = await self.execute_code(code_path)
            self.psutil_process = psutil.Process(self.process.pid)
            self.running = True
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.timer.start()
            self.log_display.append(f"Standard Output:\n{stdout}\n")
            self.log_display.append(f"Standard Error:\n{stderr}\n")
            logger.info("Sandbox started.")
        except Exception as e:
            self.log_display.append(f"Error starting sandbox: {e}")
            logger.error(f"Error starting sandbox: {e}")

    def stop_sandbox(self):
        """Stop the sandboxed execution."""
        if self.process:
            try:
                self.process.terminate()
                stdout, stderr = self.process.communicate(timeout=5)
                self.log_display.append(f"Standard Output:\n{stdout}\n")
                self.log_display.append(f"Standard Error:\n{stderr}\n")
                logger.info("Process terminated.")
            except subprocess.TimeoutExpired:
                self.process.kill()
                logger.warning("Process killed due to timeout.")
            finally:
                self.process = None
                self.psutil_process = None
                self.running = False
                self.start_button.setEnabled(True)
                self.stop_button.setEnabled(False)
                self.timer.stop()
                logger.info("Sandbox stopped.")

    def update_monitoring(self):
        """Update monitoring data and check process status."""
        if self.process and self.process.poll() is None:
            self.monitor_process()
        else:
            self.stop_sandbox()

    def export_log(self):
        """Export monitoring data as JSON."""
        data = {
            "cpu_usage": self.cpu_data,
            "memory_usage": self.memory_data,
            "disk_usage": self.disk_data,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Log", "", "JSON Files (*.json)"
        )
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=4)
            logger.info(f"Log exported to {file_path}")
            QMessageBox.information(self, "Export", f"Log exported to {file_path}")

async def main():
    app = QApplication(sys.argv)
    window = SandboxGUI()
    window.show()
    await asyncio.sleep(0)  # Allow GUI to process events
    sys.exit(app.exec())

if __name__ == "__main__":
    asyncio.run(main())
