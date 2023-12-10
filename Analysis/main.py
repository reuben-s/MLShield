from pywinpipes import PipeServer
import tkinter as tk
import multiprocessing
import queue
from datetime import datetime

PIPE_NAME = "TestPipe"

class InterfaceManager:
    def __init__(self, gui=False):
        if gui:
            self.message_queue = multiprocessing.Queue()

            self.connected_clients = []

            gui_process = multiprocessing.Process(target=self.run_gui)
            gui_process.start()

        self.pipe_sever = PipeServer(PIPE_NAME, new_message=self.new_message)

    def new_message(self, client, message):
        print(f"{client.pid}-> \"{message}\"")

        self.message_queue.put({"pid": client.pid, "message": message})
        # client.send_message("Response from server") This blocks so ignore for now

    def run_gui(self):
        root = tk.Tk()
        root.title("MLShield Debug View")
        root.resizable(False, False)

        process_activity_label = tk.Label(root, text="Process activity")
        process_activity_label.grid(row=0, column=1, padx=10)

        console_text = tk.Text(root, wrap=tk.WORD, state=tk.DISABLED)
        console_text.grid(row=1, column=1)

        details_frame = tk.LabelFrame(root, text="Pipe server details")
        details_frame.grid(row=2, column=1)

        server_status = tk.Label(details_frame, text="Server status: Waiting for new connection ...")
        server_status.grid(row=0, column=0, padx=5, sticky="w")

        no_connected_clients = tk.Label(details_frame, text="Number of connected clients: ")
        no_connected_clients.grid(row=1, column=0, padx=5, sticky="w")

        console_text.tag_configure("pid_color", foreground="red")

        def update_gui():
            while True:
                try:
                    no_connected_clients.config(text=f"Number of connected clients: {len(self.connected_clients)}")

                    event = self.message_queue.get_nowait()

                    if event["pid"] not in self.connected_clients:
                        self.connected_clients.append(event["pid"])
                        console_text.insert(tk.END, event["pid"])

                    console_text.config(state=tk.NORMAL)
                    console_text.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ")
                    console_text.insert(tk.END, f"PID: {event['pid']}", "pid_color")
                    console_text.insert(tk.END, f"-> {event['message']}\n")
                    console_text.config(state=tk.DISABLED)
                    console_text.yview(tk.END)
                    
                except queue.Empty:
                    break
            root.after(100, update_gui)

        root.after(100, update_gui)  # Schedule the next update

        root.mainloop()
        
if __name__ == "__main__":
    interface_manager = InterfaceManager(gui=True)