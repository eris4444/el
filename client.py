import socket
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext, filedialog, messagebox
import json
import base64
import os
import uuid
from datetime import datetime
from PIL import Image, ImageTk
import io
import sys
import time

# Server configuration
HOST = '127.0.0.1'  # localhost
PORT = 5555

class ChatClient:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.client_socket = None
        self.username = ""
        self.connected = False
        self.file_transfer_active = False
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("Chat Client")
        self.root.geometry("800x600")
        self.root.configure(bg="#17212b")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Login frame
        self.login_frame = tk.Frame(self.root, bg="#17212b")
        self.create_login_widgets()
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
        # Chat frame (will be shown after login)
        self.chat_frame = tk.Frame(self.root, bg="#17212b")
        self.create_chat_widgets()
        
        # Start the GUI
        self.root.mainloop()
    
    def create_login_widgets(self):
        """Create the login screen widgets"""
        # Center frame for login
        center_frame = tk.Frame(self.login_frame, bg="#17212b", padx=20, pady=20)
        center_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        # App title
        title_label = tk.Label(
            center_frame, 
            text="Python Chat", 
            font=("Arial", 24, "bold"), 
            bg="#17212b", 
            fg="#ffffff"
        )
        title_label.pack(pady=(0, 20))
        
        # Username field
        username_frame = tk.Frame(center_frame, bg="#17212b")
        username_frame.pack(fill=tk.X, pady=5)
        
        username_label = tk.Label(
            username_frame, 
            text="Username:", 
            bg="#17212b", 
            fg="#ffffff", 
            font=("Arial", 12)
        )
        username_label.pack(anchor=tk.W)
        
        self.username_entry = tk.Entry(
            username_frame, 
            font=("Arial", 12), 
            bg="#242f3d", 
            fg="#ffffff", 
            insertbackground="#ffffff",
            relief=tk.FLAT,
            highlightthickness=1,
            highlightcolor="#4d79ff",
            highlightbackground="#242f3d"
        )
        self.username_entry.pack(fill=tk.X, pady=5)
        
        # Password field
        password_frame = tk.Frame(center_frame, bg="#17212b")
        password_frame.pack(fill=tk.X, pady=5)
        
        password_label = tk.Label(
            password_frame, 
            text="Password:", 
            bg="#17212b", 
            fg="#ffffff", 
            font=("Arial", 12)
        )
        password_label.pack(anchor=tk.W)
        
        self.password_entry = tk.Entry(
            password_frame, 
            font=("Arial", 12), 
            bg="#242f3d", 
            fg="#ffffff", 
            show="•", 
            insertbackground="#ffffff",
            relief=tk.FLAT,
            highlightthickness=1,
            highlightcolor="#4d79ff",
            highlightbackground="#242f3d"
        )
        self.password_entry.pack(fill=tk.X, pady=5)
        
        # Server settings
        server_frame = tk.Frame(center_frame, bg="#17212b")
        server_frame.pack(fill=tk.X, pady=5)
        
        server_label = tk.Label(
            server_frame, 
            text="Server:", 
            bg="#17212b", 
            fg="#ffffff", 
            font=("Arial", 12)
        )
        server_label.pack(anchor=tk.W)
        
        server_input_frame = tk.Frame(server_frame, bg="#17212b")
        server_input_frame.pack(fill=tk.X)
        
        self.host_entry = tk.Entry(
            server_input_frame, 
            font=("Arial", 12), 
            bg="#242f3d", 
            fg="#ffffff", 
            insertbackground="#ffffff",
            relief=tk.FLAT,
            highlightthickness=1,
            highlightcolor="#4d79ff",
            highlightbackground="#242f3d"
        )
        self.host_entry.insert(0, self.host)
        self.host_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        tk.Label(
            server_input_frame, 
            text=":", 
            bg="#17212b", 
            fg="#ffffff", 
            font=("Arial", 12)
        ).pack(side=tk.LEFT, padx=2)
        
        self.port_entry = tk.Entry(
            server_input_frame, 
            font=("Arial", 12), 
            width=6, 
            bg="#242f3d", 
            fg="#ffffff", 
            insertbackground="#ffffff",
            relief=tk.FLAT,
            highlightthickness=1,
            highlightcolor="#4d79ff",
            highlightbackground="#242f3d"
        )
        self.port_entry.insert(0, str(self.port))
        self.port_entry.pack(side=tk.LEFT)
        
        # Connect button
        self.connect_button = tk.Button(
            center_frame, 
            text="Connect", 
            command=self.connect_to_server,
            bg="#4d79ff", 
            fg="white", 
            font=("Arial", 12, "bold"),
            relief=tk.FLAT,
            activebackground="#3a5fcc",
            activeforeground="white",
            padx=20, 
            pady=8
        )
        self.connect_button.pack(pady=20)
        
        # Status label
        self.status_label = tk.Label(
            center_frame, 
            text="", 
            bg="#17212b", 
            fg="#ff5252", 
            font=("Arial", 10)
        )
        self.status_label.pack()
    
    def create_chat_widgets(self):
        """Create the chat screen widgets"""
        # Top bar with user info
        top_bar = tk.Frame(self.chat_frame, bg="#242f3d", height=50)
        top_bar.pack(fill=tk.X)
        top_bar.pack_propagate(False)
        
        self.chat_title = tk.Label(
            top_bar, 
            text="Chat Room", 
            font=("Arial", 14, "bold"), 
            bg="#242f3d", 
            fg="#ffffff"
        )
        self.chat_title.pack(side=tk.LEFT, padx=15)
        
        self.user_label = tk.Label(
            top_bar, 
            text="", 
            font=("Arial", 12), 
            bg="#242f3d", 
            fg="#8a9aa9"
        )
        self.user_label.pack(side=tk.RIGHT, padx=15)
        
        # Chat area
        chat_area_frame = tk.Frame(self.chat_frame, bg="#17212b")
        chat_area_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.chat_area = scrolledtext.ScrolledText(
            chat_area_frame, 
            wrap=tk.WORD, 
            bg="#17212b", 
            fg="#ffffff", 
            font=("Arial", 11),
            padx=10,
            pady=10,
            insertbackground="#ffffff",
            relief=tk.FLAT,
            highlightthickness=0
        )
        self.chat_area.pack(fill=tk.BOTH, expand=True)
        self.chat_area.config(state=tk.DISABLED)
        
        # Message input area
        input_frame = tk.Frame(self.chat_frame, bg="#242f3d", height=60)
        input_frame.pack(fill=tk.X, side=tk.BOTTOM)
        input_frame.pack_propagate(False)
        
        # File button
        self.file_button = tk.Button(
            input_frame, 
            text="📎", 
            command=self.select_file,
            bg="#242f3d", 
            fg="#ffffff", 
            font=("Arial", 16),
            relief=tk.FLAT,
            activebackground="#3a5fcc",
            activeforeground="white",
            width=3
        )
        self.file_button.pack(side=tk.LEFT, padx=5)
        
        # Message entry
        self.message_entry = tk.Entry(
            input_frame, 
            font=("Arial", 12), 
            bg="#242f3d", 
            fg="#ffffff", 
            insertbackground="#ffffff",
            relief=tk.FLAT,
            highlightthickness=1,
            highlightcolor="#4d79ff",
            highlightbackground="#242f3d"
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=10)
        self.message_entry.bind("<Return>", lambda event: self.send_message())
        
        # Send button
        self.send_button = tk.Button(
            input_frame, 
            text="Send", 
            command=self.send_message,
            bg="#4d79ff", 
            fg="white", 
            font=("Arial", 10, "bold"),
            relief=tk.FLAT,
            activebackground="#3a5fcc",
            activeforeground="white",
            width=8
        )
        self.send_button.pack(side=tk.RIGHT, padx=10)
    
    def connect_to_server(self):
        """Connect to the chat server"""
        self.username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        # Validate inputs
        if not self.username:
            self.status_label.config(text="Username is required")
            return
        
        if not password:
            self.status_label.config(text="Password is required")
            return
        
        try:
            # Update host and port from entries
            self.host = self.host_entry.get().strip()
            self.port = int(self.port_entry.get().strip())
            
            # Disable connect button
            self.connect_button.config(state=tk.DISABLED, text="Connecting...")
            self.status_label.config(text="Connecting to server...")
            
            # Create socket and connect
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
            
            # Send authentication data
            auth_data = {
                "username": self.username,
                "password": password
            }
            self.client_socket.send(json.dumps(auth_data).encode('utf-8'))
            
            # Wait for authentication response
            response = self.client_socket.recv(1024).decode('utf-8')
            response_obj = json.loads(response)
            
            if response_obj.get("status") == "error":
                self.status_label.config(text=response_obj.get("message", "Connection failed"))
                self.connect_button.config(state=tk.NORMAL, text="Connect")
                self.client_socket.close()
                return
            
            # Authentication successful
            self.connected = True
            
            # Switch to chat frame
            self.login_frame.pack_forget()
            self.chat_frame.pack(fill=tk.BOTH, expand=True)
            
            # Update UI
            self.root.title(f"Chat - {self.username}")
            self.user_label.config(text=f"Logged in as: {self.username}")
            
            # Start receiving messages
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # Display welcome message
            self.display_message("System", "Connected to the server!")
            self.display_message("System", response_obj.get("message", "Welcome!"))
            
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")
            self.connect_button.config(state=tk.NORMAL, text="Connect")
    
    def receive_messages(self):
        """Receive and process messages from the server"""
        while self.connected:
            try:
                data = self.client_socket.recv(65536)
                if not data:
                    break
                
                message_data = json.loads(data.decode('utf-8'))
                message_type = message_data.get("type", "message")
                
                if message_type == "message":
                    sender = message_data.get("sender", "Unknown")
                    message = message_data.get("message", "")
                    self.display_message(sender, message)
                
                elif message_type == "file":
                    sender = message_data.get("sender", "Unknown")
                    filename = message_data.get("filename", "unknown_file")
                    file_data = message_data.get("data", "")
                    
                    # Display file message
                    self.display_message(sender, f"Sent a file: {filename}")
                    
                    # Save file option
                    self.root.after(0, lambda s=sender, f=filename, d=file_data: 
                                   self.prompt_save_file(s, f, d))
                
                elif message_type == "kick":
                    self.display_message("System", "You have been kicked from the server")
                    self.connected = False
                    self.client_socket.close()
                    self.root.after(0, self.show_login_screen)
                
            except json.JSONDecodeError:
                self.display_message("System", "Received invalid data from server")
            except Exception as e:
                if self.connected:
                    self.display_message("System", f"Connection error: {str(e)}")
                    self.connected = False
                    self.client_socket.close()
                    self.root.after(0, self.show_login_screen)
                break
    
    def show_login_screen(self):
        """Switch back to login screen"""
        self.chat_frame.pack_forget()
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        self.connect_button.config(state=tk.NORMAL, text="Connect")
        self.status_label.config(text="Disconnected from server")
    
    def display_message(self, sender, message):
        """Display a message in the chat area"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.chat_area.config(state=tk.NORMAL)
        
        # Add sender with timestamp
        if sender == self.username:
            self.chat_area.insert(tk.END, f"\n[{timestamp}] You: ", "self_sender")
            self.chat_area.tag_config("self_sender", foreground="#4d79ff", font=("Arial", 11, "bold"))
        elif sender == "System":
            self.chat_area.insert(tk.END, f"\n[{timestamp}] {sender}: ", "system_sender")
            self.chat_area.tag_config("system_sender", foreground="#ff9800", font=("Arial", 11, "bold"))
        else:
            self.chat_area.insert(tk.END, f"\n[{timestamp}] {sender}: ", "other_sender")
            self.chat_area.tag_config("other_sender", foreground="#4CAF50", font=("Arial", 11, "bold"))
        
        # Add message
        self.chat_area.insert(tk.END, message, "message")
        self.chat_area.tag_config("message", foreground="#ffffff", font=("Arial", 11))
        
        # Scroll to bottom
        self.chat_area.see(tk.END)
        self.chat_area.config(state=tk.DISABLED)
    
    def send_message(self):
        """Send a message to the server"""
        if not self.connected:
            return
            
        message = self.message_entry.get().strip()
        if not message:
            return
            
        try:
            message_data = {
                "type": "message",
                "message": message
            }
            self.client_socket.send(json.dumps(message_data).encode('utf-8'))
            self.message_entry.delete(0, tk.END)
        except:
            self.display_message("System", "Failed to send message")
    
    def select_file(self):
        """Open file dialog to select a file to send"""
        if not self.connected or self.file_transfer_active:
            return
            
        file_path = filedialog.askopenfilename(
            title="Select File to Send",
            filetypes=[("All Files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                messagebox.showerror("Error", "File is too large. Maximum size is 10MB.")
                return
                
            # Get file name
            filename = os.path.basename(file_path)
            
            # Generate unique file ID
            file_id = str(uuid.uuid4())
            
            # Read file data
            with open(file_path, "rb") as file:
                file_data = file.read()
            
            # Convert to base64
            file_data_b64 = base64.b64encode(file_data).decode('utf-8')
            
            # Set file transfer flag
            self.file_transfer_active = True
            self.display_message("System", f"Sending file: {filename}...")
            
            # Send file start message
            start_message = {
                "type": "file_start",
                "file_id": file_id,
                "file_info": {
                    "filename": filename,
                    "size": file_size
                }
            }
            self.client_socket.send(json.dumps(start_message).encode('utf-8'))
            
            # Split file into chunks (max 64KB per chunk)
            chunk_size = 64 * 1024
            chunks = [file_data_b64[i:i+chunk_size] for i in range(0, len(file_data_b64), chunk_size)]
            
            # Send chunks
            for i, chunk in enumerate(chunks):
                chunk_message = {
                    "type": "file_chunk",
                    "file_id": file_id,
                    "chunk_num": i,
                    "data": chunk
                }
                self.client_socket.send(json.dumps(chunk_message).encode('utf-8'))
            
            # Send file end message
            end_message = {
                "type": "file_end",
                "file_id": file_id
            }
            self.client_socket.send(json.dumps(end_message).encode('utf-8'))
            
            # Reset file transfer flag
            self.file_transfer_active = False
            self.display_message("System", f"File sent: {filename}")
            
        except Exception as e:
            self.file_transfer_active = False
            self.display_message("System", f"Error sending file: {str(e)}")
    
    def prompt_save_file(self, sender, filename, file_data_b64):
        """Prompt user to save received file"""
        if messagebox.askyesno("File Received", f"Save file '{filename}' from {sender}?"):
            save_path = filedialog.asksaveasfilename(
                title="Save File",
                initialfile=filename,
                filetypes=[("All Files", "*.*")]
            )
            
            if save_path:
                try:
                    # Decode base64 data
                    file_data = base64.b64decode(file_data_b64)
                    
                    # Save file
                    with open(save_path, "wb") as file:
                        file.write(file_data)
                    
                    self.display_message("System", f"File saved: {os.path.basename(save_path)}")
                except Exception as e:
                    self.display_message("System", f"Error saving file: {str(e)}")
    
    def on_closing(self):
        """Handle window closing"""
        if self.connected:
            try:
                # Send quit message
                quit_message = {"type": "quit"}
                self.client_socket.send(json.dumps(quit_message).encode('utf-8'))
                self.client_socket.close()
            except:
                pass
        
        self.root.destroy()

if __name__ == "__main__":
    client = ChatClient()