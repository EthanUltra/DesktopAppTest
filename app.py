import tkinter as tk
from tkinter import messagebox

class CounterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("My First App")
        self.root.geometry("300x200")
        self.count = 0

        self.label = tk.Label(root, text="Count: 0", font=("Arial", 16))
        self.label.pack(pady=20)

        tk.Button(root, text="Increment", command=self.increment).pack(pady=5)
        tk.Button(root, text="Reset", command=self.reset).pack(pady=5)
        tk.Button(root, text="About", command=self.about).pack(pady=5)

    def increment(self):
        self.count += 1
        self.label.config(text=f"Count: {self.count}")

    def reset(self):
        self.count = 0
        self.label.config(text="Count: 0")

    def about(self):
        messagebox.showinfo("About", "A tiny Tkinter app.")

if __name__ == "__main__":
    root = tk.Tk()
    CounterApp(root)
    root.mainloop()