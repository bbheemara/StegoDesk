import tkinter as tk
from gui.ui import DashboardPage

class App(tk.Tk):
    def __init__(self):
        super().__init__()

        container = tk.Frame(self)
        container.pack(fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        dashboard = DashboardPage(container, self)
        dashboard.grid(row=0, column=0, sticky="nsew")

        self.frames = {"DashboardPage": dashboard}
        dashboard.tkraise()

        self.state("zoomed")  

if __name__ == "__main__":
    app = App()
    app.mainloop()
