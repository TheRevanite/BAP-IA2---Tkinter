import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import lib
import hashlib
from PIL import Image, ImageTk


#Has images too. Only need to change the text perhaps.
#PADDING AND/OR HORIZONTAL SCROLL IS HORRIBLE I TRIED EVERYTHING I GIVE UP.

sql = sqlite3.connect("Database.db")
sql.execute(
    "create table if not exists data_table(username text, md5 text, sha1 text, sha224 text, blake2s text, blake2b text, sha3_384 text, sha384 text, sha3_512 text, sha3_224 text, sha512 text, sha256 text, sha3_256 text)"
)
sql.commit()
cursor = sql.cursor()

app = tk.Tk()
app.title("AccessCrypt")
app.geometry("1920x1080")

PRIMARY_COLOR = "#2196F3"  #Blue
ERROR_COLOR = "#FF5722"  #Red
SUCCESS_COLOR = "#4CAF50"  #Green


#Working directory is /.Database, so we need to add "../" to indicate its parent directory.
login_image = Image.open(r"../img/login.jpeg")
login_image = login_image.resize((200, 150))
login_image = ImageTk.PhotoImage(login_image)

signup_image = Image.open(r"../img/signup.jpeg")
signup_image = signup_image.resize((200, 150))
signup_image = ImageTk.PhotoImage(signup_image)

info_image = Image.open(r"../img/info.jpeg")
info_image = info_image.resize((200, 150))
info_image = ImageTk.PhotoImage(info_image)

def switch_to_signup():
    login_frame.pack_forget()
    special_login_frame.pack_forget()  
    signup_frame.pack()
    info_label_signup.pack()

def switch_to_login():
    signup_frame.pack_forget()
    special_login_frame.pack_forget()  
    login_frame.pack()
    info_label_login.pack()

def switch_to_special_login():
    signup_frame.pack_forget()
    login_frame.pack_forget()
    special_login_frame.pack()
    info_label_special_login.pack()

def fetch_password_hashes(username):
    all_hashes = lib.get_all_hashes(username)
    if all_hashes:
        return all_hashes
    else:
        return None

def display_profile(username):
    for widget in app.winfo_children():
        widget.pack_forget()

    password_hashes = fetch_password_hashes(username)
    if password_hashes:
        welcome_label = tk.Label(app, text=f"Welcome, {username}!", font=("Helvetica", 24), pady=20)
        welcome_label.pack()

        welcome_image = Image.open(r"../img/welcome.jpeg")
        welcome_image = welcome_image.resize((220, 120))
        welcome_image = ImageTk.PhotoImage(welcome_image)
        welcome_image_label = tk.Label(app, image=welcome_image)
        welcome_image_label.image = welcome_image
        welcome_image_label.pack()
        table_frame = ttk.Frame(app)
        table_frame.pack(fill="both", expand=True)

        columns = ("Algorithm", "Hash Value")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=10)
        tree.heading("#1", text="Algorithm", anchor="w")
        tree.heading("#2", text="Hash Value", anchor="w")

        tree_scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        tree_scroll_y.pack(side="right", fill="y")
        tree.configure(yscrollcommand=tree_scroll_y.set)

        tree_scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=tree.xview)
        tree_scroll_x.pack(side="bottom", fill="x")
        tree.configure(xscrollcommand=tree_scroll_x.set)

        for i, (algorithm, hash_value) in enumerate(password_hashes):
            tree.insert("", tk.END, values=(algorithm, hash_value))

        tree.pack(fill="both", expand=True)

        hashes_image = Image.open(r"../img/hash.jpeg")
        hashes_image = hashes_image.resize((800, 400))
        hashes_image = ImageTk.PhotoImage(hashes_image)
        hashes_image_label = tk.Label(app, image=hashes_image)
        hashes_image_label.image = hashes_image
        hashes_image_label.pack()

    else:
        messagebox.showerror("Error", "User not found")

def login():
    entered_username = user_name_login.get()
    entered_password = password_login.get()

    cursor.execute("SELECT * FROM data_table WHERE username=?", (entered_username,))
    result = cursor.fetchone()
    if result:
        stored_hash = result[1]
        password_matched = False
        hashed_password = hashlib.md5(entered_password.encode()).hexdigest()
        if stored_hash == hashed_password:
            password_matched = True
        if password_matched:
            label_login.configure(text="Correct")
            display_profile(entered_username)
            return
        else:
            label_login.configure(text="Wrong password", fg=ERROR_COLOR)
    else:
        label_login.configure(text="User not found", fg=ERROR_COLOR)

def special_login():
    entered_hash = hash_special_login.get()
    result = lib.fetch_from_database(entered_hash)
    entered_username = lib.get_username(entered_hash)
    if result:
        label_special_login.configure(text="Correct")
        if entered_username:
            display_profile(entered_username)
        return
    else:
        label_special_login.configure(text="Wrong hash or user does not exist.", fg=ERROR_COLOR)

def signup():
    username_input = user_name_signup.get()
    password_input = password_signup.get()

    if not username_input or not password_input:
        label_signup.configure(text="Username and password cannot be empty.", fg=ERROR_COLOR)
    elif lib.check_me(username_input):
        lib.add_data(username_input, password_input)
        label_signup.configure(text="Signed up successfully. Please login.", fg=SUCCESS_COLOR)
        switch_to_login()
    else:
        label_signup.configure(text="An account with that username already exists.", fg=ERROR_COLOR)

navbar_frame = tk.Frame(app)
navbar_frame.pack(fill="x", pady=10)

program_name_label = tk.Label(master=navbar_frame, text="AccessCrypt", font=("Helvetica", 16))
program_name_label.pack()

signup_button = tk.Button(master=navbar_frame, image=signup_image, command=switch_to_signup, bg=PRIMARY_COLOR, bd=0)
signup_button.pack(side="left", padx=10)

login_button = tk.Button(master=navbar_frame, image=login_image, command=switch_to_login, bg=PRIMARY_COLOR, bd=0)
login_button.pack(side="right", padx=10)

special_login_button = tk.Button(master=navbar_frame, image=info_image, command=switch_to_special_login, bg=PRIMARY_COLOR, bd=0)
special_login_button.pack(side="right", padx=10)

login_frame = tk.Frame(app)
user_name_login = tk.Entry(master=login_frame, font=("Helvetica", 18))
user_name_login.pack()
password_login = tk.Entry(master=login_frame, show="*", font=("Helvetica", 18))
password_login.pack()
login_button = tk.Button(master=login_frame, text="Log In", command=login, font=("Helvetica", 18), bg=PRIMARY_COLOR, fg="white")
login_button.pack()
label_login = tk.Label(master=login_frame, font=("Helvetica", 18))
label_login.pack()
info_label_login = tk.Label(master=login_frame, text="Please enter your username and password to login.", font=("Helvetica", 12))
info_label_login.pack()

special_login_frame = tk.Frame(app)
hash_special_login = tk.Entry(master=special_login_frame, font=("Helvetica", 18))
hash_special_login.pack()
special_login_button = tk.Button(master=special_login_frame, text="Special Log In", command=special_login, font=("Helvetica", 18), bg=PRIMARY_COLOR, fg="white")
special_login_button.pack()
label_special_login = tk.Label(master=special_login_frame, font=("Helvetica", 18))
label_special_login.pack()
info_label_special_login = tk.Label(master=special_login_frame, text="Please enter the hash provided to you to login.", font=("Helvetica", 12))
info_label_special_login.pack()

signup_frame = tk.Frame(app)
user_name_signup = tk.Entry(master=signup_frame, font=("Helvetica", 18))
user_name_signup.pack()
password_signup = tk.Entry(master=signup_frame, show="*", font=("Helvetica", 18))
password_signup.pack()
signup_button = tk.Button(master=signup_frame, text="Sign Up", command=signup, font=("Helvetica", 18), bg=PRIMARY_COLOR, fg="white")
signup_button.pack()
label_signup = tk.Label(master=signup_frame, font=("Helvetica", 18))
label_signup.pack()
info_label_signup = tk.Label(master=signup_frame, text="Please enter your desired username and password to sign up.", font=("Helvetica", 12))
info_label_signup.pack()

info_label = tk.Label(app, text="AccessCrypt is a secure login system.\nPlease login or sign up to continue.", font=("Helvetica", 14))
info_label.pack(pady=20)

app.mainloop()
