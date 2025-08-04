import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from random import choice
import json, os, pyperclip, sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64
from PIL import Image, ImageTk
from pymongo import MongoClient
import bcrypt

# ---------------------------- CENTER WINDOW FUNCTION ------------------------------- #
def center_window(win, width=None, height=None):
    if width and height:
        win.geometry(f"{width}x{height}")
    win.update_idletasks()
    if not width:
        width = win.winfo_width()
    if not height:
        height = win.winfo_height()
    x = (win.winfo_screenwidth() // 2) - (width // 2)
    y = (win.winfo_screenheight() // 2) - (height // 2)
    win.geometry(f"{width}x{height}+{x}+{y}")

# ---------------------------- RESOURCE PATH ------------------------------- #
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# ---------------------------- CONFIG ------------------------------- #
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "notepad_config.json")
LOCAL_ADMIN_FILE = os.path.join(BASE_DIR, "admin_local.json")
LOCAL_BACKUP_FILE = os.path.join(BASE_DIR, "NOTEPAD.json")
SECURITY_KEY_FILE = os.path.join(BASE_DIR, "security_key.bin")
KEY_SALT_FILE = os.path.join(BASE_DIR, "key_salt.bin")

def get_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return {}

def save_config(config):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
    except Exception:
        pass

def get_mongo_uri_and_pref():
    config = get_config()

    if "store_in_mongo" in config and (not config["store_in_mongo"] or config.get("mongo_uri")):
        return config.get("mongo_uri"), config["store_in_mongo"]

    # Custom preference window
    pref_root = tk.Tk()
    pref_root.title("Storage Preference")
    pref_root.configure(bg="#f7f9fb")
    pref_root.withdraw()  
    center_window(pref_root, 450, 200)
    pref_root.deiconify()
    pref_root.resizable(False, False)
    try:
        pref_root.iconbitmap(resource_path("initial_image.ico"))
    except:
        pass

    choice_holder = {"store_in_mongo": None}

    tk.Label(
        pref_root,
        text="Where should credentials be stored?",
        font=("Segoe UI", 13, "bold"),
        bg="#f7f9fb",
        fg="#333"
    ).pack(pady=(15, 5))

    tk.Label(
        pref_root,
        text="You can store credentials locally only, or both locally and in MongoDB.",
        font=("Segoe UI", 10),
        bg="#f7f9fb",
        fg="#555",
        wraplength=400,
        justify="center"
    ).pack(pady=(0, 15))

    btn_frame = tk.Frame(pref_root, bg="#f7f9fb")
    btn_frame.pack(pady=10)

    def choose_yes():
        choice_holder["store_in_mongo"] = True
        pref_root.destroy()

    def choose_no():
        choice_holder["store_in_mongo"] = False
        pref_root.destroy()

    tk.Button(
        btn_frame,
        text="Yes: MongoDB + Local",
        font=("Segoe UI", 10, "bold"),
        bg="#d4f7dc",
        width=18,
        command=choose_yes,
        relief="flat"
    ).grid(row=0, column=0, padx=8, pady=5)
    tk.Button(
        btn_frame,
        text="No: Local Only",
        font=("Segoe UI", 10, "bold"),
        bg="#ffd6d6",
        width=18,
        command=choose_no,
        relief="flat"
    ).grid(row=0, column=1, padx=8, pady=5)

    # If user closes preference window, exit immediately without writing config
    def on_pref_close():
        pref_root.destroy()
        sys.exit(0)
    pref_root.protocol("WM_DELETE_WINDOW", on_pref_close)

    pref_root.mainloop()

    store_choice = choice_holder["store_in_mongo"]
    if store_choice is None:
        # Shouldn't reach here because closing window exits, but guard anyway
        sys.exit(0)

    config["store_in_mongo"] = store_choice

    if store_choice:
        # Ask for MongoDB URI via styled window
        def save_and_close():
            uri_val = uri_entry.get().strip()
            if not uri_val:
                messagebox.showerror("Error", "MongoDB URI is required.", parent=uri_root)
                return
            config["mongo_uri"] = uri_val
            save_config(config)
            uri_root.uri_result = uri_val
            uri_root.destroy()

        uri_root = tk.Tk()
        uri_root.title("🔗 MongoDB Connection Setup")
        uri_root.configure(bg="#f7f9fb")
        uri_root.withdraw()  
        center_window(uri_root, 600, 250)
        uri_root.deiconify()
        uri_root.resizable(False, False)
        try:
            uri_root.iconbitmap(resource_path("initial_image.ico"))
        except:
            pass

        frame = tk.Frame(uri_root, bg="#f7f9fb", padx=20, pady=20)
        frame.pack(expand=True, fill="both")

        tk.Label(frame, text="Enter Your MongoDB URI", font=("Segoe UI", 14, "bold"),
                 bg="#f7f9fb", fg="#333").pack(pady=(0, 10))
        tk.Label(
            frame,
            text="Example:\n mongodb+srv://<username>:<password>@cluster0.mongodb.net/\n"
                 "?retryWrites=true&w=majority&appName=Cluster0",
            font=("Segoe UI", 9),
            bg="#f7f9fb",
            fg="#666",
            justify="center"
        ).pack(pady=(0, 10))

        uri_entry = tk.Entry(frame, width=65, font=("Segoe UI", 10))
        uri_entry.pack(pady=(5, 15))
        uri_entry.focus()

        tk.Button(frame, text="Save & Continue", font=("Segoe UI", 11, "bold"), bg="#d4f7dc",
                  relief="flat", width=20, command=save_and_close).pack()

        # If user closes URI window, exit immediately without saving config
        def on_uri_close():
            uri_root.destroy()
            sys.exit(0)
        uri_root.protocol("WM_DELETE_WINDOW", on_uri_close)

        uri_root.uri_result = None
        uri_root.mainloop()

        # At this point, URI must exist because closing exits
        return config.get("mongo_uri"), config["store_in_mongo"]
    else:
        # Local only choice; persist preference
        save_config(config)
        return None, False



# ---------------------------- INITIAL SETUP ------------------------------- #
MONGO_URI, STORE_IN_MONGO = get_mongo_uri_and_pref()

# Database handles (only if using MongoDB)
if STORE_IN_MONGO:
    CLIENT = MongoClient(MONGO_URI)
    DB = CLIENT["NOTEPAD"]
    ADMIN_COLL = DB["admin"]
    CREDENTIALS_COLL = DB["credentials"]
    FILES_COLL = DB["files"]
    try:
        for idx in CREDENTIALS_COLL.list_indexes():
            key_pattern = getattr(idx, "key_pattern", dict(idx.get("key", {})))
            if key_pattern == {"website": 1} and idx.get("unique", False):
                CREDENTIALS_COLL.drop_index(idx["name"])
    except Exception:
        pass
    CREDENTIALS_COLL.create_index([("website", 1), ("email", 1)], unique=True)

# ---------------------------- FERNET / SALT HELPERS ------------------------------- #
def load_salt():
    if STORE_IN_MONGO:
        try:
            doc = FILES_COLL.find_one({"_id": "key_salt"})
            if doc and "salt" in doc:
                salt = base64.b64decode(doc["salt"])
                with open(KEY_SALT_FILE, "wb") as f:
                    f.write(salt)
                return salt
        except Exception:
            pass
    if os.path.exists(KEY_SALT_FILE):
        with open(KEY_SALT_FILE, "rb") as f:
            return f.read()
    salt = os.urandom(16)
    try:
        with open(KEY_SALT_FILE, "wb") as f:
            f.write(salt)
    except:
        pass
    if STORE_IN_MONGO:
        try:
            FILES_COLL.replace_one({"_id": "key_salt"}, {"_id": "key_salt", "salt": base64.b64encode(salt).decode()}, upsert=True)
        except:
            pass
    return salt

def derive_key(password):
    salt = load_salt()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def get_security_fernet():
    if STORE_IN_MONGO:
        try:
            doc = FILES_COLL.find_one({"_id": "security_key"})
            if doc and "key" in doc:
                key = base64.b64decode(doc["key"])
                with open(SECURITY_KEY_FILE, "wb") as f:
                    f.write(key)
                return Fernet(key)
        except Exception:
            pass
    if os.path.exists(SECURITY_KEY_FILE):
        with open(SECURITY_KEY_FILE, "rb") as f:
            return Fernet(f.read())
    key = Fernet.generate_key()
    try:
        with open(SECURITY_KEY_FILE, "wb") as f:
            f.write(key)
    except:
        pass
    if STORE_IN_MONGO:
        try:
            FILES_COLL.replace_one({"_id": "security_key"}, {"_id": "security_key", "key": base64.b64encode(key).decode()}, upsert=True)
        except:
            pass
    return Fernet(key)

security_fernet = get_security_fernet()
fernet = None  # will be set after admin login / setup

def migrate_local_artifacts_to_db():
    if not STORE_IN_MONGO:
        return
    if os.path.exists(KEY_SALT_FILE):
        try:
            with open(KEY_SALT_FILE, "rb") as f:
                local_salt = f.read()
            FILES_COLL.replace_one(
                {"_id": "key_salt"},
                {"_id": "key_salt", "salt": base64.b64encode(local_salt).decode()},
                upsert=True
            )
        except Exception:
            pass
    if os.path.exists(SECURITY_KEY_FILE):
        try:
            with open(SECURITY_KEY_FILE, "rb") as f:
                local_key = f.read()
            FILES_COLL.replace_one(
                {"_id": "security_key"},
                {"_id": "security_key", "key": base64.b64encode(local_key).decode()},
                upsert=True
            )
        except Exception:
            pass

migrate_local_artifacts_to_db()

# ---------------------------- ENCRYPT / DECRYPT FOR CREDENTIALS ------------------------------- #
def encrypt(text):
    return fernet.encrypt(text.encode()).decode()

def decrypt(token):
    return fernet.decrypt(token.encode()).decode()

# ---------------------------- LOCAL PLAINTEXT BACKUP HELPERS ------------------------------- #
def backup_plaintext_locally(website, email, password):
    data = {}
    if os.path.exists(LOCAL_BACKUP_FILE):
        try:
            with open(LOCAL_BACKUP_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except:
            data = {}
    data.setdefault(website, {})[email] = password
    try:
        with open(LOCAL_BACKUP_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except:
        pass

def remove_plaintext_local(website, email):
    if not os.path.exists(LOCAL_BACKUP_FILE):
        return
    try:
        with open(LOCAL_BACKUP_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except:
        return
    changed = False
    if website in data:
        if email in data[website]:
            del data[website][email]
            changed = True
        if not data.get(website):
            data.pop(website, None)
            changed = True
    if changed:
        tmp = f"{LOCAL_BACKUP_FILE}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, LOCAL_BACKUP_FILE)
        except:
            pass

# ---------------------------- ADMIN STORAGE (Mongo or Local) ------------------------------- #
def _load_local_admin():
    if os.path.exists(LOCAL_ADMIN_FILE):
        try:
            with open(LOCAL_ADMIN_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return {}

def _save_local_admin(admin_doc):
    try:
        with open(LOCAL_ADMIN_FILE, "w", encoding="utf-8") as f:
            json.dump(admin_doc, f, indent=2)
    except:
        pass

def is_admin_setup():
    if STORE_IN_MONGO:
        try:
            doc = ADMIN_COLL.find_one({})
            return bool(doc and doc.get("password_hash"))
        except:
            return False
    else:
        doc = _load_local_admin()
        return bool(doc.get("password_hash"))

def save_admin_password(password, security_answers=None):
    global fernet
    password_bytes = password.encode()
    password_hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    fernet = Fernet(derive_key(password))
    if security_answers is None:
        security_answers = {}
    encrypted_answers = {q: security_fernet.encrypt(a.encode()).decode() for q, a in security_answers.items()}

    if STORE_IN_MONGO:
        try:
            ADMIN_COLL.replace_one(
                {},
                {
                    "password_hash": password_hash.decode(),
                    "security_questions": encrypted_answers
                },
                upsert=True
            )
        except Exception:
            pass
    else:
        _save_local_admin({
            "password_hash": password_hash.decode(),
            "security_questions": encrypted_answers
        })

def check_admin_password(input_password):
    global fernet
    try:
        if STORE_IN_MONGO:
            doc = ADMIN_COLL.find_one({})
        else:
            doc = _load_local_admin()
        if not doc or "password_hash" not in doc:
            return False
        stored_hash = doc["password_hash"].encode()
        if bcrypt.checkpw(input_password.encode(), stored_hash):
            fernet = Fernet(derive_key(input_password))
            return True
        return False
    except Exception:
        return False

# ---------------------------- ADMIN RESET ------------------------------- #
def reset_admin_password():
    def verify_answers():
        try:
            if STORE_IN_MONGO:
                doc = ADMIN_COLL.find_one({})
            else:
                doc = _load_local_admin()
            if not doc:
                messagebox.showerror("Error", "No admin data found.")
                return
            encrypted_answers = doc.get("security_questions", {})
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load security answers: {e}")
            return

        if not any(encrypted_answers.values()):
            sec_win.destroy()
            show_set_security_questions()
            return

        user_answers = {
            "High School Name": q1_entry.get().strip(),
            "Intermediate School Name": q2_entry.get().strip(),
            "Maternal Grandmother Name": q3_entry.get().strip(),
            "Grandfather Name": q4_entry.get().strip(),
            "Grandmother Name": q5_entry.get().strip(),
        }

        try:
            decrypted_answers = {
                q: security_fernet.decrypt(ans.encode()).decode()
                for q, ans in encrypted_answers.items()
            }
            for question, correct in decrypted_answers.items():
                if user_answers.get(question, "").lower() != correct.lower():
                    messagebox.showerror("Incorrect", f"Answer to '{question}' is incorrect.")
                    return
            sec_win.destroy()
            show_reset_window(decrypted_answers)
        except Exception:
            messagebox.showerror("Error", "Verification failed. Incorrect answers or corrupted data.")
            return

    def show_set_security_questions():
        setup_win = tk.Tk()
        setup_win.title("🛡️ Set Security Questions")
        setup_win.withdraw()
        center_window(setup_win, 500, 500)
        setup_win.deiconify()
        setup_win.geometry("500x500")
        setup_win.configure(bg="#f7f9fb")
        setup_win.resizable(False, False)
        try:
            setup_win.iconbitmap(resource_path("security_image.ico"))
        except:
            pass

        frame = tk.Frame(setup_win, bg="#f7f9fb", padx=20, pady=20)
        frame.pack(expand=True, fill="both")
        tk.Label(frame, text="Set Admin Password & Security Questions", bg="#f7f9fb",
                 font=("Segoe UI", 13, "bold")).pack(pady=(0, 15))

        def make_question(label_text):
            tk.Label(frame, text=label_text, bg="#f7f9fb", font=("Segoe UI", 10)).pack(anchor="w", padx=62)
            entry = tk.Entry(frame, width=50)
            entry.pack(pady=4)
            return entry

        q1 = make_question("1. High School Name")
        q2 = make_question("2. Intermediate School Name")
        q3 = make_question("3. Maternal Grandmother Name")
        q4 = make_question("4. Grandfather Name")
        q5 = make_question("5. Grandmother Name")

        pw1 = tk.Entry(frame, show="*", width=50)
        pw2 = tk.Entry(frame, show="*", width=50)
        tk.Label(frame, text="New Admin Password", bg="#f7f9fb", font=("Segoe UI", 10)).pack(pady=(10, 0))
        pw1.pack(pady=5)
        tk.Label(frame, text="Confirm Password", bg="#f7f9fb", font=("Segoe UI", 10)).pack(pady=(10, 0))
        pw2.pack(pady=5)

        def save_all():
            if not all([q1.get(), q2.get(), q3.get(), q4.get(), q5.get(), pw1.get(), pw2.get()]):
                messagebox.showerror("Error", "All fields are required.")
                return
            if pw1.get() != pw2.get():
                messagebox.showerror("Mismatch", "Passwords do not match.")
                return
            answers = {
                "High School Name": q1.get().strip(),
                "Intermediate School Name": q2.get().strip(),
                "Maternal Grandmother Name": q3.get().strip(),
                "Grandfather Name": q4.get().strip(),
                "Grandmother Name": q5.get().strip(),
            }
            save_admin_password(pw1.get(), answers)
            messagebox.showinfo("Success", "Admin password and security questions set.")
            setup_win.destroy()
            login_window()

        tk.Button(frame, text="Save", command=save_all, bg="#d4f7dc", font=("Segoe UI", 10, "bold"),
                  width=25).pack(pady=15)
        setup_win.mainloop()

    def show_reset_window(existing_answers):
        reset_win = tk.Tk()
        reset_win.title("Set Admin Password")
        reset_win.withdraw()
        center_window(reset_win, 400, 250)
        reset_win.deiconify()
        reset_win.geometry("400x250")
        reset_win.configure(bg="#f7f9fb")
        reset_win.resizable(False, False)
        try:
            reset_win.iconbitmap(resource_path("initial_image.ico"))
        except:
            pass

        frame = tk.Frame(reset_win, bg="#f7f9fb", padx=20, pady=20)
        frame.pack(expand=True, fill="both")
        tk.Label(frame, text="New Admin Password", bg="#f7f9fb", font=("Segoe UI", 12, "bold")).pack(pady=(0, 15))

        def make_labeled_entry(label_text):
            tk.Label(frame, text=label_text, bg="#f7f9fb", font=("Segoe UI", 10)).pack(anchor="w", padx=52)
            entry = tk.Entry(frame, show="*", width=35, font=("Segoe UI", 10))
            entry.pack(pady=5)
            return entry

        new_pw_entry = make_labeled_entry("New Password:")
        confirm_pw_entry = make_labeled_entry("Confirm Password:")

        def save_new_password():
            pw1 = new_pw_entry.get()
            pw2 = confirm_pw_entry.get()
            if not pw1 or not pw2:
                messagebox.showerror("Error", "Fields cannot be empty.")
                return
            if pw1 != pw2:
                messagebox.showerror("Mismatch", "Passwords do not match.")
                return
            save_admin_password(pw1, existing_answers)
            messagebox.showinfo("Success", "Admin password set successfully.")
            reset_win.destroy()
            login_window()

        tk.Button(frame, text="Set Password", command=save_new_password,
                  bg="#d4f7dc", font=("Segoe UI", 10, "bold"), width=25).pack(pady=15)
        reset_win.mainloop()

    try:
        login_win.destroy()
    except:
        pass

    sec_win = tk.Tk()
    sec_win.title("Verify Identity")
    sec_win.withdraw()
    center_window(sec_win, 500, 400)
    sec_win.deiconify()
    sec_win.geometry("500x400")
    sec_win.configure(bg="#f7f9fb")
    sec_win.resizable(False, False)
    try:
        sec_win.iconbitmap(resource_path("security_image.ico"))
    except:
        pass

    frame = tk.Frame(sec_win, bg="#f7f9fb", padx=20, pady=20)
    frame.pack(expand=True, fill="both")
    tk.Label(frame, text="Answer the Security Questions", bg="#f7f9fb",
             font=("Segoe UI", 13, "bold")).pack(pady=(0, 20))

    def make_question(label_text):
        tk.Label(frame, text=label_text, bg="#f7f9fb", font=("Segoe UI", 10)).pack(anchor="w", padx=62)
        entry = tk.Entry(frame, width=50)
        entry.pack(pady=4)
        return entry

    q1_entry = make_question("1. High School Name")
    q2_entry = make_question("2. Intermediate School Name")
    q3_entry = make_question("3. Maternal Grandmother Name")
    q4_entry = make_question("4. Grandfather Name")
    q5_entry = make_question("5. Grandmother Name")

    tk.Button(frame, text="Verify Answers", command=verify_answers,
              bg="#ffd8b5", font=("Segoe UI", 10, "bold"), width=25).pack(pady=10)
    sec_win.mainloop()

# ---------------------------- LOGIN WINDOW ------------------------------- #
def login_window():
    def attempt_login():
        pw = password_entry.get()
        if check_admin_password(pw):
            login_win.destroy()
            launch_main_window()
        else:
            messagebox.showerror("Access Denied", "Incorrect password.")

    global login_win
    login_win = tk.Tk()
    login_win.title("Admin Login")
    login_win.geometry("350x220")
    login_win.withdraw()
    center_window(login_win, 400, 250)
    login_win.deiconify()
    login_win.configure(bg="#f7f9fb")
    login_win.resizable(False, False)
    try:
        login_win.iconbitmap(resource_path("initial_image.ico"))
    except:
        pass

    frame = tk.Frame(login_win, bg="#f7f9fb", padx=20, pady=20)
    frame.pack(expand=True, fill="both")
    tk.Label(frame, text="Admin Login", bg="#f7f9fb", font=("Segoe UI", 13, "bold")).pack(pady=(0, 15))
    tk.Label(frame, text="Password:", bg="#f7f9fb", font=("Segoe UI", 10)).pack(anchor="w", padx=45)
    password_entry = tk.Entry(frame, show="*", width=30, font=("Segoe UI", 10))
    password_entry.pack(pady=10)
    password_entry.focus()

    btn_frame = tk.Frame(frame, bg="#f7f9fb")
    btn_frame.pack(pady=15)
    tk.Button(btn_frame, text="Login", command=attempt_login,
              bg="#d4f7dc", font=("Segoe UI", 10, "bold"), width=12).pack(side="left", padx=5)
    tk.Button(btn_frame, text="Reset Password", command=reset_admin_password,
              bg="#ffd8b5", font=("Segoe UI", 10, "bold"), width=12).pack(side="left", padx=5)
    login_win.mainloop()

# ---------------------------- PASSWORD GENERATOR ------------------------------- #
def generate_password():
    length = length_var.get()
    use_letters = letters_var.get()
    use_numbers = numbers_var.get()
    use_symbols = symbols_var.get()

    if not (use_letters or use_numbers or use_symbols):
        messagebox.showwarning("Missing Selection", "Select at least one character type.")
        return

    letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    numbers = "0123456789"
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    choices = ""
    if use_letters:
        choices += letters
    if use_numbers:
        choices += numbers
    if use_symbols:
        choices += symbols

    password = "".join(choice(choices) for _ in range(length))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)
    pyperclip.copy(password)

# ---------------------------- VERIFY ADMIN BEFORE SENSITIVE ACTION ------------------------------- #
def verify_admin_dialog():
    result = {"ok": False}
    pw_win = tk.Toplevel(window)
    pw_win.title("Admin Verification")
    pw_win.geometry("350x170")
    pw_win.resizable(False, False)
    center_window(pw_win, 350, 170)
    pw_win.grab_set()

    tk.Label(pw_win, text="Re-enter Admin Password", font=("Segoe UI", 12, "bold")).pack(pady=(15, 5))
    pw_entry = tk.Entry(pw_win, show="*", width=30, font=("Segoe UI", 11))
    pw_entry.pack(pady=5)
    try:
        pw_win.iconbitmap(resource_path("initial_image.ico"))
    except:
        pass
    pw_entry.focus()

    def attempt():
        pw = pw_entry.get()
        if check_admin_password(pw):
            result["ok"] = True
            pw_win.destroy()
        else:
            messagebox.showerror("Access Denied", "Incorrect admin password.")

    btn_frame = tk.Frame(pw_win)
    btn_frame.pack(pady=10)
    tk.Button(btn_frame, text="Verify", command=attempt, bg="#d4f7dc", width=10).pack(side="left", padx=5)
    tk.Button(btn_frame, text="Cancel", command=pw_win.destroy, bg="#ffd8b5", width=10).pack(side="left", padx=5)
    pw_win.wait_window()
    return result["ok"]

# ---------------------------- SAVE PASSWORD (MongoDB + LOCAL BACKUP) ------------------------------- #
def save_password():
    website = website_entry.get().strip()
    email = email_entry.get().strip()
    password = password_entry.get().strip()
    if not website or not password:
        messagebox.showwarning("Missing Info", "Website and Password cannot be empty.")
        return
    try:
        encrypted_password = encrypt(password)
    except Exception:
        messagebox.showerror("Error", "Encryption not initialized. Login first.")
        return

    if STORE_IN_MONGO:
        try:
            CREDENTIALS_COLL.replace_one(
                {"website": website, "email": email},
                {"website": website, "email": email, "password": encrypted_password},
                upsert=True
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save credential: {e}")
            return

    backup_plaintext_locally(website, email, password)
    website_entry.delete(0, tk.END)
    email_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    messagebox.showinfo("Password Saved", f"Website: {website}\nEmail/Username: {email}\n\nPassword saved successfully!")

# ---------------------------- SHOW ALL PASSWORDS (WITH DELETE & AUTH) ------------------------------- #
def load_all_credentials():
    out = []
    if STORE_IN_MONGO:
        try:
            cursor = CREDENTIALS_COLL.find({})
            for doc in cursor:
                out.append(doc)
        except:
            pass
    # Also include local ones if backup exists for display (dedup by website/email, prefer decrypted Mongo version if present)
    local = {}
    if os.path.exists(LOCAL_BACKUP_FILE):
        try:
            with open(LOCAL_BACKUP_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                for site, emails in data.items():
                    for email, pw in emails.items():
                        local.setdefault(site, {})[email] = pw
        except:
            pass
    # Merge: if a credential exists from Mongo, use that; otherwise use local plaintext
    merged = {}
    for doc in out:
        website = doc.get("website", "")
        email = doc.get("email", "")
        try:
            password = decrypt(doc.get("password", ""))
        except:
            password = "[Error decrypting]"
        merged.setdefault(website, {})[email] = password
    for site, emails in local.items():
        for email, pw in emails.items():
            if site not in merged or email not in merged[site]:
                merged.setdefault(site, {})[email] = pw
    # Convert to list of dicts like earlier expected structure
    result = []
    for website, emails in merged.items():
        for email, pw in emails.items():
            result.append({"website": website, "email": email, "password": pw})
    return result

def show_all_passwords():
    data = load_all_credentials()
    if not data:
        messagebox.showinfo("Empty", "No passwords saved.")
        return

    data.sort(key=lambda d: (d.get("website", "").lower(), d.get("email", "").lower()))

    all_win = tk.Toplevel(window)
    all_win.title("All Saved Passwords")
    all_win.withdraw()
    center_window(all_win, 900, 500)
    all_win.deiconify()
    all_win.geometry("900x500")
    all_win.configure(bg="#f9fbff")
    try:
        all_win.iconbitmap(resource_path("initial_image.ico"))
    except:
        pass

    search_var = tk.StringVar(value="")
    placeholder = "🔍 Search by website or email..."
    search_frame = tk.Frame(all_win, bg="#f9fbff")
    search_frame.pack(pady=10)
    search_entry = tk.Entry(search_frame, textvariable=search_var, width=50, font=("Segoe UI", 10))
    search_entry.insert(0, placeholder)
    search_entry.config(fg="gray")

    def clear_placeholder(e):
        if search_entry.get() == placeholder:
            search_entry.delete(0, tk.END)
            search_entry.config(fg="black")

    def add_placeholder(e):
        if not search_entry.get():
            search_entry.insert(0, placeholder)
            search_entry.config(fg="gray")

    search_entry.bind("<FocusIn>", clear_placeholder)
    search_entry.bind("<FocusOut>", add_placeholder)
    search_entry.pack(pady=10)

    canvas = tk.Canvas(all_win, bg="#f9fbff", borderwidth=0)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar = ttk.Scrollbar(all_win, orient="vertical", command=canvas.yview)
    scrollbar.pack(side="right", fill="y")
    canvas.configure(yscrollcommand=scrollbar.set)
    list_frame = tk.Frame(canvas, bg="#f9fbff")
    canvas.create_window((0, 0), window=list_frame, anchor="nw")

    def on_frame_configure(event):
        canvas.configure(scrollregion=canvas.bbox("all"))

    list_frame.bind("<Configure>", on_frame_configure)

    def update_list():
        nonlocal data
        for widget in list_frame.winfo_children():
            widget.destroy()

        headers = ["S.No.", "Website", "Email/Username", "Password", "Actions"]
        col_widths = [5, 25, 30, 30, 25]

        for idx, text in enumerate(headers):
            tk.Label(list_frame, text=text, font=("Segoe UI", 10, "bold"),
                     bg="#cde5ff", width=col_widths[idx], anchor="w", pady=6).grid(row=0, column=idx, padx=3, sticky="w")

        query = search_var.get().strip().lower()
        if query == placeholder.lower():
            query = ""
        row = 1
        count = 1
        for doc in data:
            website = doc.get("website", "")
            email = doc.get("email", "")
            if (not query or query in website.lower() or query in email.lower()):
                try:
                    password = doc.get("password", "")
                except:
                    password = "[Error]"
                password_var = tk.StringVar(value="*" * len(password))

                def make_toggle(pv, pw):
                    def toggle():
                        pv.set(pw if pv.get().startswith("*") else "*" * len(pw))
                    return toggle

                def make_copy(pw):
                    def copy():
                        pyperclip.copy(pw)
                    return copy

                def make_delete(w, e):
                    def delete():
                        if STORE_IN_MONGO:
                            if not verify_admin_dialog():
                                return
                        confirm = messagebox.askyesno(
                            "Confirm Delete",
                            f"Delete credential for '{w}' / '{e}'?",
                            parent=all_win
                        )
                        if not confirm:
                            return
                        try:
                            if STORE_IN_MONGO:
                                CREDENTIALS_COLL.delete_one({"website": w, "email": e})
                            remove_plaintext_local(w, e)
                            all_win.destroy()
                            show_all_passwords()
                        except Exception as ex:
                            messagebox.showerror("Error", f"Failed to delete: {ex}", parent=all_win)
                    return delete

                tk.Label(list_frame, text=f"{count}", font=("Segoe UI", 10),
                         width=col_widths[0], anchor="w").grid(row=row, column=0, padx=3, pady=4, sticky="w")
                tk.Label(list_frame, text=website, font=("Segoe UI", 10),
                         width=col_widths[1], anchor="w").grid(row=row, column=1, padx=3, pady=4, sticky="w")
                tk.Label(list_frame, text=email, font=("Segoe UI", 10),
                         width=col_widths[2], anchor="w").grid(row=row, column=2, padx=3, pady=4, sticky="w")
                tk.Label(list_frame, textvariable=password_var, font=("Segoe UI", 10),
                         width=col_widths[3], anchor="w").grid(row=row, column=3, padx=3, pady=4, sticky="w")

                action_frame = tk.Frame(list_frame)
                action_frame.grid(row=row, column=4, padx=3, pady=2, sticky="w")

                toggle_btn = tk.Button(action_frame, text="👁️", command=make_toggle(password_var, password),
                                       font=("Segoe UI", 9), bg="#e1eaff", relief="flat", width=4)
                copy_btn = tk.Button(action_frame, text="📋", command=make_copy(password),
                                     font=("Segoe UI", 9), bg="#d8f0e0", relief="flat", width=4)
                delete_btn = tk.Button(action_frame, text="🗑️", command=make_delete(website, email),
                                       font=("Segoe UI", 9), bg="#ffd6d6", relief="flat", width=4)

                toggle_btn.pack(side="left", padx=2)
                copy_btn.pack(side="left", padx=2)
                delete_btn.pack(side="left", padx=2)

                row += 1
                count += 1

    search_entry.bind("<KeyRelease>", lambda event: update_list())
    update_list()

# ---------------------------- TOGGLE PASSWORD ------------------------------- #
def toggle_password():
    if password_entry.cget("show") == "":
        password_entry.config(show="*")
        toggle_btn.config(text="👁️ Show")
    else:
        password_entry.config(show="")
        toggle_btn.config(text="🙈 Hide")

# ---------------------------- DOWNLOAD ALL PASSWORDS AS JSON ------------------------------- #
def download_all_passwords():
    try:
        combined = {}
        # From Mongo if enabled
        if STORE_IN_MONGO:
            try:
                for doc in CREDENTIALS_COLL.find({}):
                    website = doc.get("website", "").strip()
                    email = doc.get("email", "").strip()
                    try:
                        pwd = decrypt(doc.get("password", ""))
                    except:
                        continue
                    combined.setdefault(website, {})[email] = pwd
            except:
                pass
        # From local plaintext backup (fill in missing)
        if os.path.exists(LOCAL_BACKUP_FILE):
            try:
                with open(LOCAL_BACKUP_FILE, "r", encoding="utf-8") as f:
                    local_data = json.load(f)
                for website, emails in local_data.items():
                    for email, pw in emails.items():
                        if website not in combined or email not in combined[website]:
                            combined.setdefault(website, {})[email] = pw
            except:
                pass

        if not combined:
            messagebox.showinfo("Empty", "No passwords found to download.")
            return

        # Sort
        sorted_data = {k: dict(sorted(v.items())) for k, v in sorted(combined.items())}

        file_path = os.path.join(BASE_DIR, "NOTEPAD.json")
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except:
                pass

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(sorted_data, f, indent=2)

        messagebox.showinfo("Success", f"All passwords saved to:\n{file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to download passwords:\n{e}")

# ---------------------------- MAIN WINDOW ------------------------------- #
def launch_main_window():
    global window, website_entry, email_entry, password_entry, password_var, toggle_btn
    global letters_var, numbers_var, symbols_var, length_var

    window = tk.Tk()
    window.title("Password Manager")
    window.withdraw()
    center_window(window, 900, 500)
    window.deiconify()
    window.config(padx=40, pady=30, bg="#f7f9fb")
    if STORE_IN_MONGO:
        window.geometry("900x550")
    else:
        window.geometry("900x500")
    window.resizable(False, False)
    try:
        window.iconbitmap(resource_path("initial_image.ico"))
    except:
        pass

    letters_var = tk.BooleanVar(value=True)
    numbers_var = tk.BooleanVar(value=True)
    symbols_var = tk.BooleanVar(value=True)
    length_var = tk.IntVar(value=12)

    main_frame = tk.Frame(window, bg="#f7f9fb")
    main_frame.pack(fill="both", expand=True)

    left_frame = tk.Frame(main_frame, bg="#f7f9fb")
    left_frame.grid(row=0, column=0, padx=(0, 40), sticky="ns")
    left_frame.grid_rowconfigure(0, weight=1)

    logo_container = tk.Frame(left_frame, bg="#f7f9fb")
    logo_container.grid(row=0, column=0)
    logo_container.grid_propagate(False)

    try:
        logo_img = Image.open(resource_path("logo.png"))
        logo_img = logo_img.resize((200, 200), Image.Resampling.LANCZOS)
        logo_photo = ImageTk.PhotoImage(logo_img)
        logo_label = tk.Label(logo_container, image=logo_photo, bg="#f7f9fb")
        logo_label.image = logo_photo
        logo_label.pack(expand=True)
    except Exception as e:
        print(f"Couldn't load logo.png: {e}")

    right_frame = tk.Frame(main_frame, bg="#f7f9fb")
    right_frame.grid(row=0, column=1, sticky="n")

    form_frame = tk.Frame(right_frame, bg="#f7f9fb")
    form_frame.pack(pady=10)

    label_font = ("Segoe UI", 11, "bold")
    entry_font = ("Segoe UI", 11)

    tk.Label(form_frame, text="Website:", bg="#f7f9fb", font=label_font).grid(row=0, column=0, sticky="w")
    website_entry = tk.Entry(form_frame, width=50, font=entry_font)
    website_entry.grid(row=1, column=0, padx=5, pady=(0, 10))
    website_entry.focus()

    tk.Label(form_frame, text="Email/Username:", bg="#f7f9fb", font=label_font).grid(row=2, column=0, sticky="w")
    email_entry = tk.Entry(form_frame, width=50, font=entry_font)
    email_entry.grid(row=3, column=0, padx=5, pady=(0, 10))

    tk.Label(form_frame, text="Password:", bg="#f7f9fb", font=label_font).grid(row=4, column=0, sticky="w")
    password_entry = tk.Entry(form_frame, width=50, font=entry_font, show="*")
    password_entry.grid(row=5, column=0, padx=5, pady=(0, 10))

    btn_frame = tk.Frame(form_frame, bg="#f7f9fb")
    btn_frame.grid(row=6, column=0, sticky="e", pady=(0, 20))

    tk.Button(btn_frame, text="Generate", width=10, command=generate_password, bg="#d4f7dc").pack(side="left", padx=5)
    toggle_btn = tk.Button(btn_frame, text="👁️ Show", width=10, command=toggle_password, bg="#eeeeee")
    toggle_btn.pack(side="left", padx=5)

    length_frame = tk.Frame(right_frame, bg="#f7f9fb")
    length_frame.pack(pady=(0, 10))

    slider_font = ("Segoe UI", 10)
    tk.Label(length_frame, text="Password Length:", bg="#f7f9fb", font=slider_font).pack(side="left", padx=(0, 5))
    tk.Label(length_frame, textvariable=length_var, bg="#f7f9fb", font=slider_font).pack(side="left", padx=(0, 10))
    tk.Scale(length_frame, from_=8, to=32, orient="horizontal", variable=length_var, length=300,
             bg="#f7f9fb", showvalue=False, sliderlength=15, command=lambda val: generate_password()).pack(side="left")

    options_frame = tk.Frame(right_frame, bg="#f7f9fb")
    options_frame.pack(pady=(10, 20))

    tk.Label(options_frame, text="Include:", bg="#f7f9fb", font=slider_font).grid(row=0, column=0, padx=10)
    tk.Checkbutton(options_frame, text="Letters", variable=letters_var, bg="#f7f9fb", font=slider_font).grid(row=0, column=1, padx=10)
    tk.Checkbutton(options_frame, text="Numbers", variable=numbers_var, bg="#f7f9fb", font=slider_font).grid(row=0, column=2, padx=10)
    tk.Checkbutton(options_frame, text="Symbols", variable=symbols_var, bg="#f7f9fb", font=slider_font).grid(row=0, column=3, padx=10)

    tk.Button(right_frame, text="Add Password", width=50, command=save_password, bg="#ffd8b5",
              font=("Segoe UI", 11, "bold"), relief="flat").pack(pady=10)

    tk.Button(right_frame, text="🔎 Show All Passwords", width=50, command=show_all_passwords, bg="#cfe2ff",
              font=("Segoe UI", 11, "bold"), relief="flat").pack(pady=10)
    
    if STORE_IN_MONGO:
        tk.Button(
            right_frame,
            text="📥 Download All Passwords",
            width=50,
            command=download_all_passwords,
            bg="#cfe2ff",
            font=("Segoe UI", 11, "bold"),
            relief="flat"
        ).pack(pady=10)

    window.mainloop()

# ---------------------------- ENTRY POINT ------------------------------- #
if not is_admin_setup():
    def set_initial_admin_password():
        init_pw_win = tk.Tk()
        init_pw_win.title("Set Admin Password")
        init_pw_win.withdraw()
        center_window(init_pw_win, 400, 250)
        init_pw_win.deiconify()
        init_pw_win.geometry("400x250")
        init_pw_win.configure(bg="#f7f9fb")
        init_pw_win.resizable(False, False)
        try:
            init_pw_win.iconbitmap(resource_path("initial_image.ico"))
        except:
            pass

        frame = tk.Frame(init_pw_win, bg="#f7f9fb", padx=20, pady=20)
        frame.pack(expand=True, fill="both")
        tk.Label(frame, text="Create Admin Password", bg="#f7f9fb", font=("Segoe UI", 13, "bold")).pack(pady=(0, 15))

        def make_labeled_entry(label_text):
            tk.Label(frame, text=label_text, bg="#f7f9fb", font=("Segoe UI", 10)).pack(anchor="w", padx=52)
            entry = tk.Entry(frame, show="*", width=35, font=("Segoe UI", 10))
            entry.pack(pady=5)
            return entry

        new_pw_entry = make_labeled_entry("New Password:")
        confirm_pw_entry = make_labeled_entry("Confirm Password:")

        def continue_to_questions():
            pw1 = new_pw_entry.get()
            pw2 = confirm_pw_entry.get()
            if not pw1 or not pw2:
                messagebox.showerror("Error", "Fields cannot be empty.")
                return
            if pw1 != pw2:
                messagebox.showerror("Mismatch", "Passwords do not match.")
                return
            init_pw_win.destroy()
            set_security_questions_first_time(pw1)

        tk.Button(frame, text="Continue", command=continue_to_questions,
                  bg="#d4f7dc", font=("Segoe UI", 10, "bold"), width=25).pack(pady=15)
        init_pw_win.mainloop()

    def set_security_questions_first_time(admin_password):
        setup_win = tk.Tk()
        setup_win.title("Set Security Questions")
        setup_win.withdraw()
        center_window(setup_win, 500, 400)
        setup_win.deiconify()
        setup_win.geometry("500x400")
        setup_win.configure(bg="#f7f9fb")
        setup_win.resizable(False, False)
        try:
            setup_win.iconbitmap(resource_path("security_image.ico"))
        except:
            pass

        frame = tk.Frame(setup_win, bg="#f7f9fb", padx=20, pady=20)
        frame.pack(expand=True, fill="both")
        tk.Label(frame, text="Set Security Questions", bg="#f7f9fb", font=("Segoe UI", 13, "bold")).pack(pady=(0, 15))

        def make_question(label_text):
            tk.Label(frame, text=label_text, bg="#f7f9fb", font=("Segoe UI", 10)).pack(anchor="w", padx=62)
            entry = tk.Entry(frame, width=50)
            entry.pack(pady=4)
            return entry

        q1 = make_question("1. High School Name")
        q2 = make_question("2. Intermediate School Name")
        q3 = make_question("3. Maternal Grandmother Name")
        q4 = make_question("4. Grandfather Name")
        q5 = make_question("5. Grandmother Name")

        def save_all():
            if not all([q1.get(), q2.get(), q3.get(), q4.get(), q5.get()]):
                messagebox.showerror("Error", "All fields are required.")
                return
            answers = {
                "High School Name": q1.get().strip(),
                "Intermediate School Name": q2.get().strip(),
                "Maternal Grandmother Name": q3.get().strip(),
                "Grandfather Name": q4.get().strip(),
                "Grandmother Name": q5.get().strip(),
            }
            save_admin_password(admin_password, answers)
            messagebox.showinfo("Success", "Admin password and security questions set.")
            setup_win.destroy()
            login_window()

        tk.Button(frame, text="Save", command=save_all, bg="#d4f7dc", font=("Segoe UI", 10, "bold"),
                  width=25).pack(pady=15)
        setup_win.mainloop()

    set_initial_admin_password()
else:
    login_window()
