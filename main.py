import random
import secrets
import tkinter as tk
import sqlite3
import hashlib

#Ģenerē paroli
def generate_password(length=8):
  """Ģenerē stipru, nejaušu paroli ar norādīto garumu.

  Args:
      length (int, optional): Vēlamais paroles garums. Defult ir 16.

  Returns:
      str: Ģenerētā random parole.
  """

  # Rakstzīmju kopas dažādiem paroles elementiem
  lowercase_letters = "abcdefghijklmnopqrstuvwxyz"
  uppercase_letters = lowercase_letters.upper()
  digits = "0123456789"
  symbols = "!\"()*+,-./0123456789:;<=>?"

  # Combine character sets for password generation
  all_chars = lowercase_letters + uppercase_letters + digits + symbols

  # Ģenerēt nejaušu paroli ar vismaz vienu rakstzīmi no katras kopas
  password = [secrets.choice(lowercase_letters), secrets.choice(uppercase_letters),
              secrets.choice(digits), secrets.choice(symbols)]

  # Aizpilda atlikušos slotus ar nejaušām rakstzīmēm no kombinētās kopas
  password.extend(random.sample(all_chars, length - len(password)))

  # Jaukt rakstzīmes, lai iegūtu dažādāku paroli x2 (nezinu vaitas palīdzēs)
  random.shuffle(password)
  random.shuffle(password)
  # Atgriež paroli kā string
  return ''.join(password)

#Iesevē paroli
def save_password(password):
   # """Iesevē ģenerēto paroli datubāzē."""
   # conn = sqlite3.connect("password.db")
   # c = conn.cursor()
   # c.execute("INSERT INTO passwords (password) VALUES (?)", (password,))
   # conn.commit()
   # conn.close()

  if password:
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    connection = sqlite3.connect("password.db")
    c = connection.cursor()
    c.execute("INSERT INTO passwords (original_password, hashed_password) VALUES (?, ?)", (password, hashed_password))
    connection.commit()
    connection.close()
  else:
    raise ValueError("Nevar būt tukša parole!") #Šis ir lai netiktu datubāzē tukšas paroles iesevētas, error redz tikai consolē

#Nokopē uz clipboarda
def copy_to_clipboard(password):
  global copy_button
  password = generated_password
  
  """Nokopē ģenerēto paroli clipboardā."""
  root.clipboard_clear() #Izdzēš iepriekšējo clipboard
  root.clipboard_append(password)
  root.update()
  copy_button.config(text="Copied!")
  root.after(1000, lambda: copy_button.config(text="Copy"))  # Pēc 1 sekundes reseto texta pogu


#Parāda visas iesevētās paroles
def show_saved_passwords():
    """Parāda visas saglabātās paroles jaunā logā."""
    connection = sqlite3.connect("password.db")
    c = connection.cursor()
    c.execute("SELECT original_password FROM passwords")
    saved_passwords = c.fetchall()
    connection.close()

    if saved_passwords:
        #saved_passwords_str = "\n".join([f"{password[0]}" for password in saved_passwords])
        saved_passwords_str = "\n".join([password[0] for password in saved_passwords])
    else:
        saved_passwords_str = "Neviena parole nav iesevēta."

    saved_passwords_window = tk.Toplevel(root)
    saved_passwords_window.geometry("400x300")
    saved_passwords_window.title("Saglabātās paroles")
    saved_passwords_label = tk.Label(saved_passwords_window, text=saved_passwords_str)
    saved_passwords_label.pack()

    for password in saved_passwords:
        password_text = password[0]
        password_frame = tk.Frame(saved_passwords_window)
        password_frame.pack(fill=tk.X, padx=10, pady=5)
        password_label = tk.Label(password_frame, text=password_text)
        password_label.pack(side=tk.LEFT, expand=True)
        copy_button = tk.Button(password_frame, text="Copy", command=lambda p=password_text: copy_to_clipboard(p))
        copy_button.pack(side=tk.RIGHT)


#Galvenais logs
def main():
  global root
  #Izveido tabel ja password key neeksistē password.db
  connection = sqlite3.connect("password.db")
  c = connection.cursor()
  c.execute('''CREATE TABLE IF NOT EXISTS passwords
                     (id INTEGER PRIMARY KEY, original_password TEXT, hashed_password TEXT)''')
  connection.commit()
  connection.close()

  # Galvenais logs
  root = tk.Tk()
  root.title("Grūta parole")
  root.geometry("400x300")
  root.resizable(False, False)
  # Paroles garuma lables
  length_label = tk.Label(root, text="Paroles garums:")
  length_label.pack()

  # Ievades lauks paroles garumam
  length_entry = tk.Entry(root, width=5)
  length_entry.insert(0, "8")  # Iestatīs default garumu
  length_entry.pack()

  # Poga lai ģenerētu paroli
  generate_button = tk.Button(root, background="light blue", text="Ģenerēt paroli", command=lambda: generate_password_and_display())
  generate_button.pack()

  # Logs lai parādītu ģenerēto paroli
  password_label = tk.Label(root, text="Ģenerētā parole:")
  password_label.pack()

  global passowrd_var
  password_var = tk.StringVar()  # StringVar, lai paturētu parādāmo un kopējamo paroli
  password_display = tk.Entry(root, textvariable=password_var, state='readonly')
  password_display.pack()

  # Poga lai nokopētu paroli uz clipboard
  copy_button = tk.Button(root, text="Copy to clipboard", background="light blue", command=lambda: copy_to_clipboard(password_var.get()))
  copy_button.pack()

  # Pogas lai saglabātu paroli un saglabāto paroli apskatīšana
  save_button = tk.Button(root, text="Save", background="light blue", command=lambda: save_and_display_password(password_var.get()))
  save_button.pack()
  #Poga lai parādītu iesevētās paroles
  show_saved_button = tk.Button(root, background="light blue", text="Parādīt saglabātās paroles", command=show_saved_passwords)
  show_saved_button.pack()
  
  #Ģenerē parolu un parādā ģenerēto paroli
  def generate_password_and_display():
    try:
      global generated_password
      length = int(length_entry.get())
      generated_password = generate_password(length)
      password_var.set(generated_password)
      print(type(password_var))
    except ValueError:
      password_label.config(text="Neatbilstošs sakitlis! Ievadie skaitli virs 0 un mazāku par 92!")
      root.after(8000, lambda: password_label.config(text="Ģenerētā parole:"))  # Restartē lable atpakaļ uz " " pēc 8sec
 
  #Iesevē un parāda ģenerēto paroli :)
  def save_and_display_password(password):
        save_password(password)
        password_var.set("")
        show_saved_passwords()

  root.mainloop()

#Nodrošina, ka galvenā main() funkcija tiek izpildīta tikai tad, kad skripts tiek izpildīts tieši, nevis tad, kad tas tiek importēts kā modulis citā skriptā.
if __name__ == "__main__":
  main()