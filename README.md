 # 🔐 LocalPass — Password Manager (Python + Flask)

A secure, local, beginner-friendly **Password Manager Web App** built using  
**Python, Flask, HTML, CSS, and JavaScript**.  
It includes **master password authentication**, **encrypted storage**,  
and a clean, modern UI.

---

## 🚀 Features

- 🔐 **Master Password Login**  
- 🔒 **AES-based Encryption** using Fernet + PBKDF2  
- 📝 **Add, View, Edit, Delete Credentials**  
- 🗄️ **Local SQLite Database**  
- 📤 **Export Encrypted Database**  
- 🌐 **Clean Frontend (HTML/CSS/JS)**  
- ⚙️ **Full Flask REST API**

---

## 📦 Tech Stack

- **Backend:** Flask, SQLAlchemy, cryptography  
- **Frontend:** HTML5, CSS3, JavaScript (Fetch API)  
- **Database:** SQLite  
- **Security:** PBKDF2HMAC, Fernet Encryption

---

## 📁 Project Structure

```
password-manager/
│
├── app.py
├── requirements.txt
├── templates/
│   └── index.html
├── static/
│   ├── styles.css
│   └── app.js
└── README.md
```

---

## 🛠 Installation & Setup

```
git clone https://github.com/<your-username>/password-manager.git
cd password-manager

# Create virtual environment
python -m venv venv
source venv/bin/activate     # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```

Now open:

```
http://127.0.0.1:5000/
```

---

## 🔐 Security Notes

✔ Passwords are encrypted before storage  
✔ Master password is hashed using PBKDF2  
✔ Database contains **only ciphertext**, never plain passwords  

⚠️ This project is for **learning** — not production use.

---

## 📸 Screenshots  

*(Add your own images)*  
```
/screenshots
  ├── login.png
  ├── dashboard.png
```

---

## 🤝 Contributions

Pull requests are welcome. Feel free to open issues or suggest new features!

---

## ⭐ Show Your Support  
If you like this project, consider giving it a ⭐ on GitHub!

---

