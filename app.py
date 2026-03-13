from flask import Flask, render_template, request, redirect, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'

socketio = SocketIO(app)

# ======================
# DB初期化
# ======================

def init_db():

    conn = sqlite3.connect("chat.db")
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        password TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room TEXT,
        username TEXT,
        message TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS room_members(
        room TEXT,
        username TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

rooms = {}

# ======================
# ページ
# ======================

@app.route("/")
def index():

    if "username" not in session:
        return render_template("auth.html")

    username = session["username"]

    conn = sqlite3.connect("chat.db")
    c = conn.cursor()

    c.execute(
        "SELECT DISTINCT room FROM room_members WHERE username=?",
        (username,)
    )

    room_history = c.fetchall()

    conn.close()

    return render_template(
        "index.html",
        username=username,
        room_history=room_history
    )

# ======================
# register
# ======================

@app.route("/register", methods=["POST"])
def register():

    username = request.form["username"]
    password = request.form["password"]

    conn = sqlite3.connect("chat.db")
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE username=?", (username,))
    if c.fetchone():
        conn.close()
        return "そのユーザーは既に存在します"

    password_hash = generate_password_hash(password)

    c.execute(
        "INSERT INTO users VALUES (?,?)",
        (username, password_hash)
    )

    conn.commit()
    conn.close()

    session["username"] = username

    return redirect("/")

# ======================
# login
# ======================

@app.route("/login", methods=["POST"])
def login():

    username = request.form["username"]
    password = request.form["password"]

    conn = sqlite3.connect("chat.db")
    c = conn.cursor()

    c.execute(
        "SELECT password FROM users WHERE username=?",
        (username,)
    )

    row = c.fetchone()
    conn.close()

    if not row:
        return "ユーザーが存在しません"

    if not check_password_hash(row[0], password):
        return "パスワードが違います"

    session["username"] = username

    return redirect("/")

# ======================
# logout
# ======================

@app.route("/logout")
def logout():

    session.pop("username", None)

    return redirect("/")

# ======================
# room id
# ======================

def generate_room_id():

    while True:

        room_id = str(random.randint(10000000,99999999))

        if room_id not in rooms:
            rooms[room_id] = []
            return room_id

# ======================
# create room
# ======================

@socketio.on("create_room")
def create_room():

    username = session["username"]

    room_id = generate_room_id()

    rooms[room_id].append(username)

    join_room(room_id)

    conn = sqlite3.connect("chat.db")
    c = conn.cursor()

    c.execute(
        "INSERT INTO room_members(room,username) VALUES (?,?)",
        (room_id, username)
    )

    conn.commit()
    conn.close()

    emit("room_created", {"room":room_id})

# ======================
# join room
# ======================

@socketio.on("join_room_by_id")
def join_room_by_id(data):

    room_id = data["room"]
    username = session["username"]

    if room_id not in rooms:
        rooms[room_id] = []

    if username not in rooms[room_id]:
        rooms[room_id].append(username)

    join_room(room_id)

    conn = sqlite3.connect("chat.db")
    c = conn.cursor()

    c.execute(
        "SELECT * FROM room_members WHERE room=? AND username=?",
        (room_id, username)
    )

    if not c.fetchone():
        c.execute(
            "INSERT INTO room_members(room,username) VALUES (?,?)",
            (room_id, username)
        )

    conn.commit()

    emit("joined", {"room":room_id})

    # メッセージ履歴送信
    c.execute(
        "SELECT username,message FROM messages WHERE room=?",
        (room_id,)
    )

    rows = c.fetchall()
    conn.close()

    for row in rows:

        emit("chat_message",{
            "username":row[0],
            "message":row[1]
        })

# ======================
# leave
# ======================

@socketio.on("leave_room")
def leave(data):

    room_id = data["room"]
    username = session["username"]

    leave_room(room_id)

    if room_id in rooms:
        if username in rooms[room_id]:
            rooms[room_id].remove(username)

# ======================
# message
# ======================

@socketio.on("message")
def handle_message(data):

    room = data["room"]
    message = data["message"]
    username = session["username"]

    conn = sqlite3.connect("chat.db")
    c = conn.cursor()

    c.execute(
        "INSERT INTO messages(room,username,message) VALUES (?,?,?)",
        (room, username, message)
    )

    conn.commit()
    conn.close()

    emit("chat_message",{
        "username":username,
        "message":message
    }, room=room)

# ======================

if __name__ == "__main__":
    socketio.run(app, debug=True)
