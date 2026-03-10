from flask import Flask, render_template, request, redirect, session
from flask_socketio import SocketIO, send, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'

socketio = SocketIO(app)

# ======================
# SQLite 初期化
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

    conn.commit()
    conn.close()

init_db()

# ======================
# メモリ管理
# ======================

rooms = {}

# ======================
# ページ
# ======================

@app.route("/")
def index():
    if "username" not in session:
        return render_template("auth.html")
    return render_template("index.html", username=session["username"])


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

    hash_pw = generate_password_hash(password)

    c.execute("INSERT INTO users VALUES (?,?)", (username, hash_pw))

    conn.commit()
    conn.close()

    session["username"] = username
    return redirect("/")


@app.route("/login", methods=["POST"])
def login():

    username = request.form["username"]
    password = request.form["password"]

    conn = sqlite3.connect("chat.db")
    c = conn.cursor()

    c.execute("SELECT password FROM users WHERE username=?", (username,))
    row = c.fetchone()

    conn.close()

    if not row:
        return "ユーザーが存在しません"

    if not check_password_hash(row[0], password):
        return "パスワードが違います"

    session["username"] = username

    return redirect("/")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/")

# ======================
# ルーム生成
# ======================

def generate_room_id():

    while True:

        room_id = str(random.randint(10000000, 99999999))

        if room_id not in rooms:

            rooms[room_id] = []

            return room_id

# ======================
# ルーム作成
# ======================

@socketio.on("create_room")
def create_room():

    username = session["username"]

    room_id = generate_room_id()

    rooms[room_id].append(username)

    join_room(room_id)

    send({"type":"room_created","room":room_id})

# ======================
# ルーム参加
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

    send({"type":"joined","room":room_id})

    # ======================
    # 過去メッセージ送信
    # ======================

    conn = sqlite3.connect("chat.db")
    c = conn.cursor()

    c.execute(
        "SELECT username,message FROM messages WHERE room=?",
        (room_id,)
    )

    rows = c.fetchall()

    conn.close()

    for row in rows:

        send({
            "username":row[0],
            "message":row[1]
        })

# ======================
# ルーム退出
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
# メッセージ
# ======================

@socketio.on("message")
def handle_message(data):

    room = data["room"]
    message = data["message"]
    username = session["username"]

    # DB保存

    conn = sqlite3.connect("chat.db")
    c = conn.cursor()

    c.execute(
        "INSERT INTO messages(room,username,message) VALUES (?,?,?)",
        (room,username,message)
    )

    conn.commit()
    conn.close()

    send({
        "username":username,
        "message":message
    }, room=room)

# ======================

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=10000)
