from flask import Flask, render_template, request, redirect, session, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash

import sqlite3
import random
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret!'

socketio = SocketIO(app)

# ======================
# DB初期化
# ======================

def init_db():

    conn = sqlite3.connect("chat.db")

    c = conn.cursor()

    # ユーザー

    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        password TEXT
    )
    """)

    # メッセージ

    c.execute("""
    CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room TEXT,
        username TEXT,
        message TEXT
    )
    """)

    # ルーム履歴

    c.execute("""
    CREATE TABLE IF NOT EXISTS room_members(
        room TEXT,
        username TEXT,
        note TEXT
    )
    """)

    # ルーム設定

    c.execute("""
    CREATE TABLE IF NOT EXISTS room_settings(
        room TEXT PRIMARY KEY,
        password_enabled INTEGER,
        password TEXT
    )
    """)

    # CREATERログ

    c.execute("""
    CREATE TABLE IF NOT EXISTS creator_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT
    )
    """)

    conn.commit()

    conn.close()

init_db()

# ======================
# メモリ上ルーム
# ======================

rooms = {}

# ======================
# index
# ======================

@app.route("/")
def index():

    if "username" not in session:
        return render_template("auth.html")

    username = session["username"]

    conn = sqlite3.connect("chat.db")

    c = conn.cursor()

    # ルーム履歴

    c.execute(
        """
        SELECT room, note
        FROM room_members
        WHERE username=?
        """,
        (username,)
    )

    room_history = c.fetchall()

    # CREATERログ

    c.execute(
        """
        SELECT id,message
        FROM creator_logs
        ORDER BY id DESC
        """
    )

    creator_logs = c.fetchall()

    conn.close()

    return render_template(
        "index.html",
        username=username,
        room_history=room_history,
        creator_logs=creator_logs
    )

# ======================
# 通話ページ
# ======================

@app.route("/call/<room_id>")
def call(room_id):

    if "username" not in session:
        return redirect("/")

    return render_template(
        "call.html",
        room_id=room_id
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

    c.execute(
        """
        SELECT *
        FROM users
        WHERE username=?
        """,
        (username,)
    )

    if c.fetchone():

        conn.close()

        return "そのユーザーは既に存在します"

    password_hash =
        generate_password_hash(password)

    c.execute(
        """
        INSERT INTO users
        VALUES (?,?)
        """,
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
        """
        SELECT password
        FROM users
        WHERE username=?
        """,
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
# メモ保存
# ======================

@app.route("/save_note", methods=["POST"])
def save_note():

    data = request.get_json()

    room = data["room"]

    note = data["note"]

    username = session["username"]

    conn = sqlite3.connect("chat.db")

    c = conn.cursor()

    c.execute(
        """
        UPDATE room_members
        SET note=?
        WHERE room=? AND username=?
        """,
        (note, room, username)
    )

    conn.commit()

    conn.close()

    return jsonify({
        "status":"ok"
    })

# ======================
# 履歴削除
# ======================

@app.route("/delete_room", methods=["POST"])
def delete_room():

    data = request.get_json()

    room = data["room"]

    username = session["username"]

    conn = sqlite3.connect("chat.db")

    c = conn.cursor()

    c.execute(
        """
        DELETE FROM room_members
        WHERE room=? AND username=?
        """,
        (room, username)
    )

    conn.commit()

    conn.close()

    return jsonify({
        "status":"ok"
    })

# ======================
# ルームパスワード設定
# ======================

@app.route("/set_room_password", methods=["POST"])
def set_room_password():

    data = request.get_json()

    room = data["room"]

    enabled = data["enabled"]

    password = data["password"]

    conn = sqlite3.connect("chat.db")

    c = conn.cursor()

    c.execute(
        """
        UPDATE room_settings
        SET password_enabled=?,
            password=?
        WHERE room=?
        """,
        (
            1 if enabled else 0,
            password,
            room
        )
    )

    conn.commit()

    conn.close()

    return jsonify({
        "status":"ok"
    })

# ======================
# 参加前パスワード確認
# ======================

@app.route("/check_room_password", methods=["POST"])
def check_room_password():

    data = request.get_json()

    room = data["room"]

    password = data.get("password","")

    username = session["username"]

    conn = sqlite3.connect("chat.db")

    c = conn.cursor()

    # 履歴確認

    c.execute(
        """
        SELECT *
        FROM room_members
        WHERE room=? AND username=?
        """,
        (room, username)
    )

    already_joined = c.fetchone()

    # 初参加じゃないならOK

    if already_joined:

        conn.close()

        return jsonify({
            "ok":True
        })

    # パス設定確認

    c.execute(
        """
        SELECT password_enabled,password
        FROM room_settings
        WHERE room=?
        """,
        (room,)
    )

    row = c.fetchone()

    conn.close()

    # 設定なし

    if not row:

        return jsonify({
            "ok":True
        })

    enabled = row[0]

    real_password = row[1]

    # OFF

    if enabled == 0:

        return jsonify({
            "ok":True
        })

    # PASS一致

    if password == real_password:

        return jsonify({
            "ok":True
        })

    return jsonify({
        "ok":False
    })

# ======================
# room id生成
# ======================

def generate_room_id():

    while True:

        room_id = str(
            random.randint(10000000,99999999)
        )

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

    conn = sqlite3.connect("chat.db")

    c = conn.cursor()

    c.execute(
        """
        INSERT INTO room_members
        (room,username,note)
        VALUES (?,?,?)
        """,
        (room_id, username, "")
    )

    # デフォルト設定

    c.execute(
        """
        INSERT OR REPLACE INTO room_settings
        (room,password_enabled,password)
        VALUES (?,?,?)
        """,
        (room_id, 0, "")
    )

    conn.commit()

    conn.close()

    emit(
        "room_created",
        {
            "room":room_id
        }
    )

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

    conn = sqlite3.connect("chat.db")

    c = conn.cursor()

    c.execute(
        """
        SELECT *
        FROM room_members
        WHERE room=? AND username=?
        """,
        (room_id, username)
    )

    if not c.fetchone():

        c.execute(
            """
            INSERT INTO room_members
            (room,username,note)
            VALUES (?,?,?)
            """,
            (room_id, username, "")
        )

    conn.commit()

    emit(
        "joined",
        {
            "room":room_id
        }
    )

    # 過去メッセージ

    c.execute(
        """
        SELECT username,message
        FROM messages
        WHERE room=?
        """,
        (room_id,)
    )

    rows = c.fetchall()

    conn.close()

    for row in rows:

        emit(
            "chat_message",
            {
                "username":row[0],
                "message":row[1]
            }
        )

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

    conn = sqlite3.connect("chat.db")

    c = conn.cursor()

    c.execute(
        """
        INSERT INTO messages
        (room,username,message)
        VALUES (?,?,?)
        """,
        (room, username, message)
    )

    conn.commit()

    conn.close()

    emit(
        "chat_message",
        {
            "username":username,
            "message":message
        },
        room=room
    )

# ======================
# 通話開始通知
# ======================

@socketio.on("call_started")
def call_started(data):

    room = data["room"]

    username = session["username"]

    emit(
        "call_notification",
        {
            "username": username,
            "room": room
        },
        room=room
    )

# ======================
# 通話終了通知
# ======================

@socketio.on("call_ended")
def call_ended(data):

    room = data["room"]

    username = session["username"]

    emit(
        "call_end_notification",
        {
            "username": username
        },
        room=room
    )

# ======================
# CREATERログ投稿
# ======================

@socketio.on("add_creator_log")
def add_creator_log(data):

    username = session["username"]

    # 開発者限定

    if username != "開発者":
        return

    message = data["message"]

    conn = sqlite3.connect("chat.db")

    c = conn.cursor()

    c.execute(
        """
        INSERT INTO creator_logs(message)
        VALUES (?)
        """,
        (message,)
    )

    log_id = c.lastrowid

    conn.commit()

    conn.close()

    socketio.emit(
        "new_creator_log",
        {
            "id":log_id,
            "message":message
        }
    )

# ======================
# CREATERログ削除
# ======================

@socketio.on("delete_creator_log")
def delete_creator_log(data):

    username = session["username"]

    if username != "開発者":
        return

    log_id = data["id"]

    conn = sqlite3.connect("chat.db")

    c = conn.cursor()

    c.execute(
        """
        DELETE FROM creator_logs
        WHERE id=?
        """,
        (log_id,)
    )

    conn.commit()

    conn.close()

    socketio.emit(
        "creator_log_deleted",
        {
            "id":log_id
        }
    )

# ======================
# main
# ======================

if __name__ == "__main__":

    port = int(
        os.environ.get("PORT", 5000)
    )

    socketio.run(
        app,
        host="0.0.0.0",
        port=port
    )
