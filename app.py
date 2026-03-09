from flask import Flask, render_template, request, redirect, session
from flask_socketio import SocketIO, send, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'

socketio = SocketIO(app)

# ======================
# データ保存
# ======================

users = {}

rooms = {}
# rooms = {
#   "12345678": {
#       "members": ["A","B"],
#       "messages": [
#           {"username":"A","message":"hello"}
#       ]
#   }
# }

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

    if username in users:
        return "そのユーザーは既に存在します"

    users[username] = generate_password_hash(password)
    session["username"] = username
    return redirect("/")


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    if username not in users:
        return "ユーザーが存在しません"

    if not check_password_hash(users[username], password):
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
            rooms[room_id] = {
                "members": [],
                "messages": []
            }
            return room_id

# ======================
# ルーム作成
# ======================

@socketio.on("create_room")
def handle_create_room():
    username = session["username"]

    room_id = generate_room_id()

    rooms[room_id]["members"].append(username)

    join_room(room_id)

    send({"type": "room_created", "room": room_id})

# ======================
# ルーム参加
# ======================

@socketio.on("join_room_by_id")
def handle_join_room(data):

    room_id = data["room"]
    username = session["username"]

    if room_id not in rooms:
        send({"type": "error", "message": "ルームが存在しません"})
        return

    if username not in rooms[room_id]["members"]:
        rooms[room_id]["members"].append(username)

    join_room(room_id)

    send({"type": "joined", "room": room_id})

    # 過去メッセージ送信
    for msg in rooms[room_id]["messages"]:
        send(msg)

# ======================
# ルーム退出
# ======================

@socketio.on("leave_room")
def handle_leave_room(data):

    room_id = data["room"]
    username = session["username"]

    leave_room(room_id)

    if room_id in rooms:

        if username in rooms[room_id]["members"]:
            rooms[room_id]["members"].remove(username)

        if len(rooms[room_id]["members"]) == 0:
            del rooms[room_id]

# ======================
# メッセージ
# ======================

@socketio.on("message")
def handle_message(data):

    room_id = data["room"]
    username = session["username"]
    message = data["message"]

    msg_data = {
        "username": username,
        "message": message
    }

    # 履歴保存
    rooms[room_id]["messages"].append(msg_data)

    # 送信
    send(msg_data, room=room_id)

# ======================

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=10000)
