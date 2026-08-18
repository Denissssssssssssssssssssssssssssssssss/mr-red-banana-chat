from flask import Flask, render_template, request, redirect, session, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash

from supabase import create_client

import random
import os
from datetime import datetime, timezone


# =========================================================
# Flask
# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = "secret!"

socketio = SocketIO(app)


# =========================================================
# Supabase
# =========================================================

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SECRET_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "SUPABASE_URL または SUPABASE_SECRET_KEY が設定されていません"
    )

supabase = create_client(
    SUPABASE_URL,
    SUPABASE_KEY
)


# =========================================================
# メモリ上のルーム参加者
#
# ※ルームそのものはSupabaseに保存する
# =========================================================

rooms = {}


# =========================================================
# index
# =========================================================

@app.route("/")
def index():

    if "username" not in session:
        return render_template("auth.html")

    username = session["username"]

    # -----------------------------------------
    # ルーム履歴
    # -----------------------------------------

    member_result = (
        supabase
        .table("room_members")
        .select("room_id,note")
        .eq("username", username)
        .execute()
    )

    room_history = []

    for row in member_result.data or []:

        room_id = row["room_id"]

        room_result = (
            supabase
            .table("rooms")
            .select("password_enabled")
            .eq("room_id", room_id)
            .execute()
        )

        locked = False

        if room_result.data:
            locked = bool(
                room_result.data[0].get(
                    "password_enabled",
                    False
                )
            )

        room_history.append(
            (
                room_id,
                row.get("note", ""),
                locked
            )
        )

    # -----------------------------------------
    # CREATERログ
    # -----------------------------------------

    creator_result = (
        supabase
        .table("creator_logs")
        .select("id,message")
        .order("id", desc=True)
        .execute()
    )

    creator_logs = []

    for row in creator_result.data or []:

        creator_logs.append(
            (
                row["id"],
                row["message"]
            )
        )

    return render_template(
        "index.html",
        username=username,
        room_history=room_history,
        creator_logs=creator_logs
    )


# =========================================================
# 通話ページ
# =========================================================

@app.route("/call/<room_id>")
def call(room_id):

    if "username" not in session:
        return redirect("/")

    return render_template(
        "call.html",
        room_id=room_id
    )


# =========================================================
# register
# =========================================================

@app.route("/register", methods=["POST"])
def register():

    username = request.form["username"]
    password = request.form["password"]

    # -----------------------------------------
    # ユーザー存在確認
    # -----------------------------------------

    result = (
        supabase
        .table("users")
        .select("username")
        .eq("username", username)
        .execute()
    )

    if result.data:

        return "そのユーザーは既に存在します"

    # -----------------------------------------
    # パスワードハッシュ化
    # -----------------------------------------

    password_hash = generate_password_hash(password)

    # -----------------------------------------
    # 保存
    # -----------------------------------------

    supabase.table("users").insert(
        {
            "username": username,
            "password": password_hash
        }
    ).execute()

    session["username"] = username

    return redirect("/")


# =========================================================
# login
# =========================================================

@app.route("/login", methods=["POST"])
def login():

    username = request.form["username"]
    password = request.form["password"]

    result = (
        supabase
        .table("users")
        .select("password")
        .eq("username", username)
        .execute()
    )

    if not result.data:

        return "ユーザーが存在しません"

    stored_password = result.data[0]["password"]

    if not check_password_hash(
        stored_password,
        password
    ):

        return "パスワードが違います"

    session["username"] = username

    return redirect("/")


# =========================================================
# logout
# =========================================================

@app.route("/logout")
def logout():

    session.pop("username", None)

    return redirect("/")


# =========================================================
# メモ保存
# =========================================================

@app.route("/save_note", methods=["POST"])
def save_note():

    if "username" not in session:
        return jsonify({"status": "error"}), 401

    data = request.get_json()

    room = data["room"]
    note = data["note"]

    username = session["username"]

    (
        supabase
        .table("room_members")
        .update(
            {
                "note": note
            }
        )
        .eq("room_id", room)
        .eq("username", username)
        .execute()
    )

    return jsonify({
        "status": "ok"
    })


# =========================================================
# 履歴削除
# =========================================================

@app.route("/delete_room", methods=["POST"])
def delete_room():

    if "username" not in session:
        return jsonify({"status": "error"}), 401

    data = request.get_json()

    room = data["room"]

    username = session["username"]

    (
        supabase
        .table("room_members")
        .delete()
        .eq("room_id", room)
        .eq("username", username)
        .execute()
    )

    return jsonify({
        "status": "ok"
    })


# =========================================================
# ルームパスワード設定
#
# ON / OFF       → いつでも変更可能
# パスワード変更 → 2時間に1回
#
# OFFにしてもパスワード自体は保存しておく
# =========================================================

@app.route("/set_room_password", methods=["POST"])
def set_room_password():

    if "username" not in session:
        return jsonify({
            "status": "error",
            "message": "ログインしてください"
        }), 401

    data = request.get_json()

    room = data["room"]
    enabled = bool(data.get("enabled", False))
    new_password = data.get("password", "")

    # -----------------------------------------
    # ルーム取得
    # -----------------------------------------

    result = (
        supabase
        .table("rooms")
        .select(
            "password_enabled,"
            "password,"
            "password_changed_at"
        )
        .eq("room_id", room)
        .execute()
    )

    if not result.data:

        return jsonify({
            "status": "error",
            "message": "ルームが存在しません"
        }), 404

    room_data = result.data[0]

    old_enabled = bool(
        room_data.get(
            "password_enabled",
            False
        )
    )

    old_password = room_data.get(
        "password"
    )

    password_changed_at = room_data.get(
        "password_changed_at"
    )

    # =====================================================
    # ON / OFFだけ変更する場合
    # =====================================================

    # OFF
    if not enabled:

        (
            supabase
            .table("rooms")
            .update(
                {
                    "password_enabled": False
                }
            )
            .eq("room_id", room)
            .execute()
        )

        return jsonify({
            "status": "ok",
            "password_changed": False
        })

    # =====================================================
    # ONにする
    # =====================================================

    # すでにパスワードが存在する場合
    # → 前のパスワードをそのまま使用
    if old_password:

        (
            supabase
            .table("rooms")
            .update(
                {
                    "password_enabled": True
                }
            )
            .eq("room_id", room)
            .execute()
        )

        return jsonify({
            "status": "ok",
            "password_changed": False
        })

    # =====================================================
    # 初めてパスワードを設定する
    # =====================================================

    if not new_password:

        return jsonify({
            "status": "error",
            "message": "初回はパスワードを入力してください"
        }), 400

    now = datetime.now(timezone.utc)

    (
        supabase
        .table("rooms")
        .update(
            {
                "password_enabled": True,
                "password": generate_password_hash(
                    new_password
                ),
                "password_changed_at": now.isoformat()
            }
        )
        .eq("room_id", room)
        .execute()
    )

    return jsonify({
        "status": "ok",
        "password_changed": True
    })


# =========================================================
# パスワード変更専用
#
# 2時間に1回
# =========================================================

@app.route("/change_room_password", methods=["POST"])
def change_room_password():

    if "username" not in session:
        return jsonify({
            "status": "error"
        }), 401

    data = request.get_json()

    room = data["room"]
    new_password = data.get("password", "")

    if not new_password:

        return jsonify({
            "status": "error",
            "message": "パスワードを入力してください"
        }), 400

    result = (
        supabase
        .table("rooms")
        .select(
            "password_changed_at"
        )
        .eq("room_id", room)
        .execute()
    )

    if not result.data:

        return jsonify({
            "status": "error",
            "message": "ルームが存在しません"
        }), 404

    password_changed_at = result.data[0].get(
        "password_changed_at"
    )

    # -----------------------------------------
    # 2時間制限
    # -----------------------------------------

    if password_changed_at:

        try:

            old_time = datetime.fromisoformat(
                password_changed_at.replace(
                    "Z",
                    "+00:00"
                )
            )

            now = datetime.now(timezone.utc)

            elapsed_seconds = (
                now - old_time
            ).total_seconds()

            if elapsed_seconds < 7200:

                remaining = int(
                    7200 - elapsed_seconds
                )

                minutes = remaining // 60

                return jsonify({
                    "status": "error",
                    "message":
                        f"パスワード変更は"
                        f"あと約{minutes}分後です"
                }), 429

        except Exception:

            pass

    # -----------------------------------------
    # パスワード変更
    # -----------------------------------------

    now = datetime.now(timezone.utc)

    (
        supabase
        .table("rooms")
        .update(
            {
                "password": generate_password_hash(
                    new_password
                ),
                "password_changed_at":
                    now.isoformat()
            }
        )
        .eq("room_id", room)
        .execute()
    )

    return jsonify({
        "status": "ok",
        "message": "パスワードを変更しました"
    })


# =========================================================
# 参加前パスワード確認
# =========================================================

@app.route("/check_room_password", methods=["POST"])
def check_room_password():

    if "username" not in session:
        return jsonify({
            "ok": False
        }), 401

    data = request.get_json()

    room = data["room"]
    password = data.get(
        "password",
        ""
    )

    username = session["username"]

    # -----------------------------------------
    # すでに履歴にあるか
    # -----------------------------------------

    member_result = (
        supabase
        .table("room_members")
        .select("room_id")
        .eq("room_id", room)
        .eq("username", username)
        .execute()
    )

    if member_result.data:

        return jsonify({
            "ok": True
        })

    # -----------------------------------------
    # ルーム設定
    # -----------------------------------------

    room_result = (
        supabase
        .table("rooms")
        .select(
            "password_enabled,password"
        )
        .eq("room_id", room)
        .execute()
    )

    if not room_result.data:

        return jsonify({
            "ok": True
        })

    room_data = room_result.data[0]

    enabled = bool(
        room_data.get(
            "password_enabled",
            False
        )
    )

    real_password = room_data.get(
        "password"
    )

    # -----------------------------------------
    # OFF
    # -----------------------------------------

    if not enabled:

        return jsonify({
            "ok": True
        })

    # -----------------------------------------
    # パスワード未設定
    # -----------------------------------------

    if not real_password:

        return jsonify({
            "ok": False
        })

    # -----------------------------------------
    # パスワード確認
    # -----------------------------------------

    if check_password_hash(
        real_password,
        password
    ):

        return jsonify({
            "ok": True
        })

    return jsonify({
        "ok": False
    })


# =========================================================
# 10桁ルームID生成
# =========================================================

def generate_room_id():

    while True:

        room_id = str(
            random.randint(
                1000000000,
                9999999999
            )
        )

        result = (
            supabase
            .table("rooms")
            .select("room_id")
            .eq("room_id", room_id)
            .execute()
        )

        if not result.data:

            rooms.setdefault(
                room_id,
                []
            )

            return room_id


# =========================================================
# ルーム作成
# =========================================================

@socketio.on("create_room")
def create_room():

    if "username" not in session:
        return

    username = session["username"]

    room_id = generate_room_id()

    # -----------------------------------------
    # Supabaseにルーム作成
    # -----------------------------------------

    supabase.table("rooms").insert(
        {
            "room_id": room_id,
            "password_enabled": False,
            "password": None,
            "password_changed_at": None
        }
    ).execute()

    # -----------------------------------------
    # メンバー登録
    # -----------------------------------------

    supabase.table("room_members").insert(
        {
            "room_id": room_id,
            "username": username,
            "note": ""
        }
    ).execute()

    # -----------------------------------------
    # メモリ
    # -----------------------------------------

    rooms[room_id] = [
        username
    ]

    join_room(room_id)

    emit(
        "room_created",
        {
            "room": room_id
        }
    )


# =========================================================
# ルーム参加
# =========================================================

@socketio.on("join_room_by_id")
def join_room_by_id(data):

    if "username" not in session:
        return

    room_id = str(
        data["room"]
    )

    username = session["username"]

    # -----------------------------------------
    # 10桁チェック
    # -----------------------------------------

    if (
        not room_id.isdigit()
        or len(room_id) != 10
    ):

        emit(
            "join_error",
            {
                "message":
                    "ルームIDは半角数字10桁です"
            }
        )

        return

    # -----------------------------------------
    # ルーム存在確認
    # -----------------------------------------

    room_result = (
        supabase
        .table("rooms")
        .select("room_id")
        .eq("room_id", room_id)
        .execute()
    )

    if not room_result.data:

        emit(
            "join_error",
            {
                "message":
                    "そのルームは存在しません"
            }
        )

        return

    # -----------------------------------------
    # メモリ
    # -----------------------------------------

    if room_id not in rooms:

        rooms[room_id] = []

    if username not in rooms[room_id]:

        rooms[room_id].append(
            username
        )

    join_room(room_id)

    # -----------------------------------------
    # 履歴登録
    # -----------------------------------------

    member_result = (
        supabase
        .table("room_members")
        .select("room_id")
        .eq("room_id", room_id)
        .eq("username", username)
        .execute()
    )

    if not member_result.data:

        supabase.table("room_members").insert(
            {
                "room_id": room_id,
                "username": username,
                "note": ""
            }
        ).execute()

    # -----------------------------------------
    # 参加通知
    # -----------------------------------------

    emit(
        "joined",
        {
            "room": room_id
        }
    )

    # -----------------------------------------
    # 過去メッセージ
    # -----------------------------------------

    message_result = (
        supabase
        .table("messages")
        .select(
            "username,message"
        )
        .eq("room_id", room_id)
        .order("id")
        .execute()
    )

    for row in message_result.data or []:

        emit(
            "chat_message",
            {
                "username":
                    row["username"],
                "message":
                    row["message"]
            }
        )


# =========================================================
# ルーム退出
# =========================================================

@socketio.on("leave_room")
def leave(data):

    room_id = data["room"]

    username = session.get(
        "username"
    )

    leave_room(room_id)

    if room_id in rooms:

        if username in rooms[room_id]:

            rooms[room_id].remove(
                username
            )

        if not rooms[room_id]:

            del rooms[room_id]


# =========================================================
# メッセージ
# =========================================================

@socketio.on("message")
def handle_message(data):

    if "username" not in session:
        return

    room = data["room"]
    message = data["message"]

    username = session["username"]

    if not message:
        return

    # -----------------------------------------
    # Supabase保存
    # -----------------------------------------

    supabase.table("messages").insert(
        {
            "room_id": room,
            "username": username,
            "message": message
        }
    ).execute()

    # -----------------------------------------
    # リアルタイム送信
    # -----------------------------------------

    emit(
        "chat_message",
        {
            "username":
                username,
            "message":
                message
        },
        room=room
    )


# =========================================================
# 通話開始通知
# =========================================================

@socketio.on("call_started")
def call_started(data):

    room = data["room"]

    username = session["username"]

    emit(
        "call_notification",
        {
            "username":
                username,
            "room":
                room
        },
        room=room
    )


# =========================================================
# 通話終了通知
# =========================================================

@socketio.on("call_ended")
def call_ended(data):

    room = data["room"]

    username = session["username"]

    emit(
        "call_end_notification",
        {
            "username":
                username
        },
        room=room
    )


# =========================================================
# CREATERログ投稿
# =========================================================

@socketio.on("add_creator_log")
def add_creator_log(data):

    username = session.get(
        "username"
    )

    # -----------------------------------------
    # 開発者限定
    # -----------------------------------------

    if username != "開発者":
        return

    message = data["message"]

    if not message:
        return

    # -----------------------------------------
    # Supabase保存
    # -----------------------------------------

    result = (
        supabase
        .table("creator_logs")
        .insert(
            {
                "message": message
            }
        )
        .execute()
    )

    if not result.data:
        return

    log_id = result.data[0]["id"]

    # -----------------------------------------
    # 全員へ通知
    # -----------------------------------------

    socketio.emit(
        "new_creator_log",
        {
            "id":
                log_id,
            "message":
                message
        }
    )


# =========================================================
# CREATERログ削除
# =========================================================

@socketio.on("delete_creator_log")
def delete_creator_log(data):

    username = session.get(
        "username"
    )

    if username != "開発者":
        return

    log_id = data["id"]

    (
        supabase
        .table("creator_logs")
        .delete()
        .eq("id", log_id)
        .execute()
    )

    socketio.emit(
        "creator_log_deleted",
        {
            "id": log_id
        }
    )


# =========================================================
# main
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    socketio.run(
        app,
        host="0.0.0.0",
        port=port
    )
