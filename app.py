from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    jsonify,
    url_for,
    flash,
)
from flask_socketio import (
    SocketIO,
    emit,
    join_room,
    leave_room,
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)

from supabase import create_client

import os
import random
from datetime import datetime, timezone


# =========================================================
# Flask
# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "FLASK_SECRET_KEY",
    "change-this-secret-key"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

if os.environ.get("RENDER") == "true":
    app.config["SESSION_COOKIE_SECURE"] = True


# =========================================================
# Socket.IO
# =========================================================

socketio = SocketIO(
    app,
    cors_allowed_origins="*"
)


# =========================================================
# Environment variables
# =========================================================

SUPABASE_URL = os.environ.get(
    "SUPABASE_URL"
)

SUPABASE_PUBLISHABLE_KEY = os.environ.get(
    "SUPABASE_PUBLISHABLE_KEY"
)

SUPABASE_SECRET_KEY = os.environ.get(
    "SUPABASE_SECRET_KEY"
)


if not SUPABASE_URL:
    raise RuntimeError(
        "SUPABASE_URL が設定されていません"
    )

if not SUPABASE_PUBLISHABLE_KEY:
    raise RuntimeError(
        "SUPABASE_PUBLISHABLE_KEY が設定されていません"
    )

if not SUPABASE_SECRET_KEY:
    raise RuntimeError(
        "SUPABASE_SECRET_KEY が設定されていません"
    )


# =========================================================
# Supabase clients
# =========================================================
#
# db
#   → Secret Key
#   → サーバー側DB操作専用
#
# auth_client
#   → Publishable Key
#   → Supabase Auth専用
#
# Secret Keyはブラウザへ絶対に出さない。
# =========================================================

db = create_client(
    SUPABASE_URL,
    SUPABASE_SECRET_KEY
)

auth_client = create_client(
    SUPABASE_URL,
    SUPABASE_PUBLISHABLE_KEY
)


# =========================================================
# SessionへSupabaseセッション保存
# =========================================================

def save_auth_session(auth_session):

    if not auth_session:
        return

    session["access_token"] = (
        auth_session.access_token
    )

    session["refresh_token"] = (
        auth_session.refresh_token
    )


# =========================================================
# 現在ログインしているSupabaseユーザー
# =========================================================

def get_current_user():

    access_token = session.get(
        "access_token"
    )

    if not access_token:
        return None

    try:

        response = (
            auth_client
            .auth
            .get_user(access_token)
        )

        return response.user

    except Exception as e:

        print(
            "get_current_user error:",
            repr(e)
        )

        return None


# =========================================================
# プロフィール取得
# =========================================================

def get_profile(user_id):

    result = (
        db
        .table("profiles")
        .select(
            "id,username,created_at"
        )
        .eq(
            "id",
            user_id
        )
        .execute()
    )

    if result.data:
        return result.data[0]

    return None


# =========================================================
# プロフィール作成
# =========================================================

def ensure_profile(user):

    user_id = str(
        user.id
    )

    # すでに存在
    profile = get_profile(
        user_id
    )

    if profile:
        return profile

    metadata = (
        user.user_metadata
        or {}
    )

    # GitHubの場合
    username = (
        metadata.get("user_name")
        or metadata.get("preferred_username")
        or metadata.get("name")
        or metadata.get("full_name")
    )

    # メールの場合
    if not username:

        if user.email:

            username = user.email.split("@")[0]

        else:

            username = "User"

    username = str(
        username
    ).strip()

    if not username:
        username = "User"

    username = username[:100]

    # -----------------------------------------------------
    # 同名チェック
    # -----------------------------------------------------

    existing = (
        db
        .table("profiles")
        .select("id")
        .eq(
            "username",
            username
        )
        .execute()
    )

    if existing.data:

        username = (
            username
            + "_"
            + user_id[:8]
        )

    # -----------------------------------------------------
    # 作成
    # -----------------------------------------------------

    result = (
        db
        .table("profiles")
        .insert(
            {
                "id": user_id,
                "username": username
            }
        )
        .execute()
    )

    if result.data:
        return result.data[0]

    return get_profile(
        user_id
    )


# =========================================================
# ログイン必須チェック
# =========================================================

def require_user():

    user = get_current_user()

    if not user:
        return None

    ensure_profile(
        user
    )

    return user


# =========================================================
# トップページ
# =========================================================

@app.route("/")
def index():

    user = get_current_user()

    if not user:

        message = request.args.get(
            "message"
        )

        error = request.args.get(
            "error"
        )

        return render_template(
            "auth.html",
            message=message,
            error=error
        )

    profile = ensure_profile(
        user
    )

    username = profile["username"]

    user_id = str(
        user.id
    )

    # =====================================================
    # ルーム履歴
    # =====================================================

    member_result = (
        db
        .table("room_members")
        .select(
            "room_id,note,joined_at"
        )
        .eq(
            "user_id",
            user_id
        )
        .order(
            "joined_at",
            desc=True
        )
        .execute()
    )

    room_history = []

    for member in (
        member_result.data or []
    ):

        room_uuid = str(
            member["room_id"]
        )

        room_result = (
            db
            .table("rooms")
            .select(
                "id,room_code"
            )
            .eq(
                "id",
                room_uuid
            )
            .execute()
        )

        if not room_result.data:
            continue

        room = room_result.data[0]

        settings_result = (
            db
            .table("room_settings")
            .select(
                "password_enabled"
            )
            .eq(
                "room_id",
                room_uuid
            )
            .execute()
        )

        locked = False

        if settings_result.data:

            locked = bool(
                settings_result
                .data[0]
                .get(
                    "password_enabled",
                    False
                )
            )

        room_history.append(
            (
                room["room_code"],
                member.get(
                    "note",
                    ""
                ),
                locked
            )
        )

    # =====================================================
    # CREATERログ
    # =====================================================

    creator_result = (
        db
        .table("creator_logs")
        .select(
            "id,message,created_at"
        )
        .order(
            "id",
            desc=True
        )
        .execute()
    )

    creator_logs = []

    for row in (
        creator_result.data or []
    ):

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
# メール＋パスワード 新規登録
# =========================================================

@app.route(
    "/register",
    methods=["POST"]
)
def register():

    email = str(
        request.form.get(
            "email",
            ""
        )
    ).strip()

    password = str(
        request.form.get(
            "password",
            ""
        )
    )

    username = str(
        request.form.get(
            "username",
            ""
        )
    ).strip()

    # usernameが空ならメールから作る
    if not username and email:

        username = email.split("@")[0]

    if not email:

        return redirect(
            "/?error=メールアドレスを入力してください"
        )

    if not password:

        return redirect(
            "/?error=パスワードを入力してください"
        )

    if len(password) < 6:

        return redirect(
            "/?error=パスワードは6文字以上にしてください"
        )

    try:

        response = (
            auth_client
            .auth
            .sign_up(
                {
                    "email": email,
                    "password": password,
                    "options": {
                        "data": {
                            "username":
                                username
                        }
                    }
                }
            )
        )

        user = response.user
        auth_session = response.session

        if not user:

            return redirect(
                "/?error=ユーザー登録に失敗しました"
            )

        # メール確認OFFの場合は
        # ここでsessionが取得できる
        if auth_session:

            save_auth_session(
                auth_session
            )

            ensure_profile(
                user
            )

            return redirect("/")

        # メール確認ONの場合
        return redirect(
            "/?message="
            "登録しました。メールを確認してからログインしてください"
        )

    except Exception as e:

        print(
            "Register error:",
            repr(e)
        )

        return redirect(
            "/?error="
            + str(e)
        )


# =========================================================
# メール＋パスワード ログイン
# =========================================================

@app.route(
    "/login",
    methods=["POST"]
)
def login():

    email = str(
        request.form.get(
            "email",
            ""
        )
    ).strip()

    password = str(
        request.form.get(
            "password",
            ""
        )
    )

    if not email:

        return redirect(
            "/?error=メールアドレスを入力してください"
        )

    if not password:

        return redirect(
            "/?error=パスワードを入力してください"
        )

    try:

        response = (
            auth_client
            .auth
            .sign_in_with_password(
                {
                    "email": email,
                    "password": password
                }
            )
        )

        auth_session = response.session
        user = response.user

        if not auth_session or not user:

            return redirect(
                "/?error=ログインに失敗しました"
            )

        save_auth_session(
            auth_session
        )

        # profiles自動作成
        ensure_profile(
            user
        )

        return redirect("/")

    except Exception as e:

        print(
            "Login error:",
            repr(e)
        )

        return redirect(
            "/?error="
            + str(e)
        )


# =========================================================
# GitHubログイン開始
# =========================================================

@app.route(
    "/auth/github"
)
def github_login():

    try:

        redirect_url = url_for(
            "github_callback",
            _external=True
        )

        response = (
            auth_client
            .auth
            .sign_in_with_oauth(
                {
                    "provider": "github",
                    "options": {
                        "redirect_to":
                            redirect_url
                    }
                }
            )
        )

        return redirect(
            response.url
        )

    except Exception as e:

        print(
            "GitHub login error:",
            repr(e)
        )

        return redirect(
            "/?error="
            + str(e)
        )


# =========================================================
# GitHub OAuth callback
# =========================================================

@app.route(
    "/auth/callback"
)
def github_callback():

    error = request.args.get(
        "error"
    )

    if error:

        description = request.args.get(
            "error_description",
            error
        )

        return redirect(
            "/?error="
            + description
        )

    code = request.args.get(
        "code"
    )

    if not code:

        return redirect(
            "/?error=認証コードがありません"
        )

    try:

        # -------------------------------------------------
        # PKCE code → session
        # -------------------------------------------------

        response = (
            auth_client
            .auth
            .exchange_code_for_session(
                {
                    "auth_code": code
                }
            )
        )

        auth_session = response.session
        user = response.user

        if not auth_session:

            return redirect(
                "/?error="
                "Supabase Authセッションを取得できませんでした"
            )

        if not user:

            return redirect(
                "/?error="
                "GitHubユーザー情報を取得できませんでした"
            )

        # -------------------------------------------------
        # Flask session
        # -------------------------------------------------

        save_auth_session(
            auth_session
        )

        # -------------------------------------------------
        # profiles自動作成
        # -------------------------------------------------

        ensure_profile(
            user
        )

        return redirect("/")

    except Exception as e:

        print(
            "GitHub callback error:",
            repr(e)
        )

        return redirect(
            "/?error="
            + str(e)
        )


# =========================================================
# ログアウト
# =========================================================

@app.route(
    "/logout"
)
def logout():

    # Supabase側の共有clientをsign_outしない。
    # ここではブラウザ側のFlask sessionだけ消す。

    session.clear()

    return redirect("/")


# =========================================================
# 通話ページ
# =========================================================

@app.route(
    "/call/<room_code>"
)
def call(room_code):

    user = require_user()

    if not user:

        return redirect("/")

    return render_template(
        "call.html",
        room_id=room_code
    )


# =========================================================
# ルームコードからroom UUID取得
# =========================================================

def get_room_by_code(room_code):

    result = (
        db
        .table("rooms")
        .select(
            "id,room_code,created_by,created_at"
        )
        .eq(
            "room_code",
            room_code
        )
        .execute()
    )

    if not result.data:
        return None

    return result.data[0]


# =========================================================
# ルームコード生成
# =========================================================

def generate_room_code():

    while True:

        room_code = str(
            random.randint(
                1000000000,
                9999999999
            )
        )

        result = (
            db
            .table("rooms")
            .select("id")
            .eq(
                "room_code",
                room_code
            )
            .execute()
        )

        if not result.data:

            return room_code


# =========================================================
# メモ保存
# =========================================================

@app.route(
    "/save_note",
    methods=["POST"]
)
def save_note():

    user = require_user()

    if not user:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ログインしてください"
            }
        ), 401

    data = (
        request.get_json()
        or {}
    )

    room_code = str(
        data.get(
            "room",
            ""
        )
    )

    note = str(
        data.get(
            "note",
            ""
        )
    )

    room = get_room_by_code(
        room_code
    )

    if not room:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ルームが存在しません"
            }
        ), 404

    (
        db
        .table("room_members")
        .update(
            {
                "note": note
            }
        )
        .eq(
            "room_id",
            room["id"]
        )
        .eq(
            "user_id",
            str(user.id)
        )
        .execute()
    )

    return jsonify(
        {
            "status": "ok"
        }
    )


# =========================================================
# 履歴削除
# =========================================================

@app.route(
    "/delete_room",
    methods=["POST"]
)
def delete_room():

    user = require_user()

    if not user:

        return jsonify(
            {
                "status": "error"
            }
        ), 401

    data = (
        request.get_json()
        or {}
    )

    room_code = str(
        data.get(
            "room",
            ""
        )
    )

    room = get_room_by_code(
        room_code
    )

    if not room:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ルームが存在しません"
            }
        ), 404

    (
        db
        .table("room_members")
        .delete()
        .eq(
            "room_id",
            room["id"]
        )
        .eq(
            "user_id",
            str(user.id)
        )
        .execute()
    )

    return jsonify(
        {
            "status": "ok"
        }
    )


# =========================================================
# ルームパスワード設定
# =========================================================

@app.route(
    "/set_room_password",
    methods=["POST"]
)
def set_room_password():

    user = require_user()

    if not user:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ログインしてください"
            }
        ), 401

    data = (
        request.get_json()
        or {}
    )

    room_code = str(
        data.get(
            "room",
            ""
        )
    )

    enabled = bool(
        data.get(
            "enabled",
            False
        )
    )

    new_password = str(
        data.get(
            "password",
            ""
        )
    )

    room = get_room_by_code(
        room_code
    )

    if not room:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ルームが存在しません"
            }
        ), 404

    room_uuid = str(
        room["id"]
    )

    settings_result = (
        db
        .table("room_settings")
        .select(
            "password_enabled,"
            "password_hash,"
            "password_changed_at"
        )
        .eq(
            "room_id",
            room_uuid
        )
        .execute()
    )

    if settings_result.data:

        settings = settings_result.data[0]

    else:

        settings = {
            "password_enabled": False,
            "password_hash": None,
            "password_changed_at": None
        }

    old_password_hash = settings.get(
        "password_hash"
    )

    # =====================================================
    # OFF
    # =====================================================

    if not enabled:

        db.table(
            "room_settings"
        ).update(
            {
                "password_enabled": False,
                "updated_at":
                    datetime.now(
                        timezone.utc
                    ).isoformat()
            }
        ).eq(
            "room_id",
            room_uuid
        ).execute()

        return jsonify(
            {
                "status": "ok",
                "password_changed": False
            }
        )

    # =====================================================
    # 既存パスワードを再利用してON
    # =====================================================

    if old_password_hash:

        db.table(
            "room_settings"
        ).update(
            {
                "password_enabled": True,
                "updated_at":
                    datetime.now(
                        timezone.utc
                    ).isoformat()
            }
        ).eq(
            "room_id",
            room_uuid
        ).execute()

        return jsonify(
            {
                "status": "ok",
                "password_changed": False
            }
        )

    # =====================================================
    # 初回設定
    # =====================================================

    if not new_password:

        return jsonify(
            {
                "status": "error",
                "message":
                    "初回はパスワードを入力してください"
            }
        ), 400

    now = datetime.now(
        timezone.utc
    )

    db.table(
        "room_settings"
    ).update(
        {
            "password_enabled": True,
            "password_hash":
                generate_password_hash(
                    new_password
                ),
            "password_changed_at":
                now.isoformat(),
            "updated_at":
                now.isoformat()
        }
    ).eq(
        "room_id",
        room_uuid
    ).execute()

    return jsonify(
        {
            "status": "ok",
            "password_changed": True
        }
    )


# =========================================================
# パスワード変更
# =========================================================

@app.route(
    "/change_room_password",
    methods=["POST"]
)
def change_room_password():

    user = require_user()

    if not user:

        return jsonify(
            {
                "status": "error"
            }
        ), 401

    data = (
        request.get_json()
        or {}
    )

    room_code = str(
        data.get(
            "room",
            ""
        )
    )

    new_password = str(
        data.get(
            "password",
            ""
        )
    )

    if not new_password:

        return jsonify(
            {
                "status": "error",
                "message":
                    "パスワードを入力してください"
            }
        ), 400

    room = get_room_by_code(
        room_code
    )

    if not room:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ルームが存在しません"
            }
        ), 404

    room_uuid = str(
        room["id"]
    )

    result = (
        db
        .table("room_settings")
        .select(
            "password_changed_at"
        )
        .eq(
            "room_id",
            room_uuid
        )
        .execute()
    )

    if not result.data:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ルーム設定がありません"
            }
        ), 404

    changed_at = result.data[0].get(
        "password_changed_at"
    )

    if changed_at:

        try:

            old_time = datetime.fromisoformat(
                changed_at.replace(
                    "Z",
                    "+00:00"
                )
            )

            now = datetime.now(
                timezone.utc
            )

            elapsed = (
                now - old_time
            ).total_seconds()

            if elapsed < 7200:

                remaining = int(
                    7200 - elapsed
                )

                minutes = (
                    remaining // 60
                )

                return jsonify(
                    {
                        "status": "error",
                        "message":
                            "パスワード変更は"
                            f"あと約{minutes}分後です"
                    }
                ), 429

        except Exception:
            pass

    now = datetime.now(
        timezone.utc
    )

    db.table(
        "room_settings"
    ).update(
        {
            "password_hash":
                generate_password_hash(
                    new_password
                ),
            "password_changed_at":
                now.isoformat(),
            "updated_at":
                now.isoformat()
        }
    ).eq(
        "room_id",
        room_uuid
    ).execute()

    return jsonify(
        {
            "status": "ok",
            "message":
                "パスワードを変更しました"
        }
    )


# =========================================================
# 参加前パスワード確認
# =========================================================

@app.route(
    "/check_room_password",
    methods=["POST"]
)
def check_room_password():

    user = require_user()

    if not user:

        return jsonify(
            {
                "ok": False
            }
        ), 401

    data = (
        request.get_json()
        or {}
    )

    room_code = str(
        data.get(
            "room",
            ""
        )
    )

    password = str(
        data.get(
            "password",
            ""
        )
    )

    room = get_room_by_code(
        room_code
    )

    if not room:

        return jsonify(
            {
                "ok": False
            }
        )

    room_uuid = str(
        room["id"]
    )

    user_id = str(
        user.id
    )

    member_result = (
        db
        .table("room_members")
        .select("id")
        .eq(
            "room_id",
            room_uuid
        )
        .eq(
            "user_id",
            user_id
        )
        .execute()
    )

    if member_result.data:

        return jsonify(
            {
                "ok": True
            }
        )

    settings_result = (
        db
        .table("room_settings")
        .select(
            "password_enabled,"
            "password_hash"
        )
        .eq(
            "room_id",
            room_uuid
        )
        .execute()
    )

    if not settings_result.data:

        return jsonify(
            {
                "ok": True
            }
        )

    settings = settings_result.data[0]

    enabled = bool(
        settings.get(
            "password_enabled",
            False
        )
    )

    password_hash = settings.get(
        "password_hash"
    )

    if not enabled:

        return jsonify(
            {
                "ok": True
            }
        )

    if not password_hash:

        return jsonify(
            {
                "ok": False
            }
        )

    if check_password_hash(
        password_hash,
        password
    ):

        return jsonify(
            {
                "ok": True
            }
        )

    return jsonify(
        {
            "ok": False
        }
    )


# =========================================================
# ルーム作成
# =========================================================

@socketio.on(
    "create_room"
)
def create_room():

    user = require_user()

    if not user:
        return

    user_id = str(
        user.id
    )

    room_code = generate_room_code()

    # =====================================================
    # rooms
    # =====================================================

    result = (
        db
        .table("rooms")
        .insert(
            {
                "room_code": room_code,
                "created_by": user_id
            }
        )
        .execute()
    )

    if not result.data:

        emit(
            "join_error",
            {
                "message":
                    "ルーム作成に失敗しました"
            }
        )

        return

    room = result.data[0]

    room_uuid = str(
        room["id"]
    )

    now = datetime.now(
        timezone.utc
    ).isoformat()

    # =====================================================
    # room_settings
    # =====================================================

    db.table(
        "room_settings"
    ).insert(
        {
            "room_id": room_uuid,
            "password_enabled": False,
            "password_hash": None,
            "password_changed_at": None,
            "updated_at": now
        }
    ).execute()

    # =====================================================
    # room_members
    # =====================================================

    db.table(
        "room_members"
    ).insert(
        {
            "room_id": room_uuid,
            "user_id": user_id,
            "note": ""
        }
    ).execute()

    join_room(
        room_code
    )

    emit(
        "room_created",
        {
            "room": room_code
        }
    )


# =========================================================
# ルーム参加
# =========================================================

@socketio.on(
    "join_room_by_id"
)
def join_room_by_id(data):

    user = require_user()

    if not user:
        return

    room_code = str(
        data.get(
            "room",
            ""
        )
    )

    user_id = str(
        user.id
    )

    if (
        not room_code.isdigit()
        or len(room_code) != 10
    ):

        emit(
            "join_error",
            {
                "message":
                    "ルームIDは半角数字10桁です"
            }
        )

        return

    room = get_room_by_code(
        room_code
    )

    if not room:

        emit(
            "join_error",
            {
                "message":
                    "そのルームは存在しません"
            }
        )

        return

    room_uuid = str(
        room["id"]
    )

    member_result = (
        db
        .table("room_members")
        .select("id")
        .eq(
            "room_id",
            room_uuid
        )
        .eq(
            "user_id",
            user_id
        )
        .execute()
    )

    if not member_result.data:

        db.table(
            "room_members"
        ).insert(
            {
                "room_id": room_uuid,
                "user_id": user_id,
                "note": ""
            }
        ).execute()

    join_room(
        room_code
    )

    emit(
        "joined",
        {
            "room": room_code
        }
    )

    # =====================================================
    # 過去メッセージ
    # =====================================================

    message_result = (
        db
        .table("messages")
        .select(
            "user_id,message,created_at"
        )
        .eq(
            "room_id",
            room_uuid
        )
        .order(
            "id"
        )
        .execute()
    )

    for row in (
        message_result.data or []
    ):

        message_user_id = str(
            row["user_id"]
        )

        profile = get_profile(
            message_user_id
        )

        message_username = (
            profile["username"]
            if profile
            else "Unknown"
        )

        emit(
            "chat_message",
            {
                "username":
                    message_username,
                "message":
                    row["message"]
            }
        )


# =========================================================
# ルーム退出
# =========================================================

@socketio.on(
    "leave_room"
)
def leave(data):

    room_code = str(
        data.get(
            "room",
            ""
        )
    )

    leave_room(
        room_code
    )


# =========================================================
# メッセージ
# =========================================================

@socketio.on(
    "message"
)
def handle_message(data):

    user = require_user()

    if not user:
        return

    room_code = str(
        data.get(
            "room",
            ""
        )
    )

    message = str(
        data.get(
            "message",
            ""
        )
    ).strip()

    if not message:
        return

    room = get_room_by_code(
        room_code
    )

    if not room:
        return

    room_uuid = str(
        room["id"]
    )

    user_id = str(
        user.id
    )

    member_result = (
        db
        .table("room_members")
        .select("id")
        .eq(
            "room_id",
            room_uuid
        )
        .eq(
            "user_id",
            user_id
        )
        .execute()
    )

    if not member_result.data:
        return

    db.table(
        "messages"
    ).insert(
        {
            "room_id": room_uuid,
            "user_id": user_id,
            "message": message
        }
    ).execute()

    profile = ensure_profile(
        user
    )

    emit(
        "chat_message",
        {
            "username":
                profile["username"],
            "message":
                message
        },
        room=room_code
    )


# =========================================================
# 通話開始通知
# =========================================================

@socketio.on(
    "call_started"
)
def call_started(data):

    user = require_user()

    if not user:
        return

    room = str(
        data.get(
            "room",
            ""
        )
    )

    profile = ensure_profile(
        user
    )

    socketio.emit(
        "call_notification",
        {
            "username":
                profile["username"],
            "room":
                room
        },
        room=room
    )


# =========================================================
# 通話終了通知
# =========================================================

@socketio.on(
    "call_ended"
)
def call_ended(data):

    user = require_user()

    if not user:
        return

    room = str(
        data.get(
            "room",
            ""
        )
    )

    profile = ensure_profile(
        user
    )

    socketio.emit(
        "call_end_notification",
        {
            "username":
                profile["username"]
        },
        room=room
    )


# =========================================================
# CREATERログ投稿
# =========================================================

@socketio.on(
    "add_creator_log"
)
def add_creator_log(data):

    user = require_user()

    if not user:
        return

    profile = ensure_profile(
        user
    )

    if profile["username"] != "開発者":
        return

    message = str(
        data.get(
            "message",
            ""
        )
    ).strip()

    if not message:
        return

    result = (
        db
        .table("creator_logs")
        .insert(
            {
                "user_id":
                    str(user.id),
                "message":
                    message
            }
        )
        .execute()
    )

    if not result.data:
        return

    log = result.data[0]

    socketio.emit(
        "new_creator_log",
        {
            "id":
                log["id"],
            "message":
                message
        }
    )


# =========================================================
# CREATERログ削除
# =========================================================

@socketio.on(
    "delete_creator_log"
)
def delete_creator_log(data):

    user = require_user()

    if not user:
        return

    profile = ensure_profile(
        user
    )

    if profile["username"] != "開発者":
        return

    try:

        log_id = int(
            data.get(
                "id"
            )
        )

    except Exception:

        return

    (
        db
        .table("creator_logs")
        .delete()
        .eq(
            "id",
            log_id
        )
        .execute()
    )

    socketio.emit(
        "creator_log_deleted",
        {
            "id":
                log_id
        }
    )


# =========================================================
# Health Check
# =========================================================

@app.route(
    "/health"
)
def health():

    return jsonify(
        {
            "status": "ok"
        }
    )


# =========================================================
# Main
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
