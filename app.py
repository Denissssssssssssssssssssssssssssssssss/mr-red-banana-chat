from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    jsonify,
    url_for,
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
import uuid
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

app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("RENDER", "").lower() == "true"
)


# =========================================================
# Socket.IO
# =========================================================

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
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

if not SUPABASE_SECRET_KEY:
    raise RuntimeError(
        "SUPABASE_SECRET_KEY が設定されていません"
    )


# =========================================================
# Supabase DB
#
# 今回はSupabaseを「DB」として使用します。
#
# メールアドレスなしでも登録できるように、
# ユーザー認証そのものはFlask Sessionで管理します。
#
# パスワードは絶対に平文保存せず、
# generate_password_hash()でハッシュ化します。
# =========================================================

db = create_client(
    SUPABASE_URL,
    SUPABASE_SECRET_KEY
)


# =========================================================
# Utility
# =========================================================

def now_iso():
    return datetime.now(
        timezone.utc
    ).isoformat()


# =========================================================
# 現在ログインしているユーザー
# =========================================================

def get_current_user():

    user_id = session.get(
        "user_id"
    )

    if not user_id:
        return None

    try:

        result = (
            db
            .table("profiles")
            .select(
                """
                id,
                username,
                password_hash,
                email,
                tutorial_completed,
                terms_accepted,
                created_at
                """
            )
            .eq(
                "id",
                user_id
            )
            .limit(1)
            .execute()
        )

        if not result.data:
            session.clear()
            return None

        return result.data[0]

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

    try:

        result = (
            db
            .table("profiles")
            .select(
                """
                id,
                username,
                password_hash,
                email,
                tutorial_completed,
                terms_accepted,
                created_at
                """
            )
            .eq(
                "id",
                str(user_id)
            )
            .limit(1)
            .execute()
        )

        if result.data:
            return result.data[0]

        return None

    except Exception as e:

        print(
            "get_profile error:",
            repr(e)
        )

        return None


# =========================================================
# ログイン必須
# =========================================================

def require_user():

    user = get_current_user()

    if not user:
        return None

    return user


# =========================================================
# 認証後の移動先
# =========================================================

def redirect_after_auth(
    user,
    newly_created=False
):

    profile = get_profile(
        user["id"]
    )

    if not profile:
        return redirect("/")

    if newly_created:

        session["new_registration"] = True

        return redirect(
            url_for("security")
        )

    if not profile.get(
        "terms_accepted",
        False
    ):

        return redirect(
            url_for("terms")
        )

    if not profile.get(
        "tutorial_completed",
        False
    ):

        return redirect(
            url_for("tutorial")
        )

    return redirect("/")


# =========================================================
# トップページ
# =========================================================

@app.route("/")
def index():

    user = get_current_user()

    if not user:

        return render_template(
            "auth.html"
        )

    if not user.get(
        "terms_accepted",
        False
    ):

        return redirect(
            url_for("terms")
        )

    if not user.get(
        "tutorial_completed",
        False
    ):

        return redirect(
            url_for("tutorial")
        )

    username = user["username"]
    user_id = str(user["id"])

    # =====================================================
    # ルーム履歴
    # =====================================================

    room_history = []

    try:

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
                .limit(1)
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
                .limit(1)
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

    except Exception as e:

        print(
            "room history error:",
            repr(e)
        )


    # =====================================================
    # CREATERログ
    # =====================================================

    creator_logs = []

    try:

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

        for row in (
            creator_result.data or []
        ):

            creator_logs.append(
                (
                    row["id"],
                    row["message"]
                )
            )

    except Exception as e:

        print(
            "creator logs error:",
            repr(e)
        )


    return render_template(
        "index.html",
        username=username,
        room_history=room_history,
        creator_logs=creator_logs
    )


# =========================================================
# 新規登録
#
# メールアドレスは不要。
#
# username + password
#       ↓
# profiles
#       ↓
# security
#       ↓
# terms
#       ↓
# tutorial
# =========================================================

@app.route(
    "/register",
    methods=["POST"]
)
def register():

    username = str(
        request.form.get(
            "username",
            ""
        )
    ).strip()

    password = str(
        request.form.get(
            "password",
            ""
        )
    )

    # -----------------------------------------------------
    # 入力チェック
    # -----------------------------------------------------

    if not username:

        return (
            "ユーザーネームを入力してください"
        ), 400

    if not password:

        return (
            "パスワードを入力してください"
        ), 400

    if len(username) > 100:

        return (
            "ユーザーネームは100文字以内にしてください"
        ), 400

    if len(password) < 6:

        return (
            "パスワードは6文字以上にしてください"
        ), 400


    try:

        # -------------------------------------------------
        # 同じユーザーネームが存在するか確認
        # -------------------------------------------------

        existing = (
            db
            .table("profiles")
            .select("id")
            .eq(
                "username",
                username
            )
            .limit(1)
            .execute()
        )

        if existing.data:

            return (
                "そのユーザーネームは既に使用されています"
            ), 409


        # -------------------------------------------------
        # 新しいユーザーID
        # -------------------------------------------------

        user_id = str(
            uuid.uuid4()
        )


        # -------------------------------------------------
        # パスワードをハッシュ化
        #
        # 平文パスワードはDBに保存しません。
        # -------------------------------------------------

        password_hash = (
            generate_password_hash(
                password
            )
        )


        # -------------------------------------------------
        # profiles作成
        # -------------------------------------------------

        result = (
            db
            .table("profiles")
            .insert(
                {
                    "id": user_id,
                    "username": username,
                    "password_hash":
                        password_hash,
                    "email": None,
                    "tutorial_completed":
                        False,
                    "terms_accepted":
                        False,
                    "created_at":
                        now_iso()
                }
            )
            .execute()
        )


        if not result.data:

            return (
                "ユーザーを作成できませんでした"
            ), 500


        # -------------------------------------------------
        # Flask Session
        # -------------------------------------------------

        session.clear()

        session["user_id"] = user_id

        session["new_registration"] = True

        session.modified = True


        print(
            "register success:",
            user_id,
            username
        )


        # -------------------------------------------------
        # セキュリティ補強ページへ
        # -------------------------------------------------

        return redirect(
            url_for("security")
        )


    except Exception as e:

        print(
            "register error:",
            repr(e)
        )

        return (
            "新規登録に失敗しました: "
            + str(e)
        ), 400


# =========================================================
# ログイン
#
# メールアドレスではなく
# ユーザーネーム + パスワード
# =========================================================

@app.route(
    "/login",
    methods=["POST"]
)
def login():

    username = str(
        request.form.get(
            "username",
            ""
        )
    ).strip()

    password = str(
        request.form.get(
            "password",
            ""
        )
    )


    if not username or not password:

        return (
            "ユーザーネームとパスワードを入力してください"
        ), 400


    try:

        result = (
            db
            .table("profiles")
            .select(
                """
                id,
                username,
                password_hash,
                email,
                tutorial_completed,
                terms_accepted,
                created_at
                """
            )
            .eq(
                "username",
                username
            )
            .limit(1)
            .execute()
        )


        if not result.data:

            return (
                "ログインに失敗しました"
            ), 401


        user = result.data[0]


        # -------------------------------------------------
        # パスワード確認
        # -------------------------------------------------

        password_hash = user.get(
            "password_hash"
        )

        if not password_hash:

            return (
                "ログインに失敗しました"
            ), 401


        if not check_password_hash(
            password_hash,
            password
        ):

            return (
                "ログインに失敗しました"
            ), 401


        # -------------------------------------------------
        # Flask Session
        # -------------------------------------------------

        session.clear()

        session["user_id"] = str(
            user["id"]
        )

        session.modified = True


        print(
            "login success:",
            user["id"],
            user["username"]
        )


        # -------------------------------------------------
        # 利用規約・チュートリアル確認
        # -------------------------------------------------

        if not user.get(
            "terms_accepted",
            False
        ):

            return redirect(
                url_for("terms")
            )


        if not user.get(
            "tutorial_completed",
            False
        ):

            return redirect(
                url_for("tutorial")
            )


        return redirect("/")


    except Exception as e:

        print(
            "login error:",
            repr(e)
        )

        return (
            "ログインに失敗しました"
        ), 401


# =========================================================
# セキュリティ補強ページ
# =========================================================

@app.route(
    "/security"
)
def security():

    user = require_user()

    if not user:

        return redirect("/")


    return render_template(
        "security.html",
        username=user["username"],
        email=user.get("email")
    )


# =========================================================
# メールアドレス追加
#
# 今回は「任意」。
#
# Supabase Authではなく、
# profiles.emailへ保存するだけの基本版。
#
# 将来的にメール確認機能を追加可能。
# =========================================================

@app.route(
    "/add_email",
    methods=["POST"]
)
def add_email():

    user = require_user()

    if not user:

        return redirect("/")


    email = str(
        request.form.get(
            "email",
            ""
        )
    ).strip()


    if not email:

        return (
            "メールアドレスを入力してください"
        ), 400


    if "@" not in email:

        return (
            "正しいメールアドレスを入力してください"
        ), 400


    try:

        (
            db
            .table("profiles")
            .update(
                {
                    "email": email
                }
            )
            .eq(
                "id",
                str(user["id"])
            )
            .execute()
        )


        session["email_added"] = True

        return redirect(
            url_for("terms")
        )


    except Exception as e:

        print(
            "add_email error:",
            repr(e)
        )

        return (
            "メールアドレスの保存に失敗しました"
        ), 500


# =========================================================
# セキュリティページからスキップ
# =========================================================

@app.route(
    "/skip_security",
    methods=["POST"]
)
def skip_security():

    user = require_user()

    if not user:

        return redirect("/")


    session["security_skipped"] = True

    return redirect(
        url_for("terms")
    )


# =========================================================
# OAuth
#
# Google / GitHub / Microsoft
#
# 今回の基本登録ではメール不要。
# OAuth連携は後から本格実装できます。
# =========================================================

@app.route(
    "/auth/<provider>"
)
def oauth_login(provider):

    allowed_providers = {
        "google",
        "github",
        "azure"
    }


    if provider not in allowed_providers:

        return (
            "対応していないログイン方法です"
        ), 400


    return (
        "OAuthログインは現在準備中です"
    ), 501


# =========================================================
# 契約画面
# =========================================================

@app.route(
    "/terms"
)
def terms():

    user = require_user()

    if not user:

        return redirect("/")


    if user.get(
        "terms_accepted",
        False
    ):

        if not user.get(
            "tutorial_completed",
            False
        ):

            return redirect(
                url_for("tutorial")
            )

        return redirect("/")


    return render_template(
        "terms.html"
    )


# =========================================================
# 契約同意
# =========================================================

@app.route(
    "/accept_terms",
    methods=["POST"]
)
def accept_terms():

    user = require_user()

    if not user:

        return redirect("/")


    (
        db
        .table("profiles")
        .update(
            {
                "terms_accepted": True
            }
        )
        .eq(
            "id",
            str(user["id"])
        )
        .execute()
    )


    session.pop(
        "new_registration",
        None
    )

    session["terms_accepted"] = True


    return redirect(
        url_for("tutorial")
    )


# =========================================================
# チュートリアル
# =========================================================

@app.route(
    "/tutorial"
)
def tutorial():

    user = require_user()

    if not user:

        return redirect("/")


    if not user.get(
        "terms_accepted",
        False
    ):

        return redirect(
            url_for("terms")
        )


    if user.get(
        "tutorial_completed",
        False
    ):

        return redirect("/")


    return render_template(
        "tutorial.html"
    )


# =========================================================
# チュートリアル完了
# =========================================================

@app.route(
    "/complete_tutorial",
    methods=["POST"]
)
def complete_tutorial():

    user = require_user()

    if not user:

        return redirect("/")


    if not user.get(
        "terms_accepted",
        False
    ):

        return redirect(
            url_for("terms")
        )


    (
        db
        .table("profiles")
        .update(
            {
                "tutorial_completed": True
            }
        )
        .eq(
            "id",
            str(user["id"])
        )
        .execute()
    )


    return redirect("/")


# =========================================================
# ログアウト
# =========================================================

@app.route(
    "/logout"
)
def logout():

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
# room_code → UUID
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
        .limit(1)
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
            .limit(1)
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


    data = request.get_json() or {}


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
            str(user["id"])
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


    data = request.get_json() or {}


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
            str(user["id"])
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


    data = request.get_json() or {}


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
        .limit(1)
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


    old_password_hash = (
        settings.get(
            "password_hash"
        )
    )


    # -----------------------------------------------------
    # OFF
    # -----------------------------------------------------

    if not enabled:

        (
            db
            .table("room_settings")
            .update(
                {
                    "password_enabled":
                        False,
                    "updated_at":
                        now_iso()
                }
            )
            .eq(
                "room_id",
                room_uuid
            )
            .execute()
        )


        return jsonify(
            {
                "status": "ok",
                "password_changed":
                    False
            }
        )


    # -----------------------------------------------------
    # 既存パスワード
    # -----------------------------------------------------

    if old_password_hash:

        (
            db
            .table("room_settings")
            .update(
                {
                    "password_enabled":
                        True,
                    "updated_at":
                        now_iso()
                }
            )
            .eq(
                "room_id",
                room_uuid
            )
            .execute()
        )


        return jsonify(
            {
                "status": "ok",
                "password_changed":
                    False
            }
        )


    # -----------------------------------------------------
    # 初回設定
    # -----------------------------------------------------

    if not new_password:

        return jsonify(
            {
                "status": "error",
                "message":
                    "初回はパスワードを入力してください"
            }
        ), 400


    now = now_iso()


    (
        db
        .table("room_settings")
        .update(
            {
                "password_enabled":
                    True,
                "password_hash":
                    generate_password_hash(
                        new_password
                    ),
                "password_changed_at":
                    now,
                "updated_at":
                    now
            }
        )
        .eq(
            "room_id",
            room_uuid
        )
        .execute()
    )


    return jsonify(
        {
            "status": "ok",
            "password_changed":
                True
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


    data = request.get_json() or {}


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
        .limit(1)
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


    changed_at = (
        result.data[0]
        .get(
            "password_changed_at"
        )
    )


    if changed_at:

        try:

            old_time = (
                datetime.fromisoformat(
                    changed_at.replace(
                        "Z",
                        "+00:00"
                    )
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


    now = now_iso()


    (
        db
        .table("room_settings")
        .update(
            {
                "password_hash":
                    generate_password_hash(
                        new_password
                    ),
                "password_changed_at":
                    now,
                "updated_at":
                    now
            }
        )
        .eq(
            "room_id",
            room_uuid
        )
        .execute()
    )


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


    data = request.get_json() or {}


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
        user["id"]
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
        .limit(1)
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
        .limit(1)
        .execute()
    )


    if not settings_result.data:

        return jsonify(
            {
                "ok": True
            }
        )


    settings = (
        settings_result.data[0]
    )


    enabled = bool(
        settings.get(
            "password_enabled",
            False
        )
    )


    password_hash = (
        settings.get(
            "password_hash"
        )
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
        user["id"]
    )


    room_code = (
        generate_room_code()
    )


    result = (
        db
        .table("rooms")
        .insert(
            {
                "room_code":
                    room_code,
                "created_by":
                    user_id
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


    db.table(
        "room_settings"
    ).insert(
        {
            "room_id":
                room_uuid,
            "password_enabled":
                False,
            "password_hash":
                None,
            "password_changed_at":
                None
        }
    ).execute()


    db.table(
        "room_members"
    ).insert(
        {
            "room_id":
                room_uuid,
            "user_id":
                user_id,
            "note":
                ""
        }
    ).execute()


    join_room(
        room_code
    )


    emit(
        "room_created",
        {
            "room":
                room_code
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
        user["id"]
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
        .limit(1)
        .execute()
    )


    if not member_result.data:

        db.table(
            "room_members"
        ).insert(
            {
                "room_id":
                    room_uuid,
                "user_id":
                    user_id,
                "note":
                    ""
            }
        ).execute()


    join_room(
        room_code
    )


    emit(
        "joined",
        {
            "room":
                room_code
        }
    )


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
        user["id"]
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
        .limit(1)
        .execute()
    )


    if not member_result.data:
        return


    db.table(
        "messages"
    ).insert(
        {
            "room_id":
                room_uuid,
            "user_id":
                user_id,
            "message":
                message
        }
    ).execute()


    emit(
        "chat_message",
        {
            "username":
                user["username"],
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


    socketio.emit(
        "call_notification",
        {
            "username":
                user["username"],
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


    socketio.emit(
        "call_end_notification",
        {
            "username":
                user["username"]
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


    if user["username"] != "開発者":
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
                    str(user["id"]),
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


    if user["username"] != "開発者":
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
            "status":
                "ok"
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
