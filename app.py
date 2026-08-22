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
import smtplib

from datetime import datetime, timezone

from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


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
# Supabase DB client
#
# Supabase Authは使用しません。
# Secret Keyはサーバー側だけで使用します。
# =========================================================

db = create_client(
    SUPABASE_URL,
    SUPABASE_SECRET_KEY
)


# =========================================================
# Password reset token
# =========================================================

password_reset_serializer = URLSafeTimedSerializer(
    app.config["SECRET_KEY"]
)


PASSWORD_RESET_MAX_AGE = 3600


# =========================================================
# SMTP settings
#
# パスワード再設定メール用。
#
# Renderの環境変数に設定します。
#
# SMTP_HOST
# SMTP_PORT
# SMTP_USERNAME
# SMTP_PASSWORD
# SMTP_FROM
# =========================================================

SMTP_HOST = os.environ.get(
    "SMTP_HOST"
)

SMTP_PORT = int(
    os.environ.get(
        "SMTP_PORT",
        "587"
    )
)

SMTP_USERNAME = os.environ.get(
    "SMTP_USERNAME"
)

SMTP_PASSWORD = os.environ.get(
    "SMTP_PASSWORD"
)

SMTP_FROM = os.environ.get(
    "SMTP_FROM",
    SMTP_USERNAME or ""
)


# =========================================================
# 現在ログインしているユーザーID
# =========================================================

def get_current_user_id():

    user_id = session.get(
        "user_id"
    )

    if not user_id:
        return None

    return str(user_id)


# =========================================================
# 現在のプロフィール取得
# =========================================================

def get_current_profile():

    user_id = get_current_user_id()

    if not user_id:
        return None

    return get_profile(
        user_id
    )


# =========================================================
# プロフィール取得
# =========================================================

def get_profile(user_id):

    result = (
        db
        .table("profiles")
        .select(
            "id,username,created_at,"
            "tutorial_completed,email,password_hash"
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


# =========================================================
# ユーザーネームからプロフィール取得
# =========================================================

def get_profile_by_username(username):

    result = (
        db
        .table("profiles")
        .select(
            "id,username,created_at,"
            "tutorial_completed,email,password_hash"
        )
        .eq(
            "username",
            username
        )
        .limit(1)
        .execute()
    )

    if result.data:
        return result.data[0]

    return None


# =========================================================
# メールアドレスからプロフィール取得
# =========================================================

def get_profile_by_email(email):

    result = (
        db
        .table("profiles")
        .select(
            "id,username,created_at,"
            "tutorial_completed,email,password_hash"
        )
        .eq(
            "email",
            email
        )
        .limit(1)
        .execute()
    )

    if result.data:
        return result.data[0]

    return None


# =========================================================
# ログイン必須
# =========================================================

def require_user():

    user_id = get_current_user_id()

    if not user_id:
        return None

    profile = get_profile(
        user_id
    )

    if not profile:
        session.clear()
        return None

    return profile


# =========================================================
# 初回ログイン後の移動先
# =========================================================

def redirect_after_login(profile):

    if not profile:
        return redirect("/")

    if not profile.get(
        "tutorial_completed",
        False
    ):

        return redirect(
            url_for("terms")
        )

    return redirect("/")


# =========================================================
# トップページ
# =========================================================

@app.route("/")
def index():

    profile = require_user()

    if not profile:

        return render_template(
            "auth.html"
        )

    if not profile.get(
        "tutorial_completed",
        False
    ):

        return redirect(
            url_for("terms")
        )

    username = profile["username"]

    user_id = str(
        profile["id"]
    )

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
# 新規登録
#
# Supabase Authは使用しません。
#
# Flask側でUUIDを生成
# ↓
# パスワードをハッシュ化
# ↓
# profilesへ直接保存
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
            "ユーザーネームが長すぎます"
        ), 400

    if len(password) < 8:

        return (
            "パスワードは8文字以上にしてください"
        ), 400

    try:

        # -------------------------------------------------
        # ユーザーネーム重複確認
        # -------------------------------------------------

        existing = get_profile_by_username(
            username
        )

        if existing:

            return (
                "そのユーザーネームは既に使用されています"
            ), 400

        # -------------------------------------------------
        # Flask側でUUID生成
        # -------------------------------------------------

        user_id = str(
            uuid.uuid4()
        )

        # -------------------------------------------------
        # パスワードをハッシュ化
        # -------------------------------------------------

        password_hash = (
            generate_password_hash(
                password
            )
        )

        # -------------------------------------------------
        # profilesへ保存
        #
        # emailは登録しないのでNULL
        # -------------------------------------------------

        profile_result = (
            db
            .table("profiles")
            .insert(
                {
                    "id":
                        user_id,

                    "username":
                        username,

                    "password_hash":
                        password_hash,

                    "email":
                        None,

                    "tutorial_completed":
                        False
                }
            )
            .execute()
        )

        if not profile_result.data:

            return (
                "プロフィールを作成できませんでした"
            ), 500

        # -------------------------------------------------
        # Flask Sessionへログイン情報保存
        # -------------------------------------------------

        session.clear()

        session["user_id"] = user_id

        session["new_registration"] = True

        session["terms_accepted"] = False

        session.modified = True

        print(
            "registration success:",
            user_id,
            username
        )

        return redirect(
            url_for("terms")
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
# ユーザーネームでもメールでもログイン可能。
# =========================================================

@app.route(
    "/login",
    methods=["POST"]
)
def login():

    login_id = str(
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

    if not login_id or not password:

        return (
            "ユーザーネームとパスワードを入力してください"
        ), 400

    try:

        # -------------------------------------------------
        # @があればメールとして検索
        # なければユーザーネームとして検索
        # -------------------------------------------------

        if "@" in login_id:

            profile = get_profile_by_email(
                login_id.lower()
            )

        else:

            profile = get_profile_by_username(
                login_id
            )

        if not profile:

            return (
                "ユーザーネームまたはパスワードが違います"
            ), 401

        password_hash = profile.get(
            "password_hash"
        )

        if not password_hash:

            return (
                "このアカウントのパスワード情報がありません"
            ), 401

        if not check_password_hash(
            password_hash,
            password
        ):

            return (
                "ユーザーネームまたはパスワードが違います"
            ), 401

        # -------------------------------------------------
        # ログイン成功
        # -------------------------------------------------

        session.clear()

        session["user_id"] = str(
            profile["id"]
        )

        session.modified = True

        print(
            "login success:",
            str(profile["id"])
        )

        return redirect_after_login(
            profile
        )

    except Exception as e:

        print(
            "login error:",
            repr(e)
        )

        return (
            "ログインに失敗しました"
        ), 401


# =========================================================
# セキュリティメール画面
#
# メール認証ではありません。
#
# パスワードを忘れたときの復旧用メールです。
# =========================================================

@app.route(
    "/security_email"
)
def security_email():

    profile = require_user()

    if not profile:

        return redirect("/")

    return render_template(
        "security_email.html",
        username=profile.get(
            "username",
            ""
        ),
        email=profile.get(
            "email"
        )
    )


# =========================================================
# セキュリティメール登録
#
# 本物のメールアドレスをプロフィールに保存するだけ。
# 認証メールは送信しません。
# =========================================================

@app.route(
    "/security_email",
    methods=["POST"]
)
def save_security_email():

    profile = require_user()

    if not profile:

        return redirect("/")

    email = str(
        request.form.get(
            "email",
            ""
        )
    ).strip().lower()

    if not email:

        return (
            "メールアドレスを入力してください"
        ), 400

    if "@" not in email:

        return (
            "正しいメールアドレスを入力してください"
        ), 400

    try:

        # -------------------------------------------------
        # 既に別ユーザーが使っていないか確認
        # -------------------------------------------------

        existing = get_profile_by_email(
            email
        )

        if (
            existing
            and str(existing["id"])
            != str(profile["id"])
        ):

            return (
                "そのメールアドレスは既に使用されています"
            ), 400

        # -------------------------------------------------
        # profilesだけ更新
        #
        # Authには一切触りません。
        # -------------------------------------------------

        (
            db
            .table("profiles")
            .update(
                {
                    "email":
                        email
                }
            )
            .eq(
                "id",
                str(profile["id"])
            )
            .execute()
        )

        return redirect(
            url_for("terms")
        )

    except Exception as e:

        print(
            "security email error:",
            repr(e)
        )

        return (
            "メールアドレスの登録に失敗しました: "
            + str(e)
        ), 400


# =========================================================
# セキュリティメールをスキップ
#
# emailはNULLのまま。
# =========================================================

@app.route(
    "/skip_security_email",
    methods=["GET", "POST"]
)
def skip_security_email():

    profile = require_user()

    if not profile:

        return redirect("/")

    return redirect(
        url_for("terms")
    )


# =========================================================
# パスワード忘れ
# =========================================================

@app.route(
    "/forgot_password",
    methods=["GET", "POST"]
)
def forgot_password():

    if request.method == "GET":

        return render_template(
            "forgot_password.html"
        )

    email = str(
        request.form.get(
            "email",
            ""
        )
    ).strip().lower()

    if not email:

        return (
            "メールアドレスを入力してください"
        ), 400

    profile = get_profile_by_email(
        email
    )

    # -----------------------------------------------------
    # セキュリティ上、
    # 存在しないメールでも同じメッセージにする
    # -----------------------------------------------------

    if not profile:

        return render_template(
            "forgot_password.html",
            message=(
                "入力されたメールアドレスに"
                "パスワード再設定の案内を送信しました。"
            )
        )

    if not SMTP_HOST:

        print(
            "SMTP is not configured."
        )

        return (
            "メール送信機能がまだ設定されていません"
        ), 500

    try:

        # -------------------------------------------------
        # リセットトークン作成
        # -------------------------------------------------

        token = (
            password_reset_serializer
            .dumps(
                {
                    "user_id":
                        str(profile["id"]),
                    "email":
                        email
                },
                salt="password-reset"
            )
        )

        reset_url = url_for(
            "reset_password",
            token=token,
            _external=True
        )

        # -------------------------------------------------
        # メール作成
        # -------------------------------------------------

        message = EmailMessage()

        message["Subject"] = (
            "Mr.Red Banana Chat "
            "パスワード再設定"
        )

        message["From"] = SMTP_FROM

        message["To"] = email

        message.set_content(
            "Mr.Red Banana Chatの"
            "パスワード再設定が要求されました。\n\n"
            "以下のリンクからパスワードを"
            "再設定してください。\n\n"
            + reset_url
            + "\n\n"
            "このリンクは1時間で期限切れになります。\n\n"
            "この操作をしていない場合は、"
            "このメールを無視してください。"
        )

        # -------------------------------------------------
        # SMTP送信
        # -------------------------------------------------

        with smtplib.SMTP(
            SMTP_HOST,
            SMTP_PORT
        ) as smtp:

            smtp.starttls()

            if SMTP_USERNAME and SMTP_PASSWORD:

                smtp.login(
                    SMTP_USERNAME,
                    SMTP_PASSWORD
                )

            smtp.send_message(
                message
            )

        print(
            "password reset email sent:",
            email
        )

        return render_template(
            "forgot_password.html",
            message=(
                "入力されたメールアドレスに"
                "パスワード再設定の案内を送信しました。"
            )
        )

    except Exception as e:

        print(
            "forgot password error:",
            repr(e)
        )

        return (
            "パスワード再設定メールの送信に失敗しました"
        ), 500


# =========================================================
# パスワード再設定
# =========================================================

@app.route(
    "/reset_password/<token>",
    methods=["GET", "POST"]
)
def reset_password(token):

    try:

        data = (
            password_reset_serializer
            .loads(
                token,
                salt="password-reset",
                max_age=PASSWORD_RESET_MAX_AGE
            )
        )

    except SignatureExpired:

        return (
            "このパスワード再設定リンクは期限切れです"
        ), 400

    except BadSignature:

        return (
            "無効なパスワード再設定リンクです"
        ), 400

    user_id = str(
        data.get("user_id", "")
    )

    email = str(
        data.get("email", "")
    ).lower()

    if not user_id or not email:

        return (
            "無効なパスワード再設定リンクです"
        ), 400

    profile = get_profile(
        user_id
    )

    if not profile:

        return (
            "ユーザーが存在しません"
        ), 404

    if str(
        profile.get("email") or ""
    ).lower() != email:

        return (
            "このリンクは使用できません"
        ), 400

    if request.method == "GET":

        return render_template(
            "reset_password.html"
        )

    password = str(
        request.form.get(
            "password",
            ""
        )
    )

    password_confirm = str(
        request.form.get(
            "password_confirm",
            ""
        )
    )

    if len(password) < 8:

        return (
            "パスワードは8文字以上にしてください"
        ), 400

    if password != password_confirm:

        return (
            "パスワードが一致しません"
        ), 400

    try:

        new_hash = (
            generate_password_hash(
                password
            )
        )

        (
            db
            .table("profiles")
            .update(
                {
                    "password_hash":
                        new_hash
                }
            )
            .eq(
                "id",
                user_id
            )
            .execute()
        )

        return redirect(
            "/"
        )

    except Exception as e:

        print(
            "reset password error:",
            repr(e)
        )

        return (
            "パスワードの変更に失敗しました"
        ), 500


# =========================================================
# パスワード変更
#
# ログイン中のユーザーが変更する場合。
# =========================================================

@app.route(
    "/change_password",
    methods=["POST"]
)
def change_password():

    profile = require_user()

    if not profile:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ログインしてください"
            }
        ), 401

    data = request.get_json() or {}

    current_password = str(
        data.get(
            "current_password",
            ""
        )
    )

    new_password = str(
        data.get(
            "new_password",
            ""
        )
    )

    if not current_password:

        return jsonify(
            {
                "status": "error",
                "message":
                    "現在のパスワードを入力してください"
            }
        ), 400

    if len(new_password) < 8:

        return jsonify(
            {
                "status": "error",
                "message":
                    "新しいパスワードは8文字以上にしてください"
            }
        ), 400

    if not check_password_hash(
        profile["password_hash"],
        current_password
    ):

        return jsonify(
            {
                "status": "error",
                "message":
                    "現在のパスワードが違います"
            }
        ), 401

    new_hash = (
        generate_password_hash(
            new_password
        )
    )

    (
        db
        .table("profiles")
        .update(
            {
                "password_hash":
                    new_hash
            }
        )
        .eq(
            "id",
            str(profile["id"])
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
# 契約画面
# =========================================================

@app.route(
    "/terms"
)
def terms():

    profile = require_user()

    if not profile:

        return redirect("/")

    if profile.get(
        "tutorial_completed",
        False
    ):

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

    profile = require_user()

    if not profile:

        return redirect("/")

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

    profile = require_user()

    if not profile:

        return redirect("/")

    if profile.get(
        "tutorial_completed",
        False
    ):

        return redirect("/")

    if (
        session.get(
            "new_registration",
            False
        )
        and not session.get(
            "terms_accepted",
            False
        )
    ):

        return redirect(
            url_for("terms")
        )

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

    profile = require_user()

    if not profile:

        return redirect("/")

    if (
        not session.get(
            "terms_accepted",
            False
        )
        and session.get(
            "new_registration",
            False
        )
    ):

        return redirect(
            url_for("terms")
        )

    (
        db
        .table("profiles")
        .update(
            {
                "tutorial_completed":
                    True
            }
        )
        .eq(
            "id",
            str(profile["id"])
        )
        .execute()
    )

    session.pop(
        "new_registration",
        None
    )

    session.pop(
        "terms_accepted",
        None
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

    profile = require_user()

    if not profile:

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

    profile = require_user()

    if not profile:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ログインしてください"
            }
        ), 401

    data = request.get_json() or {}

    room_code = str(
        data.get("room", "")
    )

    note = str(
        data.get("note", "")
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
                "note":
                    note
            }
        )
        .eq(
            "room_id",
            room["id"]
        )
        .eq(
            "user_id",
            str(profile["id"])
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

    profile = require_user()

    if not profile:

        return jsonify(
            {
                "status": "error"
            }
        ), 401

    data = request.get_json() or {}

    room_code = str(
        data.get("room", "")
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
            str(profile["id"])
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

    profile = require_user()

    if not profile:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ログインしてください"
            }
        ), 401

    data = request.get_json() or {}

    room_code = str(
        data.get("room", "")
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
            "password_enabled":
                False,
            "password_hash":
                None,
            "password_changed_at":
                None
        }

    old_password_hash = (
        settings.get(
            "password_hash"
        )
    )

    if not enabled:

        (
            db
            .table("room_settings")
            .update(
                {
                    "password_enabled":
                        False,
                    "updated_at":
                        datetime.now(
                            timezone.utc
                        ).isoformat()
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

    if old_password_hash:

        (
            db
            .table("room_settings")
            .update(
                {
                    "password_enabled":
                        True,
                    "updated_at":
                        datetime.now(
                            timezone.utc
                        ).isoformat()
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
                    now.isoformat(),
                "updated_at":
                    now.isoformat()
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

    profile = require_user()

    if not profile:

        return jsonify(
            {
                "status": "error"
            }
        ), 401

    data = request.get_json() or {}

    room_code = str(
        data.get("room", "")
    )

    new_password = str(
        data.get("password", "")
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

    changed_at = (
        result.data[0]
        .get(
            "password_changed_at"
        )
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
                    now.isoformat(),
                "updated_at":
                    now.isoformat()
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

    profile = require_user()

    if not profile:

        return jsonify(
            {
                "ok": False
            }
        ), 401

    data = request.get_json() or {}

    room_code = str(
        data.get("room", "")
    )

    password = str(
        data.get("password", "")
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
        profile["id"]
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

    profile = require_user()

    if not profile:
        return

    user_id = str(
        profile["id"]
    )

    room_code = generate_room_code()

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

    profile = require_user()

    if not profile:
        return

    room_code = str(
        data.get(
            "room",
            ""
        )
    )

    user_id = str(
        profile["id"]
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

        message_profile = get_profile(
            message_user_id
        )

        message_username = (
            message_profile["username"]
            if message_profile
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

    profile = require_user()

    if not profile:
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
        profile["id"]
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

    profile = require_user()

    if not profile:
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

    profile = require_user()

    if not profile:
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

    profile = require_user()

    if not profile:
        return

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
                    str(profile["id"]),
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

    profile = require_user()

    if not profile:
        return

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
        port=port,
        allow_unsafe_werkzeug=True
    )
