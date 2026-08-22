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
import secrets
import smtplib

from email.message import EmailMessage
from datetime import datetime, timezone, timedelta


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

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY")

if not SUPABASE_URL:
    raise RuntimeError(
        "SUPABASE_URL が設定されていません"
    )

if not SUPABASE_SECRET_KEY:
    raise RuntimeError(
        "SUPABASE_SECRET_KEY が設定されていません"
    )


# =========================================================
# Supabase
#
# 今回はSupabase Authではなく、
# Supabase Databaseだけを使用します。
# =========================================================

db = create_client(
    SUPABASE_URL,
    SUPABASE_SECRET_KEY
)


# =========================================================
# メール設定
#
# パスワード再設定メール用。
#
# RenderのEnvironment Variablesに設定します。
#
# SMTP_HOST
# SMTP_PORT
# SMTP_USERNAME
# SMTP_PASSWORD
# MAIL_FROM
#
# MAIL_FROMを省略した場合はSMTP_USERNAMEを使用。
# =========================================================

SMTP_HOST = os.environ.get("SMTP_HOST")
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

MAIL_FROM = os.environ.get(
    "MAIL_FROM",
    SMTP_USERNAME or ""
)


# =========================================================
# 現在のユーザー
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
                "id,username,email,created_at,"
                "tutorial_completed,password_hash"
            )
            .eq(
                "id",
                str(user_id)
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

    result = (
        db
        .table("profiles")
        .select(
            "id,username,email,created_at,"
            "tutorial_completed,password_hash"
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
# ログイン必須
# =========================================================

def require_user():

    user = get_current_user()

    if not user:
        return None

    return user


# =========================================================
# ユーザーID生成
# =========================================================

def generate_user_id():

    return str(
        uuid.uuid4()
    )


# =========================================================
# 初回ログイン後の移動先
# =========================================================

def redirect_after_auth(
    user,
    newly_created=False
):

    if not user:
        return redirect("/")

    if newly_created:

        session["new_registration"] = True

        return redirect(
            url_for("security_email")
        )

    if not user.get(
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

    user = get_current_user()

    if not user:

        return render_template(
            "auth.html"
        )

    if not user.get(
        "tutorial_completed",
        False
    ):

        if not session.get(
            "terms_accepted",
            False
        ):

            return redirect(
                url_for("terms")
            )

        return redirect(
            url_for("tutorial")
        )

    username = user["username"]
    user_id = str(user["id"])

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
# username
# password
#      ↓
# profiles
#
# emailはNULL
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
            "ユーザーネームは100文字以内にしてください"
        ), 400

    if len(password) < 8:

        return (
            "パスワードは8文字以上にしてください"
        ), 400

    try:

        # -------------------------------------------------
        # username重複確認
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
                "そのユーザーネームはすでに使用されています"
            ), 409

        # -------------------------------------------------
        # 新しいUUID
        # -------------------------------------------------

        user_id = generate_user_id()

        # -------------------------------------------------
        # パスワードハッシュ
        # -------------------------------------------------

        password_hash = (
            generate_password_hash(
                password
            )
        )

        # -------------------------------------------------
        # profiles作成
        #
        # emailはNULL。
        # 架空メールは作りません。
        # -------------------------------------------------

        result = (
            db
            .table("profiles")
            .insert(
                {
                    "id": user_id,
                    "username": username,
                    "email": None,
                    "password_hash":
                        password_hash,
                    "tutorial_completed":
                        False
                }
            )
            .execute()
        )

        if not result.data:

            return (
                "アカウントを作成できませんでした"
            ), 500

        # -------------------------------------------------
        # 自動ログイン
        # -------------------------------------------------

        session.clear()

        session["user_id"] = user_id
        session["new_registration"] = True

        session.modified = True

        print(
            "registration success:",
            user_id,
            username
        )

        return redirect(
            url_for("security_email")
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
# ユーザーネームでログイン
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
                "id,username,email,created_at,"
                "tutorial_completed,password_hash"
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
                "ユーザーネームまたはパスワードが違います"
            ), 401

        user = result.data[0]

        password_hash = user.get(
            "password_hash"
        )

        if not password_hash:

            return (
                "このアカウントにはパスワードが設定されていません"
            ), 401

        if not check_password_hash(
            password_hash,
            password
        ):

            return (
                "ユーザーネームまたはパスワードが違います"
            ), 401

        session.clear()

        session["user_id"] = str(
            user["id"]
        )

        session.modified = True

        print(
            "login success:",
            str(user["id"])
        )

        return redirect_after_auth(
            user,
            newly_created=False
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
# メールは完全に任意。
# 登録しなくても利用可能。
# =========================================================

@app.route(
    "/security_email"
)
def security_email():

    user = require_user()

    if not user:

        return redirect("/")

    return render_template(
        "security_email.html",
        username=user.get(
            "username",
            ""
        ),
        email=user.get(
            "email"
        ),
        email_registered=bool(
            user.get("email")
        )
    )


# =========================================================
# セキュリティメール登録
#
# メール認証は行いません。
# DBに保存するだけです。
# =========================================================

@app.route(
    "/security_email",
    methods=["POST"]
)
def save_security_email():

    user = require_user()

    if not user:

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

        user_id = str(
            user["id"]
        )

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
                user_id
            )
            .execute()
        )

        session["security_email_added"] = True

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

    user = require_user()

    if not user:

        return redirect("/")

    session["security_email_skipped"] = True

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

    username = str(
        request.form.get(
            "username",
            ""
        )
    ).strip()

    if not username:

        return (
            "ユーザーネームを入力してください"
        ), 400

    try:

        result = (
            db
            .table("profiles")
            .select(
                "id,username,email"
            )
            .eq(
                "username",
                username
            )
            .limit(1)
            .execute()
        )

        # セキュリティ上、
        # 存在しないユーザーと
        # メール未登録ユーザーを
        # 区別しない。
        if not result.data:

            return render_template(
                "forgot_password.html",
                message=(
                    "メールアドレスが登録されている場合、"
                    "再設定メールを送信します。"
                )
            )

        user = result.data[0]
        email = user.get("email")

        if not email:

            return render_template(
                "forgot_password.html",
                message=(
                    "このアカウントには"
                    "復旧用メールアドレスが登録されていません。"
                )
            )

        # -------------------------------------------------
        # リセットトークン
        # -------------------------------------------------

        token = secrets.token_urlsafe(48)

        expires_at = (
            datetime.now(
                timezone.utc
            )
            + timedelta(
                minutes=30
            )
        )

        # -------------------------------------------------
        # password_reset_tokens テーブル
        #
        # Supabase側で作成してください。
        # -------------------------------------------------

        db.table(
            "password_reset_tokens"
        ).insert(
            {
                "token": token,
                "user_id": str(user["id"]),
                "expires_at":
                    expires_at.isoformat()
            }
        ).execute()

        reset_url = url_for(
            "reset_password",
            token=token,
            _external=True
        )

        send_reset_email(
            email,
            reset_url
        )

        return render_template(
            "forgot_password.html",
            message=(
                "パスワード再設定メールを送信しました。"
            )
        )

    except Exception as e:

        print(
            "forgot password error:",
            repr(e)
        )

        return (
            "パスワード再設定処理でエラーが発生しました"
        ), 500


# =========================================================
# パスワード再設定メール送信
# =========================================================

def send_reset_email(
    email,
    reset_url
):

    if not SMTP_HOST:
        raise RuntimeError(
            "SMTP_HOST が設定されていません"
        )

    if not SMTP_USERNAME:
        raise RuntimeError(
            "SMTP_USERNAME が設定されていません"
        )

    if not SMTP_PASSWORD:
        raise RuntimeError(
            "SMTP_PASSWORD が設定されていません"
        )

    if not MAIL_FROM:
        raise RuntimeError(
            "MAIL_FROM が設定されていません"
        )

    message = EmailMessage()

    message["Subject"] = (
        "Mr.Red Banana Chat "
        "パスワード再設定"
    )

    message["From"] = MAIL_FROM
    message["To"] = email

    message.set_content(
        "Mr.Red Banana Chatの"
        "パスワード再設定を行います。\n\n"
        "以下のリンクを開いて、"
        "新しいパスワードを設定してください。\n\n"
        f"{reset_url}\n\n"
        "このリンクは30分間有効です。\n"
        "心当たりがない場合は、このメールを無視してください。"
    )

    with smtplib.SMTP(
        SMTP_HOST,
        SMTP_PORT
    ) as smtp:

        smtp.starttls()

        smtp.login(
            SMTP_USERNAME,
            SMTP_PASSWORD
        )

        smtp.send_message(
            message
        )


# =========================================================
# パスワード再設定
# =========================================================

@app.route(
    "/reset_password/<token>",
    methods=["GET", "POST"]
)
def reset_password(token):

    try:

        result = (
            db
            .table("password_reset_tokens")
            .select(
                "id,user_id,expires_at,used"
            )
            .eq(
                "token",
                token
            )
            .limit(1)
            .execute()
        )

        if not result.data:

            return (
                "無効なパスワード再設定リンクです"
            ), 400

        reset_token = result.data[0]

        if reset_token.get(
            "used",
            False
        ):

            return (
                "この再設定リンクはすでに使用されています"
            ), 400

        expires_at = datetime.fromisoformat(
            reset_token["expires_at"]
            .replace(
                "Z",
                "+00:00"
            )
        )

        if (
            datetime.now(timezone.utc)
            > expires_at
        ):

            return (
                "この再設定リンクは期限切れです"
            ), 400

        if request.method == "GET":

            return render_template(
                "reset_password.html",
                token=token
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
                str(reset_token["user_id"])
            )
            .execute()
        )

        (
            db
            .table("password_reset_tokens")
            .update(
                {
                    "used": True
                }
            )
            .eq(
                "id",
                reset_token["id"]
            )
            .execute()
        )

        return redirect(
            url_for("index")
        )

    except Exception as e:

        print(
            "reset password error:",
            repr(e)
        )

        return (
            "パスワードの再設定に失敗しました"
        ), 500


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

    user = require_user()

    if not user:

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

    user = require_user()

    if not user:

        return redirect("/")

    if user.get(
        "tutorial_completed",
        False
    ):

        return redirect("/")

    if not session.get(
        "terms_accepted",
        False
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

    user = require_user()

    if not user:

        return redirect("/")

    if not session.get(
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

    session.pop(
        "new_registration",
        None
    )

    session.pop(
        "terms_accepted",
        None
    )

    session.pop(
        "security_email_added",
        None
    )

    session.pop(
        "security_email_skipped",
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

    if not enabled:

        (
            db
            .table("room_settings")
            .update(
                {
                    "password_enabled": False,
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
                "password_changed": False
            }
        )

    if old_password_hash:

        (
            db
            .table("room_settings")
            .update(
                {
                    "password_enabled": True,
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
                "password_changed": False
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

    settings = settings_result.data[0]

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

    room_code = generate_room_code()

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

    db.table(
        "room_settings"
    ).insert(
        {
            "room_id": room_uuid,
            "password_enabled": False,
            "password_hash": None,
            "password_changed_at": None
        }
    ).execute()

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
            "room_id": room_uuid,
            "user_id": user_id,
            "message": message
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
            data.get("id")
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
        port=port,
        allow_unsafe_werkzeug=True
    )
