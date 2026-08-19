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
from supabase.client import ClientOptions

import os
import random
import re
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

# RenderではHTTPSなのでSecure Cookieを使用
# "false" という文字列をTrue扱いしないようにする
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

if not SUPABASE_PUBLISHABLE_KEY:
    raise RuntimeError(
        "SUPABASE_PUBLISHABLE_KEY が設定されていません"
    )

if not SUPABASE_SECRET_KEY:
    raise RuntimeError(
        "SUPABASE_SECRET_KEY が設定されていません"
    )


# =========================================================
# Supabase DB / Admin Client
#
# Secret Keyはサーバー側だけで使用。
# ブラウザには絶対に渡さない。
# =========================================================

db = create_client(
    SUPABASE_URL,
    SUPABASE_SECRET_KEY
)


# =========================================================
# Flask Session Storage
#
# OAuth PKCEのstate/verifier等を
# Flask Sessionに保存するために使用。
# =========================================================

class FlaskSessionStorage:

    def get_item(self, key):
        return session.get(key)

    def set_item(self, key, value):
        session[key] = value

    def remove_item(self, key):
        session.pop(key, None)


# =========================================================
# Supabase Auth Client
# =========================================================

def get_auth_client():

    options = ClientOptions(
        storage=FlaskSessionStorage(),
        flow_type="pkce",
        auto_refresh_token=False,
        persist_session=True,
    )

    return create_client(
        SUPABASE_URL,
        SUPABASE_PUBLISHABLE_KEY,
        options=options
    )


# =========================================================
# JSON request判定
# =========================================================

def wants_json_response():

    return request.is_json or (
        "application/json" in
        request.headers.get("Accept", "")
    )


# =========================================================
# JSON / Form 両対応の入力取得
# =========================================================

def get_request_data():

    if request.is_json:

        return request.get_json(
            silent=True
        ) or {}

    return request.form.to_dict()


# =========================================================
# 現在時刻
# =========================================================

def now_iso():

    return datetime.now(
        timezone.utc
    ).isoformat()


# =========================================================
# 内部Auth用メールアドレス
#
# 実際のメールアドレスではありません。
#
# ユーザーネーム
#     ↓
# username@mr-red-banana-chat.local
#
# Supabase Authはemail+password認証を利用するため、
# 内部的な識別子として使用します。
#
# 実際のメールアドレスはprofiles.emailに任意保存します。
# =========================================================

def make_internal_auth_email(username):

    safe_username = re.sub(
        r"[^a-zA-Z0-9_.-]",
        "_",
        username
    )

    safe_username = safe_username.lower()

    return (
        safe_username
        + "@mr-red-banana-chat.local"
    )


# =========================================================
# プロフィール取得
#
# profiles:
#   id
#   username
#   email
#   created_at
#   tutorial_completed
# =========================================================

def get_profile(user_id):

    try:

        result = (
            db
            .table("profiles")
            .select(
                "id,username,email,created_at,tutorial_completed"
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

    except Exception as e:

        print(
            "get_profile error:",
            repr(e)
        )

    return None


# =========================================================
# Profile作成
# =========================================================

def ensure_profile(
    auth_user,
    username=None
):

    user_id = str(
        auth_user.id
    )

    profile = get_profile(
        user_id
    )

    if profile:

        # OAuth等でusernameが未設定の場合のみ補完
        if (
            username
            and profile.get("username") != username
        ):

            try:

                (
                    db
                    .table("profiles")
                    .update(
                        {
                            "username":
                                username
                        }
                    )
                    .eq(
                        "id",
                        user_id
                    )
                    .execute()
                )

                profile = get_profile(
                    user_id
                )

            except Exception as e:

                print(
                    "profile username update error:",
                    repr(e)
                )

        return profile, False


    metadata = (
        auth_user.user_metadata
        or {}
    )


    resolved_username = (
        username
        or metadata.get("username")
        or metadata.get("user_name")
        or metadata.get("preferred_username")
        or metadata.get("name")
        or (
            auth_user.email.split("@")[0]
            if getattr(auth_user, "email", None)
            else "User"
        )
    )


    resolved_username = str(
        resolved_username
    )[:100]


    # -----------------------------------------------------
    # 同名ユーザー確認
    # -----------------------------------------------------

    try:

        existing = (
            db
            .table("profiles")
            .select("id")
            .eq(
                "username",
                resolved_username
            )
            .limit(1)
            .execute()
        )

        if existing.data:

            resolved_username = (
                resolved_username
                + "_"
                + user_id[:8]
            )

    except Exception as e:

        print(
            "profile duplicate check error:",
            repr(e)
        )


    # -----------------------------------------------------
    # profiles作成
    # -----------------------------------------------------

    result = (
        db
        .table("profiles")
        .insert(
            {
                "id": user_id,
                "username": resolved_username,
                "email": None,
                "tutorial_completed": False
            }
        )
        .execute()
    )


    if result.data:

        return result.data[0], True


    return get_profile(
        user_id
    ), False


# =========================================================
# 現在ログイン中のSupabase Authユーザー
# =========================================================

def get_current_auth_user():

    access_token = session.get(
        "access_token"
    )

    refresh_token = session.get(
        "refresh_token"
    )


    if not access_token:
        return None


    try:

        auth_client = get_auth_client()


        # -------------------------------------------------
        # Sessionを復元
        # -------------------------------------------------

        if refresh_token:

            auth_client.auth.set_session(
                access_token,
                refresh_token
            )

            current_session = (
                auth_client
                .auth
                .get_session()
            )

            if (
                current_session
                and current_session.session
            ):

                current = (
                    current_session.session
                )

                session["access_token"] = (
                    current.access_token
                )

                if current.refresh_token:

                    session["refresh_token"] = (
                        current.refresh_token
                    )

                access_token = (
                    current.access_token
                )


        # -------------------------------------------------
        # JWTをSupabase側で検証
        # -------------------------------------------------

        response = (
            auth_client
            .auth
            .get_user(
                access_token
            )
        )

        user = response.user

        if not user:

            return None

        return user


    except Exception as e:

        print(
            "get_current_auth_user error:",
            repr(e)
        )

        return None


# =========================================================
# 現在ログイン中のプロフィール
# =========================================================

def get_current_user():

    auth_user = get_current_auth_user()

    if not auth_user:

        return None

    profile = get_profile(
        auth_user.id
    )

    if not profile:

        profile, _ = ensure_profile(
            auth_user
        )

    if not profile:

        return None

    return profile


# =========================================================
# ログイン必須
# =========================================================

def require_user():

    return get_current_user()


# =========================================================
# 認証後の移動
# =========================================================

def redirect_after_auth(
    auth_user,
    newly_created=False,
    linked=False
):

    profile, created = ensure_profile(
        auth_user
    )


    if not profile:

        return (
            "プロフィールを作成できませんでした"
        ), 500


    # -----------------------------------------------------
    # OAuth連携完了
    # -----------------------------------------------------

    if linked:

        return redirect(
            url_for("security_email")
        )


    # -----------------------------------------------------
    # 新規登録
    # -----------------------------------------------------

    if newly_created or created:

        session["new_registration"] = True

        return redirect(
            url_for("security_email")
        )


    # -----------------------------------------------------
    # 新規登録途中
    # -----------------------------------------------------

    if session.get(
        "new_registration",
        False
    ):

        return redirect(
            url_for("security_email")
        )


    # -----------------------------------------------------
    # チュートリアル未完了
    # -----------------------------------------------------

    if not profile.get(
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

        if session.get(
            "new_registration",
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

    user_id = str(
        user["id"]
    )


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
# JSON / Form の両方を受け付ける
# =========================================================

@app.route(
    "/register",
    methods=["POST"]
)
def register():

    data = get_request_data()


    username = str(
        data.get(
            "username",
            ""
        )
    ).strip()


    password = str(
        data.get(
            "password",
            ""
        )
    )


    # -----------------------------------------------------
    # 入力チェック
    # -----------------------------------------------------

    if not username:

        message = (
            "ユーザーネームを入力してください"
        )

        if wants_json_response():

            return jsonify(
                {
                    "ok": False,
                    "message": message
                }
            ), 400

        return message, 400


    if len(username) < 3:

        message = (
            "ユーザーネームは3文字以上にしてください"
        )

        if wants_json_response():

            return jsonify(
                {
                    "ok": False,
                    "message": message
                }
            ), 400

        return message, 400


    if len(username) > 50:

        message = (
            "ユーザーネームは50文字以内にしてください"
        )

        if wants_json_response():

            return jsonify(
                {
                    "ok": False,
                    "message": message
                }
            ), 400

        return message, 400


    if not password:

        message = (
            "パスワードを入力してください"
        )

        if wants_json_response():

            return jsonify(
                {
                    "ok": False,
                    "message": message
                }
            ), 400

        return message, 400


    if len(password) < 6:

        message = (
            "パスワードは6文字以上にしてください"
        )

        if wants_json_response():

            return jsonify(
                {
                    "ok": False,
                    "message": message
                }
            ), 400

        return message, 400


    # =====================================================
    # profilesのユーザーネーム重複確認
    # =====================================================

    try:

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

            message = (
                "そのユーザーネームは"
                "すでに使用されています"
            )


            if wants_json_response():

                return jsonify(
                    {
                        "ok": False,
                        "message": message
                    }
                ), 409


            return message, 409


    except Exception as e:

        print(
            "username duplicate check error:",
            repr(e)
        )


    # =====================================================
    # Supabase Authユーザー作成
    #
    # Admin APIで内部メールを使用。
    #
    # email_confirm=Trueなので、
    # この内部メール宛の確認メールは送られません。
    #
    # Admin APIはSecret Keyが必要で、
    # サーバー側でのみ実行します。
    # =====================================================

    internal_email = (
        make_internal_auth_email(
            username
        )
    )


    try:

        admin_response = (
            db
            .auth
            .admin
            .create_user(
                {
                    "email":
                        internal_email,

                    "password":
                        password,

                    "email_confirm":
                        True,

                    "user_metadata":
                        {
                            "username":
                                username
                        }
                }
            )
        )


        auth_user = (
            admin_response.user
        )


    except Exception as create_error:

        print(
            "admin create_user error:",
            repr(create_error)
        )


        # -------------------------------------------------
        # 以前の試行でAuth側だけ
        # 作成済みだった場合の救済
        # -------------------------------------------------

        try:

            auth_client = get_auth_client()

            login_response = (
                auth_client
                .auth
                .sign_in_with_password(
                    {
                        "email":
                            internal_email,

                        "password":
                            password
                    }
                )
            )


            if (
                login_response.user
                and login_response.session
            ):

                auth_user = (
                    login_response.user
                )

                session["access_token"] = (
                    login_response
                    .session
                    .access_token
                )

                session["refresh_token"] = (
                    login_response
                    .session
                    .refresh_token
                )

                session["new_registration"] = (
                    True
                )

                ensure_profile(
                    auth_user,
                    username=username
                )

                if wants_json_response():

                    return jsonify(
                        {
                            "ok": True,
                            "next":
                                url_for(
                                    "security_email"
                                )
                        }
                    )


                return redirect(
                    url_for(
                        "security_email"
                    )
                )


        except Exception as recovery_error:

            print(
                "register recovery error:",
                repr(recovery_error)
            )


        message = (
            "新規登録に失敗しました: "
            + str(create_error)
        )


        if wants_json_response():

            return jsonify(
                {
                    "ok": False,
                    "message": message
                }
            ), 400


        return message, 400


    # =====================================================
    # profiles作成
    # =====================================================

    try:

        profile, _ = (
            ensure_profile(
                auth_user,
                username=username
            )
        )


        if not profile:

            # Authだけ出来てprofileがない状態を
            # 放置しない
            try:

                db.auth.admin.delete_user(
                    str(auth_user.id)
                )

            except Exception:

                pass


            message = (
                "プロフィールを作成できませんでした"
            )


            if wants_json_response():

                return jsonify(
                    {
                        "ok": False,
                        "message": message
                    }
                ), 500


            return message, 500


    except Exception as e:

        print(
            "ensure_profile after register error:",
            repr(e)
        )


        message = (
            "プロフィール作成に失敗しました"
        )


        if wants_json_response():

            return jsonify(
                {
                    "ok": False,
                    "message": message
                }
            ), 500


        return message, 500


    # =====================================================
    # 作成直後に通常ログイン
    #
    # Admin create_user() 自体はsessionを返さないため、
    # publishable clientでpassword loginする。
    # =====================================================

    try:

        auth_client = get_auth_client()


        login_response = (
            auth_client
            .auth
            .sign_in_with_password(
                {
                    "email":
                        internal_email,

                    "password":
                        password
                }
            )
        )


        auth_session = (
            login_response.session
        )


        if not auth_session:

            message = (
                "登録はできましたが、"
                "ログインセッションを作成できませんでした"
            )


            if wants_json_response():

                return jsonify(
                    {
                        "ok": False,
                        "message": message
                    }
                ), 500


            return message, 500


        session.clear()


        session["access_token"] = (
            auth_session.access_token
        )


        session["refresh_token"] = (
            auth_session.refresh_token
        )


        session["new_registration"] = True


        session.modified = True


        print(
            "REGISTER SUCCESS:",
            str(auth_user.id),
            username
        )


        if wants_json_response():

            return jsonify(
                {
                    "ok": True,
                    "next":
                        url_for(
                            "security_email"
                        )
                }
            )


        return redirect(
            url_for(
                "security_email"
            )
        )


    except Exception as e:

        print(
            "register login error:",
            repr(e)
        )


        message = (
            "登録はできましたが、"
            "自動ログインに失敗しました"
        )


        if wants_json_response():

            return jsonify(
                {
                    "ok": False,
                    "message": message
                }
            ), 500


        return message, 500


# =========================================================
# ログイン
#
# ユーザーネーム + パスワード
# =========================================================

@app.route(
    "/login",
    methods=["POST"]
)
def login():

    data = get_request_data()


    username = str(
        data.get(
            "username",
            ""
        )
    ).strip()


    password = str(
        data.get(
            "password",
            ""
        )
    )


    if not username or not password:

        message = (
            "ユーザーネームと"
            "パスワードを入力してください"
        )


        if wants_json_response():

            return jsonify(
                {
                    "ok": False,
                    "message": message
                }
            ), 400


        return message, 400


    # =====================================================
    # username → internal auth email
    # =====================================================

    internal_email = (
        make_internal_auth_email(
            username
        )
    )


    try:

        auth_client = get_auth_client()


        response = (
            auth_client
            .auth
            .sign_in_with_password(
                {
                    "email":
                        internal_email,

                    "password":
                        password
                }
            )
        )


        user = response.user
        auth_session = response.session


        if not user or not auth_session:

            message = (
                "ログインに失敗しました"
            )


            if wants_json_response():

                return jsonify(
                    {
                        "ok": False,
                        "message": message
                    }
                ), 401


            return message, 401


        # =================================================
        # Session保存
        # =================================================

        session.clear()


        session["access_token"] = (
            auth_session.access_token
        )


        session["refresh_token"] = (
            auth_session.refresh_token
        )


        session.modified = True


        profile = get_profile(
            user.id
        )


        if not profile:

            profile, _ = ensure_profile(
                user,
                username=username
            )


        if not profile:

            message = (
                "プロフィールを取得できませんでした"
            )


            if wants_json_response():

                return jsonify(
                    {
                        "ok": False,
                        "message": message
                    }
                ), 500


            return message, 500


        print(
            "LOGIN SUCCESS:",
            str(user.id),
            username
        )


        # =================================================
        # 未完了ユーザー
        # =================================================

        if not profile.get(
            "tutorial_completed",
            False
        ):

            if not session.get(
                "terms_accepted",
                False
            ):

                # 既存ユーザーでも、
                # 初回オンボーディングが途中なら
                # セキュリティ補強画面へ
                if session.get(
                    "new_registration",
                    False
                ):

                    next_url = (
                        url_for(
                            "security_email"
                        )
                    )

                else:

                    next_url = (
                        url_for(
                            "terms"
                        )
                    )


            else:

                next_url = (
                    url_for(
                        "tutorial"
                    )
                )


        else:

            next_url = "/"


        if wants_json_response():

            return jsonify(
                {
                    "ok": True,
                    "next": next_url
                }
            )


        return redirect(
            next_url
        )


    except Exception as e:

        print(
            "login error:",
            repr(e)
        )


        message = (
            "ログインに失敗しました: "
            + str(e)
        )


        if wants_json_response():

            return jsonify(
                {
                    "ok": False,
                    "message": message
                }
            ), 401


        return message, 401


# =========================================================
# セキュリティ補強画面
# =========================================================

@app.route(
    "/security-email"
)
def security_email():

    user = require_user()


    if not user:

        return redirect("/")


    return render_template(
        "security_email.html",
        username=user["username"],
        email=user.get("email")
    )


# =========================================================
# メール追加
#
# 今回は profiles.email に保存。
#
# Auth内部メールは変更しません。
# 実メール確認フローは後から追加可能です。
# =========================================================

@app.route(
    "/add_email",
    methods=["POST"]
)
def add_email():

    user = require_user()


    if not user:

        if wants_json_response():

            return jsonify(
                {
                    "ok": False,
                    "message":
                        "ログインしてください"
                }
            ), 401


        return (
            "ログインしてください"
        ), 401


    data = get_request_data()


    email = str(
        data.get(
            "email",
            ""
        )
    ).strip()


    if not email:

        message = (
            "メールアドレスを入力してください"
        )


        if wants_json_response():

            return jsonify(
                {
                    "ok": False,
                    "message": message
                }
            ), 400


        return message, 400


    if not re.match(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        email
    ):

        message = (
            "正しいメールアドレスを入力してください"
        )


        if wants_json_response():

            return jsonify(
                {
                    "ok": False,
                    "message": message
                }
            ), 400


        return message, 400


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


        if wants_json_response():

            return jsonify(
                {
                    "ok": True,
                    "next":
                        url_for(
                            "terms"
                        )
                }
            )


        return redirect(
            url_for("terms")
        )


    except Exception as e:

        print(
            "add_email error:",
            repr(e)
        )


        message = (
            "メールアドレスの保存に失敗しました"
        )


        if wants_json_response():

            return jsonify(
                {
                    "ok": False,
                    "message": message
                }
            ), 500


        return message, 500


# =========================================================
# メールスキップ
# =========================================================

@app.route(
    "/skip_email",
    methods=["POST", "GET"]
)
def skip_email():

    user = require_user()


    if not user:

        if wants_json_response():

            return jsonify(
                {
                    "ok": False,
                    "message":
                        "ログインしてください"
                }
            ), 401


        return redirect("/")


    session["security_skipped"] = True


    if wants_json_response():

        return jsonify(
            {
                "ok": True,
                "next":
                    url_for(
                        "terms"
                    )
            }
        )


    return redirect(
        url_for("terms")
    )


# =========================================================
# OAuth ログイン開始
#
# Google / GitHub / Microsoft
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


    try:

        auth_client = get_auth_client()


        redirect_url = url_for(
            "oauth_callback",
            _external=True
        )


        # 通常のログイン
        session["oauth_purpose"] = (
            "login"
        )


        response = (
            auth_client
            .auth
            .sign_in_with_oauth(
                {
                    "provider":
                        provider,

                    "options":
                        {
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
            "OAuth start error:",
            repr(e)
        )


        return (
            "OAuthログインを開始できませんでした"
        ), 500


# =========================================================
# OAuth Identity Linking開始
#
# ログイン中ユーザーが
# Google / GitHub / Microsoftを追加する。
#
# Supabase Dashboardで
# Manual Linkingを有効にする必要があります。
# =========================================================

@app.route(
    "/auth/link/<provider>"
)
def oauth_link_start(provider):

    allowed_providers = {
        "google",
        "github",
        "azure"
    }


    if provider not in allowed_providers:

        return (
            "対応していないログイン方法です"
        ), 400


    user = require_user()


    if not user:

        return redirect("/")


    try:

        auth_client = get_auth_client()


        redirect_url = url_for(
            "oauth_callback",
            _external=True
        )


        session["oauth_purpose"] = (
            "link"
        )


        session["oauth_link_user_id"] = (
            str(user["id"])
        )


        response = (
            auth_client
            .auth
            .link_identity(
                {
                    "provider":
                        provider,

                    "options":
                        {
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
            "OAuth link start error:",
            repr(e)
        )


        return (
            "外部アカウント連携を開始できませんでした。"
            "SupabaseのManual Linking設定も確認してください。"
        ), 500


# =========================================================
# OAuth callback
# =========================================================

@app.route(
    "/auth/callback"
)
def oauth_callback():

    error = request.args.get(
        "error"
    )


    if error:

        description = request.args.get(
            "error_description",
            error
        )


        return (
            "ログインに失敗しました: "
            + description
        ), 400


    code = request.args.get(
        "code"
    )


    if not code:

        return (
            "認証コードがありません"
        ), 400


    purpose = session.get(
        "oauth_purpose",
        "login"
    )


    try:

        auth_client = get_auth_client()


        response = (
            auth_client
            .auth
            .exchange_code_for_session(
                {
                    "auth_code":
                        code
                }
            )
        )


        auth_session = response.session
        auth_user = response.user


        if not auth_session or not auth_user:

            return (
                "認証セッションを取得できませんでした"
            ), 500


        # =================================================
        # Identity Link
        # =================================================

        if purpose == "link":

            current_user_id = session.get(
                "oauth_link_user_id"
            )


            if (
                not current_user_id
                or str(auth_user.id)
                != str(current_user_id)
            ):

                return (
                    "外部アカウント連携を確認できませんでした"
                ), 400


            session["access_token"] = (
                auth_session.access_token
            )


            session["refresh_token"] = (
                auth_session.refresh_token
            )


            session["oauth_purpose"] = None
            session["oauth_link_user_id"] = None


            return redirect(
                url_for(
                    "security_email"
                )
            )


        # =================================================
        # 通常OAuthログイン
        # =================================================

        session["access_token"] = (
            auth_session.access_token
        )


        session["refresh_token"] = (
            auth_session.refresh_token
        )


        session["oauth_purpose"] = None


        profile = get_profile(
            auth_user.id
        )


        if not profile:

            profile, created = (
                ensure_profile(
                    auth_user
                )
            )

        else:

            created = False


        if profile and not profile.get(
            "email"
        ):

            auth_email = getattr(
                auth_user,
                "email",
                None
            )


            if (
                auth_email
                and "@mr-red-banana-chat.local"
                not in auth_email
            ):

                try:

                    (
                        db
                        .table("profiles")
                        .update(
                            {
                                "email":
                                    auth_email
                            }
                        )
                        .eq(
                            "id",
                            str(auth_user.id)
                        )
                        .execute()
                    )

                except Exception as e:

                    print(
                        "OAuth email save warning:",
                        repr(e)
                    )


        return redirect_after_auth(
            auth_user,
            newly_created=created
        )


    except Exception as e:

        print(
            "OAuth callback error:",
            repr(e)
        )


        return (
            "OAuthログイン処理でエラーが発生しました"
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


    # -----------------------------------------------------
    # チュートリアル完了済みならホーム
    # -----------------------------------------------------

    if user.get(
        "tutorial_completed",
        False
    ):

        return redirect("/")


    # -----------------------------------------------------
    # すでにこのセッションで
    # 契約同意済みならTutorial
    # -----------------------------------------------------

    if session.get(
        "terms_accepted",
        False
    ):

        return redirect(
            url_for(
                "tutorial"
            )
        )


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
# Tutorial
# =========================================================

@app.route(
    "/tutorial"
)
def tutorial():

    user = require_user()


    if not user:

        return redirect("/")


    # 新規登録フロー中なら
    # 契約同意が先
    if session.get(
        "new_registration",
        False
    ) and not session.get(
        "terms_accepted",
        False
    ):

        return redirect(
            url_for(
                "terms"
            )
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
# Tutorial 完了
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
            url_for(
                "terms"
            )
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
        "security_skipped",
        None
    )


    session.pop(
        "email_added",
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

    try:

        auth_client = get_auth_client()

        auth_client.auth.sign_out()

    except Exception as e:

        print(
            "logout error:",
            repr(e)
        )


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
# room_code -> UUID
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
                "status":
                    "error",
                "message":
                    "ログインしてください"
            }
        ), 401


    data = request.get_json(
        silent=True
    ) or {}


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
                "status":
                    "error",
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
            str(user["id"])
        )
        .execute()
    )


    return jsonify(
        {
            "status":
                "ok"
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
                "status":
                    "error"
            }
        ), 401


    data = request.get_json(
        silent=True
    ) or {}


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
                "status":
                    "error",
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
            "status":
                "ok"
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
                "status":
                    "error",
                "message":
                    "ログインしてください"
            }
        ), 401


    data = request.get_json(
        silent=True
    ) or {}


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
                "status":
                    "error",
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
                "status":
                    "ok",
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
                "status":
                    "ok",
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
                "status":
                    "error",
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
            "status":
                "ok",
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
                "status":
                    "error"
            }
        ), 401


    data = request.get_json(
        silent=True
    ) or {}


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
                "status":
                    "error",
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
                "status":
                    "error",
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
                "status":
                    "error",
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
                        "status":
                            "error",
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
            "status":
                "ok",
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
                "ok":
                    False
            }
        ), 401


    data = request.get_json(
        silent=True
    ) or {}


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
                "ok":
                    False
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
                "ok":
                    True
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
                "ok":
                    True
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
                "ok":
                    True
            }
        )


    if not password_hash:

        return jsonify(
            {
                "ok":
                    False
            }
        )


    if check_password_hash(
        password_hash,
        password
    ):

        return jsonify(
            {
                "ok":
                    True
            }
        )


    return jsonify(
        {
            "ok":
                False
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
