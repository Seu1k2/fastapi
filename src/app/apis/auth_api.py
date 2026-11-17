
import os
import secrets
from dotenv import load_dotenv
from fastapi import (
    APIRouter,
    Query,
    Depends,
    Response,
    Request,
    HTTPException,
)
from fastapi.responses import RedirectResponse
from urllib.parse import urlencode
import httpx

from app.schemas.common_schema import ApiResponseDTO
from app.schemas.member_schema import MemberClaimDTO
from app.enums.member_enum import MemberProvider
from app.schemas.auth_schema import (
    JwtTokenDTO,
    LoginRequestDTO,
    SocialLoginRequestDTO,
)
from app.services.auth_service import AuthService, get_auth_service
from app.dependencies.auth_dependency import get_current_member, get_tokens


load_dotenv()
router = APIRouter()


# ==========================================
# 환경 변수
# ==========================================

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# Google
GOOGLE_AUTH_URL = os.getenv("GOOGLE_AUTH_URL")
GOOGLE_TOKEN_URL = os.getenv("GOOGLE_TOKEN_URL")
GOOGLE_USERINFO_URL = os.getenv("GOOGLE_USERINFO_URL")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

# Kakao
KAKAO_CLIENT_ID = os.getenv("KAKAO_CLIENT_ID")
KAKAO_CLIENT_SECRET = os.getenv("KAKAO_CLIENT_SECRET")
KAKAO_REDIRECT_URI = os.getenv("KAKAO_REDIRECT_URI")
KAKAO_AUTH_URL = os.getenv("KAKAO_AUTH_URL")
KAKAO_TOKEN_URL = os.getenv("KAKAO_TOKEN_URL")
KAKAO_USERINFO_URL = os.getenv("KAKAO_USERINFO_URL")

# Naver
NAVER_CLIENT_ID = os.getenv("NAVER_CLIENT_ID")
NAVER_CLIENT_SECRET = os.getenv("NAVER_CLIENT_SECRET")
NAVER_REDIRECT_URI = os.getenv("NAVER_REDIRECT_URI")
NAVER_AUTH_URL = os.getenv("NAVER_AUTH_URL")
NAVER_TOKEN_URL = os.getenv("NAVER_TOKEN_URL")
NAVER_USERINFO_URL = os.getenv("NAVER_USERINFO_URL")


# ==========================================
# 일반 로그인
# ==========================================

@router.post(
    "/login",
    response_model=ApiResponseDTO,
    summary="로컬 로그인",
    responses={
        200: {"description": "로그인 성공"},
        400: {"description": "아이디 또는 비밀번호 불일치"},
        404: {"description": "존재하지 않는 회원"},
    },
)
async def login(
    login_member: LoginRequestDTO,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
):
    login_member.member_provider = MemberProvider.LOCAL.value
    tokens = await auth_service.login(login_member)

    response.set_cookie(
        key="access_token",
        value=tokens.access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60 * 24,
    )

    response.set_cookie(
        key="refresh_token",
        value=tokens.refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60 * 24 * 30,
    )

    return ApiResponseDTO(
        success=True,
        message="로그인 성공",
    )


# ==========================================
# 구글 로그인
# ==========================================

@router.get("/google", summary="구글 로그인")
async def google_login():
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    }

    url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    return RedirectResponse(url)


@router.get("/google/callback", summary="구글 로그인 콜백")
async def google_login_callback(
    code: str,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
):
    async with httpx.AsyncClient() as client:
        token_res = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
        )

        token_data = token_res.json()
        access_token = token_data.get("access_token")

        user_res = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )

    user = user_res.json()

    user_params = {
        "member_email": user.get("email"),
        "member_provider": MemberProvider.GOOGLE.value,
        "member_provider_id": user.get("sub"),
    }

    return await _handle_social_login(user_params, auth_service)


# ==========================================
# 카카오 로그인
# ==========================================

@router.get("/kakao", summary="카카오 로그인 리다이렉트")
async def kakao_login():
    params = {
        "client_id": KAKAO_CLIENT_ID,
        "redirect_uri": KAKAO_REDIRECT_URI,
        "response_type": "code",
    }

    url = f"{KAKAO_AUTH_URL}?{urlencode(params)}"
    return RedirectResponse(url)


@router.get("/kakao/callback", summary="카카오 로그인 콜백")
async def kakao_login_callback(
    code: str,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
):
    async with httpx.AsyncClient() as client:
        token_res = await client.post(
            KAKAO_TOKEN_URL,
            data={
                "code": code,
                "client_id": KAKAO_CLIENT_ID,
                "client_secret": KAKAO_CLIENT_SECRET,
                "redirect_uri": KAKAO_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
        )

        token_data = token_res.json()
        access_token = token_data.get("access_token")

        user_res = await client.get(
            KAKAO_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )

    user = user_res.json()
    kakao_account = user.get("kakao_account") or {}

    member_email = kakao_account.get("email")
    member_profile_id = str(user.get("id"))

    user_params = {
        "member_email": member_email,
        "member_provider": MemberProvider.KAKAO.value,
        "member_provider_id": member_profile_id,
    }

    return await _handle_social_login(user_params, auth_service)


# ==========================================
# 네이버 로그인
# ==========================================

@router.get("/naver", summary="네이버 로그인 리다이렉트")
async def naver_login():

    # CSRF 방지를 위한 임의의 state 생성
    state = secrets.token_urlsafe(32)

    params = {
        "response_type": "code",
        "client_id": NAVER_CLIENT_ID,
        "redirect_uri": NAVER_REDIRECT_URI,
        "state": state,
    }

    url = f"{NAVER_AUTH_URL}?{urlencode(params)}"

    redirect_response = RedirectResponse(url)

    # 콜백에서 state를 비교할 수 있도록 쿠키에 저장
    redirect_response.set_cookie(
        key="naver_oauth_state",
        value=state,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=300,
        path="/",
    )

    return redirect_response


@router.get("/naver/callback", summary="네이버 로그인 콜백")
async def naver_login_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    auth_service: AuthService = Depends(get_auth_service),
):

    # 네이버에서 인증을 거절한 경우
    if error:
        raise HTTPException(
            status_code=400,
            detail=f"네이버 인증 실패: {error}",
        )

    # state 검증
    saved_state = request.cookies.get("naver_oauth_state")

    if (
        not saved_state
        or not state
        or not secrets.compare_digest(saved_state, state)
    ):
        raise HTTPException(
            status_code=400,
            detail="네이버 로그인 state 검증 실패",
        )

    if not code:
        raise HTTPException(
            status_code=400,
            detail="네이버 인증 코드가 없습니다.",
        )

    # 네이버 Access Token 발급
    async with httpx.AsyncClient(timeout=10.0) as client:
        token_res = await client.post(
            NAVER_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "client_id": NAVER_CLIENT_ID,
                "client_secret": NAVER_CLIENT_SECRET,
                "code": code,
                "state": state,
            },
        )

        if token_res.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail="네이버 토큰 발급 요청 실패",
            )

        token_data = token_res.json()
        access_token = token_data.get("access_token")

        if not access_token:
            raise HTTPException(
                status_code=400,
                detail="네이버 Access Token 발급 실패",
            )

        # 네이버 회원 정보 조회
        user_res = await client.get(
            NAVER_USERINFO_URL,
            headers={
                "Authorization": f"Bearer {access_token}"
            },
        )

        if user_res.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail="네이버 회원 정보 조회 실패",
            )

        user = user_res.json()

    naver_user = user.get("response") or {}

    member_email = naver_user.get("email")
    member_profile_id = naver_user.get("id")

    if not member_email or not member_profile_id:
        raise HTTPException(
            status_code=400,
            detail="네이버 회원 정보가 부족합니다.",
        )

    user_params = {
        "member_email": member_email,
        "member_provider": MemberProvider.NAVER.value,
        "member_provider_id": str(member_profile_id),
    }

    # 기존 회원 로그인 또는 신규 회원 처리
    redirect_response = await _handle_social_login_or_join(
        user_params,
        auth_service,
    )

    # 사용한 state 쿠키 삭제
    redirect_response.delete_cookie(
        key="naver_oauth_state",
        path="/",
    )

    return redirect_response


# ==========================================
# 로그아웃
# ==========================================

@router.post(
    "/logout",
    summary="로그아웃",
    response_model=ApiResponseDTO,
)
async def logout(
    response: Response,
    member_claims: MemberClaimDTO = Depends(get_current_member),
    tokens: JwtTokenDTO = Depends(get_tokens),
    auth_service: AuthService = Depends(get_auth_service),
):
    await auth_service.logout(member_claims.id, tokens)

    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    return ApiResponseDTO(
        success=True,
        message="로그아웃 성공",
    )


# ==========================================
# 토큰 재발급
# ==========================================

@router.get(
    "/refresh",
    response_model=ApiResponseDTO,
    summary="토큰 재발급",
)
async def refresh(
    response: Response,
    tokens: JwtTokenDTO = Depends(get_tokens),
    auth_service: AuthService = Depends(get_auth_service),
):
    refresh_token = tokens.refresh_token

    try:
        access_token = await auth_service.refresh(refresh_token)

        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=60 * 60 * 24,
        )

        return ApiResponseDTO(
            success=True,
            message="Access Token 재발급 성공",
        )

    except Exception:
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")

        return ApiResponseDTO(
            success=False,
            message="Refresh Token 만료",
        )


# ==========================================
# 소셜 로그인 공통 처리
# ==========================================

async def _handle_social_login(
    user_params: dict,
    auth_service: AuthService,
):
    social_member = SocialLoginRequestDTO.model_validate(user_params)
    tokens = await auth_service.social_login_or_none(social_member)

    # 비회원은 추가 회원가입 페이지로 이동
    if not tokens:
        url = f"{FRONTEND_URL}/join-additional?{urlencode(user_params)}"
        return RedirectResponse(url)

    # 기존 회원 로그인
    redirect_response = RedirectResponse(url=FRONTEND_URL)

    redirect_response.set_cookie(
        key="access_token",
        value=tokens.access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60 * 24,
    )

    redirect_response.set_cookie(
        key="refresh_token",
        value=tokens.refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60 * 24 * 30,
    )

    return redirect_response


async def _handle_social_login_or_join(
    user_params: dict,
    auth_service: AuthService,
):
    social_member = SocialLoginRequestDTO.model_validate(user_params)
    tokens = await auth_service.social_login_or_join(social_member)

    redirect_response = RedirectResponse(url=FRONTEND_URL)

    redirect_response.set_cookie(
        key="access_token",
        value=tokens.access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60 * 24,
    )

    redirect_response.set_cookie(
        key="refresh_token",
        value=tokens.refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60 * 24 * 30,
    )

    return redirect_response
