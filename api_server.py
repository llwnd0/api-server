import os
import sys
import time
import json
import asyncio
import logging
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import base64
import jwt
from jwt.exceptions import InvalidTokenError
import httpx
import ssl

# Analytics path no longer needed - using LMArenaBridge instead

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse, HTMLResponse
from pydantic import BaseModel, Field
import uvicorn
from dotenv import load_dotenv
import urllib.parse
import stripe
from supabase import create_client, Client

# --- Configuration ---
DEBUG_MODE = False
API_VERSION = "1.0.0"
MAX_CONCURRENT_BOTS = 10  # Maximum bots running simultaneously
BOT_TIMEOUT = 300  # 5 minutes timeout for bot operations

# --- LMArenaBridge Configuration ---
LMARENA_BRIDGE_URL = "http://localhost:5102"  # LMArenaBridge API endpoint
LMARENA_BRIDGE_TIMEOUT = 60  # Timeout for LMArenaBridge calls

# --- Load environment variables ---
load_dotenv()
CLIENT_ID = os.getenv("TWITTER_CLIENT_ID")
CLIENT_SECRET = os.getenv("TWITTER_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "https://api.costras.com/auth/callback")
AUTH_URL = "https://twitter.com/i/oauth2/authorize"
TOKEN_URL = "https://api.twitter.com/2/oauth2/token"
SCOPES = "tweet.read users.read offline.access"

# --- Stripe Configuration ---
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY
    print("Stripe API key loaded")
else:
    print("Warning: STRIPE_SECRET_KEY not found")

# --- Supabase Configuration ---
# Project URL for database operations
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://sjsuwthvozuzabktkcxu.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

# OAuth callback URL (for Google login)
OAUTH_REDIRECT_URI = os.getenv("REDIRECT_URI", "https://sjsuwthvozuzabktkcxu.supabase.co/auth/v1/callback")

# Configure httpx client to handle SSL issues
# Create SSL context that's more permissive for development
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# Create httpx client with custom SSL configuration
httpx_client = httpx.AsyncClient(
    verify=False,  # Disable SSL verification for development
    timeout=30.0
)

# Initialize Supabase client with minimal configuration
if SUPABASE_KEY:
    try:
        # Create client with minimal options to avoid proxy conflicts
        supabase: Client = create_client(
            supabase_url=SUPABASE_URL,
            supabase_key=SUPABASE_KEY
        )
        print("Supabase client loaded successfully")
    except Exception as e:
        print(f"Warning: Failed to load Supabase client: {e}")
        supabase = None
else:
    print("Warning: SUPABASE_SERVICE_ROLE_KEY not found")
    supabase = None

# --- Helper Functions ---
def get_user_twitter_tokens_from_supabase(user_id: str) -> Optional[Dict[str, Any]]:
    """Get user's Twitter tokens from Supabase using user_id"""
    try:
        if not supabase:
            debug_print("Supabase client not available", "ERROR")
            return None
            
        # Get user's Twitter tokens from Supabase
        user_response = supabase.table('users').select(
            'twitter_auth_token, twitter_ct0_token, twitter_handle, twitter_display_name, twitter_profile_image_url'
        ).eq('id', user_id).execute()
        
        if not user_response.data:
            debug_print(f"No user found with ID: {user_id}", "WARNING")
            return None
        
        user_data = user_response.data[0]
        
        # Check if user has Twitter tokens
        if not user_data.get('twitter_auth_token'):
            debug_print(f"No Twitter tokens found for user: {user_id}", "WARNING")
            return None
        
        return {
            "auth_token": user_data.get('twitter_auth_token'),
            "ct0_token": user_data.get('twitter_ct0_token'),
            "user_handle": user_data.get('twitter_handle'),
            "display_name": user_data.get('twitter_display_name'),
            "profile_image_url": user_data.get('twitter_profile_image_url')
        }
        
    except Exception as e:
        debug_print(f"Error getting Twitter tokens for user {user_id}: {str(e)}", "ERROR")
        return None

# --- Logging setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler('api_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def debug_print(message: str, level: str = "INFO", force: bool = False):
    """Print debug message to both console and log file"""
    if DEBUG_MODE or force:
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[{timestamp}] {message}")
        if level == "INFO":
            logger.info(message)
        elif level == "ERROR":
            logger.error(message)
        elif level == "WARNING":
            logger.warning(message)
        elif level == "DEBUG":
            logger.debug(message)

# JWT Configuration
def generate_secure_jwt_secret():
    """Generate a secure JWT secret if none is provided"""
    import secrets
    return secrets.token_urlsafe(32)

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET or JWT_SECRET == "your-super-secret-jwt-key-change-this-in-production":
    JWT_SECRET = generate_secure_jwt_secret()
    debug_print(f"Generated new JWT_SECRET: {JWT_SECRET[:20]}...", force=True)

# Get Supabase JWT secret from environment
# This should be the same JWT secret that Supabase uses to sign tokens
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")
if not SUPABASE_JWT_SECRET:
    # Try to get it from SUPABASE_ANON_KEY as fallback (not ideal but works for development)
    SUPABASE_JWT_SECRET = os.getenv("SUPABASE_ANON_KEY")
    if SUPABASE_JWT_SECRET:
        debug_print("Using SUPABASE_ANON_KEY as JWT secret (development mode)", "WARNING", force=True)
    else:
        debug_print("WARNING: SUPABASE_JWT_SECRET not configured - JWT verification will be limited", "WARNING", force=True)

# --- FastAPI App Setup ---
app = FastAPI(
    title="Twitter Bot API",
    description="API for controlling Twitter outreach bots",
    version=API_VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# --- CORS Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this properly for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Security ---
security = HTTPBearer()

# --- Data Models ---
class BotConfig(BaseModel):
    """Configuration for a bot instance"""
    user_id: str = Field(..., description="Unique user identifier")
    twitter_cookie: Optional[str] = Field(None, description="Twitter session cookie")
    max_actions_per_hour: int = Field(default=15, description="Maximum actions per hour")
    follow_limit: int = Field(default=5, description="Maximum follows per hour")
    ai_api_key: Optional[str] = Field(None, description="AI API key for analysis")
    custom_prompt: Optional[str] = Field(None, description="Custom AI prompt")

class BotStatus(BaseModel):
    """Status of a bot instance"""
    user_id: str
    status: str  # "running", "stopped", "error", "starting", "stopping"
    process_id: Optional[int] = None
    start_time: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    actions_today: int = 0
    follows_today: int = 0
    replies_today: int = 0
    errors: List[str] = []

class BotLog(BaseModel):
    """Log entry for a bot"""
    timestamp: datetime
    level: str
    message: str
    user_id: str

class StartBotRequest(BaseModel):
    """Request to start a bot"""
    config: BotConfig

class StopBotRequest(BaseModel):
    """Request to stop a bot"""
    user_id: str

class UpdateConfigRequest(BaseModel):
    """Request to update bot configuration"""
    user_id: str
    config: BotConfig

# --- Global State Management ---
class BotManager:
    """Manages all running bot instances"""
    
    def __init__(self):
        self.bots: Dict[str, Dict[str, Any]] = {}
        self.logs: Dict[str, List[BotLog]] = {}
        self.max_bots = MAX_CONCURRENT_BOTS
        
    def can_start_bot(self, user_id: str) -> bool:
        """Check if a new bot can be started"""
        if user_id in self.bots:
            return False  # User already has a bot running
        if len(self.bots) >= self.max_bots:
            return False  # Maximum bots reached
        return True
        
    def start_bot(self, user_id: str, config: BotConfig) -> bool:
        """Start a bot for a user"""
        try:
            if not self.can_start_bot(user_id):
                return False
                
            debug_print(f"Starting bot for user {user_id}")
            
            # Create bot directory and config file
            bot_dir = Path(f"bots/{user_id}")
            bot_dir.mkdir(parents=True, exist_ok=True)
            
            # Save configuration
            config_file = bot_dir / "config.json"
            config_dict = config.dict()
            config_dict["user_id"] = user_id
            config_dict["created_at"] = datetime.now().isoformat()
            
            with open(config_file, 'w') as f:
                json.dump(config_dict, f, indent=2)
            
            # Start bot process
            env = os.environ.copy()
            env["USER_ID"] = user_id
            env["BOT_CONFIG_PATH"] = str(config_file)
            
            # Get user's Twitter tokens from Supabase
            twitter_tokens = get_user_twitter_tokens_from_supabase(user_id)
            if twitter_tokens:
                env["TWITTER_AUTH_TOKEN"] = twitter_tokens["auth_token"]
                env["TWITTER_CT0_TOKEN"] = twitter_tokens["ct0_token"]
                env["TWITTER_HANDLE"] = twitter_tokens["user_handle"]
                debug_print(f"Twitter tokens loaded for user {user_id}: @{twitter_tokens['user_handle']}")
            else:
                debug_print(f"Warning: No Twitter tokens found for user {user_id}", "WARNING")
            
            # Add Twitter cookie to environment if provided (fallback)
            if config.twitter_cookie:
                env["SESSION_COOKIE"] = config.twitter_cookie
                
            # Add AI API key if provided
            if config.ai_api_key:
                env["AI_API_KEY"] = config.ai_api_key
            
            # Start the bot script
            process = subprocess.Popen(
                [sys.executable, "twitter_stealth_bot.py"],
                cwd=os.getcwd(),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Store bot information
            self.bots[user_id] = {
                "process": process,
                "config": config,
                "status": "running",
                "start_time": datetime.now(),
                "last_activity": datetime.now(),
                "actions_today": 0,
                "follows_today": 0,
                "replies_today": 0,
                "errors": []
            }
            
            # Initialize logs for this user
            self.logs[user_id] = []
            
            debug_print(f"Bot started successfully for user {user_id} (PID: {process.pid})")
            return True
            
        except Exception as e:
            debug_print(f"Error starting bot for user {user_id}: {str(e)}", "ERROR")
            return False
    
    def stop_bot(self, user_id: str) -> bool:
        """Stop a bot for a user"""
        try:
            if user_id not in self.bots:
                return False
                
            debug_print(f"Stopping bot for user {user_id}")
            
            bot_info = self.bots[user_id]
            process = bot_info["process"]
            
            # Terminate the process
            process.terminate()
            
            # Wait for graceful shutdown
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # Force kill if it doesn't stop gracefully
                process.kill()
                process.wait()
            
            # Update status
            bot_info["status"] = "stopped"
            bot_info["last_activity"] = datetime.now()
            
            debug_print(f"Bot stopped successfully for user {user_id}")
            return True
            
        except Exception as e:
            debug_print(f"Error stopping bot for user {user_id}: {str(e)}", "ERROR")
            return False
    
    def get_bot_status(self, user_id: str) -> Optional[BotStatus]:
        """Get status of a bot"""
        if user_id not in self.bots:
            return None
            
        bot_info = self.bots[user_id]
        process = bot_info["process"]
        
        # Check if process is still running
        if process.poll() is not None:
            bot_info["status"] = "stopped"
        
        return BotStatus(
            user_id=user_id,
            status=bot_info["status"],
            process_id=process.pid if process.poll() is None else None,
            start_time=bot_info["start_time"],
            last_activity=bot_info["last_activity"],
            actions_today=bot_info["actions_today"],
            follows_today=bot_info["follows_today"],
            replies_today=bot_info["replies_today"],
            errors=bot_info["errors"]
        )
    
    def get_all_bots_status(self) -> List[BotStatus]:
        """Get status of all bots"""
        return [self.get_bot_status(user_id) for user_id in self.bots.keys()]
    
    def update_bot_activity(self, user_id: str, action_type: str = "action"):
        """Update bot activity counters"""
        if user_id in self.bots:
            self.bots[user_id]["last_activity"] = datetime.now()
            self.bots[user_id]["actions_today"] += 1
            
            if action_type == "follow":
                self.bots[user_id]["follows_today"] += 1
            elif action_type == "reply":
                self.bots[user_id]["replies_today"] += 1
    
    def add_bot_log(self, user_id: str, level: str, message: str):
        """Add a log entry for a bot"""
        if user_id not in self.logs:
            self.logs[user_id] = []
            
        log_entry = BotLog(
            timestamp=datetime.now(),
            level=level,
            message=message,
            user_id=user_id
        )
        
        self.logs[user_id].append(log_entry)
        
        # Keep only last 100 logs per user
        if len(self.logs[user_id]) > 100:
            self.logs[user_id] = self.logs[user_id][-100:]
    
    def get_bot_logs(self, user_id: str, limit: int = 50) -> List[BotLog]:
        """Get logs for a specific bot"""
        if user_id not in self.logs:
            return []
        return self.logs[user_id][-limit:]
    
    def cleanup_stopped_bots(self):
        """Clean up stopped bot processes"""
        stopped_users = []
        for user_id, bot_info in self.bots.items():
            if bot_info["process"].poll() is not None:
                stopped_users.append(user_id)
        
        for user_id in stopped_users:
            debug_print(f"Cleaning up stopped bot for user {user_id}")
            del self.bots[user_id]

# Initialize bot manager
bot_manager = BotManager()

# --- Authentication (JWT-based with Supabase integration) ---
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Verify JWT token from Supabase and return user_id"""
    try:
        token = credentials.credentials
        
        # Special case for testing
        if token == "test":
            debug_print("Test token used - bypassing authentication for testing", "WARNING")
            return "test-user-id"
        
        # Try to decode JWT token
        try:
            # First try with Supabase JWT secret
            if SUPABASE_JWT_SECRET and SUPABASE_JWT_SECRET != "your-supabase-jwt-secret":
                try:
                    decoded = jwt.decode(
                        token, 
                        SUPABASE_JWT_SECRET, 
                        algorithms=["HS256"],
                        options={"verify_signature": True}
                    )
                    user_id = decoded.get('sub')
                    if user_id:
                        debug_print(f"Authenticated user via Supabase JWT: {user_id}")
                        return user_id
                except Exception as e:
                    debug_print(f"JWT verification failed: {e}", "WARNING")
                    pass
            
            # Fallback: decode without verification (development only)
            decoded_unverified = jwt.decode(token, options={"verify_signature": False})
            user_id = decoded_unverified.get('sub')
            
            if user_id:
                debug_print(f"WARNING: JWT signature not verified, but allowing user: {user_id}", "WARNING")
                return user_id
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token: no user ID found"
                )
                
        except Exception as e:
            debug_print(f"Failed to decode JWT token: {str(e)}", "ERROR")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Authentication error: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

# --- API Endpoints ---

@app.get("/")
async def root():
    raise HTTPException(status_code=404, detail="Not found")

# --- Twitter OAuth 2.0 endpoints ---
@app.get("/login")
def login():
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": "teststate123",  # TODO: Gebruik random & uniek in productie!
        "code_challenge": "challenge",  # TODO: Implementeer echte PKCE in productie
        "code_challenge_method": "plain"
    }
    url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url)

@app.get("/auth/callback")
async def auth_callback(request: Request):
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code:
        return {"error": "No code in callback"}
    # Token exchange met Basic Auth header
    basic_auth = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {basic_auth}"
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            TOKEN_URL,
            data={
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": REDIRECT_URI,
                "code_verifier": "challenge",  # TODO: Implementeer echte PKCE in productie
            },
            headers=headers,
        )
        token_data = resp.json()
    # TODO: Sla token_data veilig op aan je user, nu alleen tonen voor test
    return token_data

@app.get("/oauth-test")
def oauth_test():
    return HTMLResponse("""
        <h2>Login met Twitter</h2>
        <a href='/login'>Login met Twitter</a>
    """)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "active_bots": len(bot_manager.bots),
        "max_bots": bot_manager.max_bots
    }

@app.get("/auth/test-extension")
async def test_extension_auth():
    """Test endpoint for extension authentication flow"""
    return {
        "status": "extension_auth_ready",
        "endpoints": {
            "verify_extension_token": "/auth/verify-extension-token",
            "verify_website_session": "/auth/verify-website-session"
        },
        "timestamp": datetime.now().isoformat()
    }

@app.post("/twitter/connect", response_model=Dict[str, Any])
async def connect_twitter(
    request: Request,
    user_id: str = Depends(verify_token)
):
    """Connect Twitter account to user"""
    try:
        # Get request body
        body = await request.json()
        auth_token = body.get('auth_token')
        ct0 = body.get('ct0')
        
        if not auth_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="auth_token is required"
            )
        
        # Use Playwright to get Twitter user info
        try:
            from playwright.async_api import async_playwright
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                
                # Set cookies for authentication
                await context.add_cookies([
                    {
                        "name": "auth_token",
                        "value": auth_token,
                        "domain": ".twitter.com",
                        "path": "/"
                    }
                ])
                
                if ct0:
                    await context.add_cookies([
                        {
                            "name": "ct0",
                            "value": ct0,
                            "domain": ".twitter.com",
                            "path": "/"
                        }
                    ])
                
                # Navigate to Twitter profile to get user info
                page = await context.new_page()
                await page.goto("https://twitter.com/home")
                
                # Wait for page to load and get user info
                try:
                    # Get Twitter handle from profile
                    handle_element = await page.wait_for_selector('[data-testid="UserName"] span', timeout=10000)
                    twitter_handle = await handle_element.text_content()
                    
                    # Get display name
                    display_name_element = await page.wait_for_selector('[data-testid="UserName"] span:first-child', timeout=5000)
                    display_name = await display_name_element.text_content()
                    
                    # Get profile image
                    profile_image_element = await page.wait_for_selector('[data-testid="UserAvatar-Container-unknown"] img', timeout=5000)
                    profile_image_url = await profile_image_element.get_attribute('src')
                    
                except Exception as e:
                    debug_print(f"Could not get Twitter user info: {e}", "WARNING")
                    twitter_handle = "unknown"
                    display_name = "Unknown User"
                    profile_image_url = None
                
                await browser.close()
                
        except ImportError:
            debug_print("Playwright not available, using fallback", "WARNING")
            twitter_handle = "unknown"
            display_name = "Unknown User"
            profile_image_url = None
        
        # Store Twitter connection in database
        try:
            if supabase:
                # Update user with Twitter info
                result = supabase.table('users').update({
                    'twitter_handle': twitter_handle,
                    'twitter_display_name': display_name,
                    'twitter_profile_image_url': profile_image_url,
                    'twitter_auth_token': auth_token,
                    'twitter_ct0_token': ct0,
                    'twitter_connected_at': datetime.now().isoformat(),
                    'twitter_last_sync': datetime.now().isoformat()
                }).eq('id', user_id).execute()
                
                debug_print(f"Twitter connection stored for user {user_id}: {twitter_handle}", "INFO")
                
        except Exception as e:
            debug_print(f"Failed to store Twitter connection: {e}", "ERROR")
        
        return {
            "success": True,
            "message": f"Twitter account @{twitter_handle} connected successfully",
            "user_id": user_id,
            "twitter_handle": twitter_handle,
            "display_name": display_name,
            "status": "connected"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error in connect_twitter endpoint: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.post("/bots/start", response_model=Dict[str, Any])
async def start_bot(
    request: StartBotRequest,
    user_id: str = Depends(verify_token)
):
    """Start a bot for the authenticated user"""
    try:
        # Override user_id from token
        request.config.user_id = user_id
        
        if not bot_manager.can_start_bot(user_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Bot already running for this user or maximum bots reached"
            )
        
        success = bot_manager.start_bot(user_id, request.config)
        
        if success:
            bot_manager.add_bot_log(user_id, "INFO", "Bot started successfully")
            return {
                "success": True,
                "message": "Bot started successfully",
                "user_id": user_id,
                "status": "running"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to start bot"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error in start_bot endpoint: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.post("/bots/stop", response_model=Dict[str, Any])
async def stop_bot(
    request: StopBotRequest,
    user_id: str = Depends(verify_token)
):
    """Stop a bot for the authenticated user"""
    try:
        # Verify user owns this bot
        if request.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to stop this bot"
            )
        
        success = bot_manager.stop_bot(user_id)
        
        if success:
            bot_manager.add_bot_log(user_id, "INFO", "Bot stopped successfully")
            return {
                "success": True,
                "message": "Bot stopped successfully",
                "user_id": user_id,
                "status": "stopped"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Bot not found or already stopped"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error in stop_bot endpoint: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/bots/status/{user_id}", response_model=BotStatus)
async def get_bot_status(
    user_id: str,
    authenticated_user_id: str = Depends(verify_token)
):
    """Get status of a specific bot"""
    try:
        # Verify user owns this bot
        if user_id != authenticated_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view this bot status"
            )
        
        status = bot_manager.get_bot_status(user_id)
        
        if status is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Bot not found"
            )
        
        return status
        
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error in get_bot_status endpoint: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/bots/status", response_model=List[BotStatus])
async def get_all_bots_status(authenticated_user_id: str = Depends(verify_token)):
    """Get status of all bots (admin endpoint)"""
    try:
        # In production, check if user is admin
        # For now, return all bots
        return bot_manager.get_all_bots_status()
        
    except Exception as e:
        debug_print(f"Error in get_all_bots_status endpoint: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/bots/logs/{user_id}", response_model=List[BotLog])
async def get_bot_logs(
    user_id: str,
    limit: int = 50,
    authenticated_user_id: str = Depends(verify_token)
):
    """Get logs for a specific bot"""
    try:
        # Verify user owns this bot
        if user_id != authenticated_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view this bot logs"
            )
        
        logs = bot_manager.get_bot_logs(user_id, limit)
        return logs
        
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error in get_bot_logs endpoint: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.put("/bots/config", response_model=Dict[str, Any])
async def update_bot_config(
    request: UpdateConfigRequest,
    user_id: str = Depends(verify_token)
):
    """Update bot configuration"""
    try:
        # Verify user owns this bot
        if request.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to update this bot config"
            )
        
        # Check if bot is running
        if user_id not in bot_manager.bots:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Bot not found"
            )
        
        # Update configuration
        bot_manager.bots[user_id]["config"] = request.config
        
        # Save updated config to file
        bot_dir = Path(f"bots/{user_id}")
        config_file = bot_dir / "config.json"
        
        config_dict = request.config.dict()
        config_dict["user_id"] = user_id
        config_dict["updated_at"] = datetime.now().isoformat()
        
        with open(config_file, 'w') as f:
            json.dump(config_dict, f, indent=2)
        
        bot_manager.add_bot_log(user_id, "INFO", "Bot configuration updated")
        
        return {
            "success": True,
            "message": "Bot configuration updated successfully",
            "user_id": user_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error in update_bot_config endpoint: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/stats", response_model=Dict[str, Any])
async def get_api_stats(authenticated_user_id: str = Depends(verify_token)):
    """Get API statistics"""
    try:
        total_bots = len(bot_manager.bots)
        running_bots = sum(1 for bot in bot_manager.bots.values() if bot["status"] == "running")
        
        total_actions = sum(bot["actions_today"] for bot in bot_manager.bots.values())
        total_follows = sum(bot["follows_today"] for bot in bot_manager.bots.values())
        total_replies = sum(bot["replies_today"] for bot in bot_manager.bots.values())
        
        return {
            "total_bots": total_bots,
            "running_bots": running_bots,
            "max_bots": bot_manager.max_bots,
            "total_actions_today": total_actions,
            "total_follows_today": total_follows,
            "total_replies_today": total_replies,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        debug_print(f"Error in get_api_stats endpoint: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/dashboard/status/{user_id}", response_model=Dict[str, Any])
async def get_dashboard_status(
    user_id: str,
    authenticated_user_id: str = Depends(verify_token)
):
    """Get comprehensive dashboard status for a user"""
    try:
        # Verify user owns this data
        if user_id != authenticated_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view this data"
            )
        
        # Get bot status
        bot_status = bot_manager.get_bot_status(user_id)
        
        # Get recent logs
        logs = bot_manager.get_bot_logs(user_id, limit=10)
        
        # Get stats
        stats = {
            "actions_today": bot_status.actions_today if bot_status else 0,
            "follows_today": bot_status.follows_today if bot_status else 0,
            "replies_today": bot_status.replies_today if bot_status else 0,
            "errors": bot_status.errors if bot_status else []
        }
        
        return {
            "user_id": user_id,
            "bot_status": bot_status.status if bot_status else "stopped",
            "bot_running": bot_status.status == "running" if bot_status else False,
            "stats": stats,
            "recent_activity": [
                {
                    "timestamp": log.timestamp.isoformat(),
                    "message": log.message,
                    "level": log.level
                } for log in logs
            ],
            "last_updated": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error in get_dashboard_status endpoint: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.post("/auth/token", response_model=Dict[str, Any])
async def generate_api_token(
    request: Request,
    user_id: str = Depends(verify_token)
):
    """Generate an API token for the authenticated user"""
    try:
        # Create a simple API token for this user
        # In production, this would be a proper JWT with expiration
        api_token = {
            "user_id": user_id,
            "exp": datetime.utcnow() + timedelta(days=30),  # 30 days expiration
            "iat": datetime.utcnow(),
            "type": "api_token"
        }
        
        # Encode as JWT
        token = jwt.encode(api_token, JWT_SECRET, algorithm="HS256")
        
        return {
            "success": True,
            "api_token": token,
            "user_id": user_id,
            "expires_in": 30 * 24 * 60 * 60  # 30 days in seconds
        }
        
    except Exception as e:
        debug_print(f"Error generating API token: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate API token"
        )

# --- Extension Authentication Endpoints ---

@app.post("/auth/verify-extension-token", response_model=Dict[str, Any])
async def verify_extension_token(request: Request):
    """
    Verify Chrome Extension authentication token and create website session
    Enables seamless transition from Chrome Extension to website
    """
    try:
        debug_print("Extension token verification request received", "INFO")
        
        # Get request body
        body = await request.json()
        extension_token = body.get('extension_token')
        user_email = body.get('user_email')
        
        if not extension_token or not user_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="extension_token and user_email are required"
            )
        
        debug_print(f"Verifying extension token for user: {user_email}", "INFO")
        
        # Verify with Supabase
        if not supabase:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Supabase client not available"
            )
        
        try:
            # Verify the user exists in Supabase
            debug_print(f"Querying Supabase for user: {user_email}", "INFO")
            
            # Try to query the users table directly (not auth.users)
            response = supabase.table('users').select('id, email, created_at').eq('email', user_email).execute()
            
            debug_print(f"Supabase response: {response}", "INFO")
            debug_print(f"Response data: {response.data}", "INFO")
            
            if not response.data:
                debug_print(f"No user found for email: {user_email}", "ERROR")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found in database"
                )
            
            user_data = response.data[0]
            debug_print(f"User verified: {user_data['id']}", "INFO")
            
            # Create website session token
            session_token = {
                "user_id": user_data['id'],
                "email": user_data['email'],
                "exp": datetime.utcnow() + timedelta(minutes=15),  # 15 minutes expiration
                "iat": datetime.utcnow(),
                "type": "website_session"
            }
            
            # Encode as JWT
            session_jwt = jwt.encode(session_token, JWT_SECRET, algorithm="HS256")
            
            # Store session in database (optional - for tracking)
            # Note: user_sessions table might not exist, so we'll skip this for now
            # In production, you would create this table in Supabase
            debug_print("Skipping session storage - user_sessions table not implemented", "INFO")
            
            debug_print(f"Website session created for user: {user_data['id']}", "INFO")
            
            return {
                "success": True,
                "session_token": session_jwt,
                "user_id": user_data['id'],
                "email": user_data['email'],
                "expires_in": 15 * 60,  # 15 minutes in seconds
                "redirect_url": "https://costras.com/dashboard"
            }
            
        except Exception as e:
            debug_print(f"Supabase verification error: {str(e)}", "ERROR")
            debug_print(f"Error type: {type(e)}", "ERROR")
            debug_print(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No details'}", "ERROR")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to verify user with database: {str(e)}"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Extension token verification error: {str(e)}", "ERROR")
        debug_print(f"Error type: {type(e)}", "ERROR")
        debug_print(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No details'}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to verify extension token: {str(e)}"
        )

@app.post("/auth/extension-connect", response_model=Dict[str, Any])
async def extension_connect(request: Request):
    """
    Record when Chrome Extension connects to the system
    Updates user's extension status in Supabase
    """
    try:
        debug_print("Extension connect request received", "INFO")
        
        # Get request body
        body = await request.json()
        user_email = body.get('user_email')
        extension_version = body.get('extension_version', '1.0.0')
        browser_info = body.get('browser_info', 'Chrome Extension')
        session_token = body.get('session_token')
        
        if not user_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="user_email is required"
            )
        
        debug_print(f"Recording extension connection for user: {user_email}", "INFO")
        
        # Update Supabase with extension connection
        if not supabase:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Supabase client not available"
            )
        
        try:
            # Get user ID from email
            user_response = supabase.table('users').select('id').eq('email', user_email).execute()
            
            if not user_response.data:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            user_id = user_response.data[0]['id']
            
            # Update user's extension status directly
            update_data = {
                'extension_connected': True,
                'extension_last_connected': datetime.utcnow().isoformat(),
                'extension_version': extension_version,
                'updated_at': datetime.utcnow().isoformat()
            }
            
            result = supabase.table('users').update(update_data).eq('id', user_id).execute()
            
            debug_print(f"Extension connection recorded: {result.data}", "INFO")
            
            return {
                "success": True,
                "message": "Extension connection recorded",
                "user_id": user_id,
                "extension_connected": True,
                "last_connected": datetime.now().isoformat()
            }
            
        except Exception as e:
            debug_print(f"Supabase update error: {str(e)}", "ERROR")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to record extension connection: {str(e)}"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Extension connect error: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to record extension connection: {str(e)}"
        )

@app.post("/auth/extension-disconnect", response_model=Dict[str, Any])
async def extension_disconnect(request: Request):
    """
    Record when Chrome Extension disconnects from the system
    Updates user's extension status in Supabase
    """
    try:
        debug_print("Extension disconnect request received", "INFO")
        
        # Get request body
        body = await request.json()
        user_email = body.get('user_email')
        
        if not user_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="user_email is required"
            )
        
        debug_print(f"Recording extension disconnection for user: {user_email}", "INFO")
        
        # Update Supabase with extension disconnection
        if not supabase:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Supabase client not available"
            )
        
        try:
            # Get user ID from email
            user_response = supabase.table('users').select('id').eq('email', user_email).execute()
            
            if not user_response.data:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            user_id = user_response.data[0]['id']
            
            # Call the disconnect_extension function
            result = supabase.rpc('disconnect_extension', {
                'p_user_id': user_id
            }).execute()
            
            debug_print(f"Extension disconnection recorded: {result.data}", "INFO")
            
            return {
                "success": True,
                "message": "Extension disconnection recorded",
                "user_id": user_id,
                "extension_connected": False
            }
            
        except Exception as e:
            debug_print(f"Supabase update error: {str(e)}", "ERROR")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to record extension disconnection: {str(e)}"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Extension disconnect error: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to record extension disconnection: {str(e)}"
        )

@app.get("/dashboard/extension-status/{user_id}", response_model=Dict[str, Any])
async def get_extension_status(user_id: str):
    """
    Get real-time extension connection status for a user
    Returns current extension status and connection history
    """
    try:
        debug_print(f"Getting extension status for user: {user_id}", "INFO")
        
        if not supabase:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Supabase client not available"
            )
        
        try:
            # Get user's extension status
            user_response = supabase.table('users').select(
                'extension_connected, extension_last_connected, extension_version, connection_method, session_origin'
            ).eq('id', user_id).execute()
            
            if not user_response.data:
                # Return default status for non-existent users
                return {
                    "success": True,
                    "extension_connected": False,
                    "last_connected": None,
                    "extension_version": None,
                    "connection_method": "manual",
                    "session_origin": "extension",
                    "active_sessions": [],
                    "session_count": 0,
                    "user_exists": False
                }
            
            user_data = user_response.data[0]
            
            # For now, return empty sessions since extension_sessions table doesn't exist
            active_sessions = []
            
            return {
                "success": True,
                "extension_connected": user_data.get('extension_connected', False),
                "last_connected": user_data.get('extension_last_connected'),
                "extension_version": user_data.get('extension_version'),
                "connection_method": user_data.get('connection_method', 'manual'),
                "session_origin": user_data.get('session_origin', 'website'),
                "active_sessions": active_sessions,
                "session_count": len(active_sessions)
            }
            
        except Exception as e:
            debug_print(f"Supabase query error: {str(e)}", "ERROR")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get extension status: {str(e)}"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Get extension status error: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get extension status: {str(e)}"
        )

@app.post("/auth/validate-extension-session", response_model=Dict[str, Any])
async def validate_extension_session(request: Request):
    """
    Validate a session created by the Chrome Extension
    Verifies session token and returns user information
    """
    try:
        debug_print("Extension session validation request received", "INFO")
        
        # Get request body
        body = await request.json()
        session_token = body.get('session_token')
        
        if not session_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="session_token is required"
            )
        
        debug_print("Validating extension session token", "INFO")
        
        try:
            # Decode and verify JWT token
            decoded_token = jwt.decode(session_token, JWT_SECRET, algorithms=["HS256"])
            
            # Check if token is expired
            if datetime.utcnow() > datetime.fromtimestamp(decoded_token['exp']):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session token expired"
                )
            
            # Check if token is from extension
            if decoded_token.get('type') != 'website_session':
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid session token type"
                )
            
            user_id = decoded_token.get('user_id')
            user_email = decoded_token.get('email')
            
            # Verify user exists in database
            if not supabase:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Supabase client not available"
                )
            
            user_response = supabase.table('users').select('id, email').eq('id', user_id).execute()
            
            if not user_response.data:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            debug_print(f"Extension session validated for user: {user_id}", "INFO")
            
            return {
                "success": True,
                "valid": True,
                "user_id": user_id,
                "email": user_email,
                "session_type": "extension",
                "expires_at": datetime.fromtimestamp(decoded_token['exp']).isoformat()
            }
            
        except jwt.InvalidTokenError as e:
            debug_print(f"Invalid JWT token: {str(e)}", "ERROR")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid session token"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Session validation error: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to validate session: {str(e)}"
        )

@app.post("/auth/verify-website-session", response_model=Dict[str, Any])
async def verify_website_session(request: Request):
    """
    Verify website session token and return user data for auto-login
    Used by costras.com website to verify session tokens
    """
    try:
        debug_print("Website session verification request received", "INFO")
        
        # Get request body
        body = await request.json()
        session_token = body.get('session_token')
        
        if not session_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="session_token is required"
            )
        
        try:
            # Decode and verify session token
            payload = jwt.decode(session_token, JWT_SECRET, algorithms=["HS256"])
            
            # Check if token is expired
            if datetime.utcnow() > datetime.fromtimestamp(payload['exp']):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session token expired"
                )
            
            # Check if it's a website session token
            if payload.get('type') != 'website_session':
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid session token type"
                )
            
            user_id = payload.get('user_id')
            email = payload.get('email')
            
            if not user_id or not email:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid session token"
                )
            
            debug_print(f"Website session verified for user: {user_id}", "INFO")
            
            # Return user data for website auto-login
            return {
                "success": True,
                "user_id": user_id,
                "email": email,
                "valid": True,
                "expires_at": datetime.fromtimestamp(payload['exp']).isoformat()
            }
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session token expired"
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid session token"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Website session verification error: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify website session"
        )

# --- Analytics Endpoints ---

@app.post("/analytics/track", response_model=Dict[str, Any])
async def track_analytics(
    request: Request,
    user_id: str = Depends(verify_token)
):
    """Track analytics data from the bot"""
    try:
        # Get analytics data from request body
        analytics_data = await request.json()
        
        # Add user_id to analytics data
        analytics_data['user_id'] = user_id
        
        # Store analytics data
        try:
            from analytics_database import get_database
            db = get_database()
            success = db.store_action(analytics_data)
            
            if success:
                return {"success": True, "message": "Analytics data tracked successfully"}
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to store analytics data"
                )
                
        except ImportError:
            debug_print("Analytics database not available", "WARNING")
            return {"success": True, "message": "Analytics tracking disabled"}
            
    except Exception as e:
        debug_print(f"Error tracking analytics: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to track analytics"
        )

@app.get("/analytics/dashboard/{user_id}", response_model=Dict[str, Any])
async def get_analytics_dashboard(
    user_id: str,
    authenticated_user_id: str = Depends(verify_token)
):
    """Get comprehensive analytics dashboard data"""
    try:
        # Verify user owns this data
        if user_id != authenticated_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view this data"
            )
        
        # Get analytics data
        try:
            from analytics_engine import get_analytics_engine
            engine = get_analytics_engine()
            engine.set_user_id(user_id)  # Set user_id for analytics engine
            analytics_data = engine.get_dashboard_data()
            
            if analytics_data:
                return analytics_data
            else:
                # Return empty analytics if no data available
                return {
                    "bot_performance": {
                        "status": "unknown",
                        "uptime": "0%",
                        "actions_today": 0,
                        "success_rate": "0%",
                        "avg_response_time": "0s",
                        "errors": 0
                    },
                    "engagement_metrics": {
                        "engagement_rate": "0%",
                        "follower_growth": 0,
                        "follower_growth_rate": "0%",
                        "actions_trend": "No data",
                        "engagement_trend": "No data"
                    },
                    "recent_actions": [],
                    "trends": {
                        "actions_trend": "No data",
                        "success_rate_trend": "No data",
                        "best_hour": "No data"
                    },
                    "insights": {
                        "recommendation": "No data available",
                        "warning": "No data available"
                    }
                }
                
        except ImportError:
            debug_print("Analytics engine not available", "WARNING")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Analytics service not available"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error getting analytics dashboard: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get analytics dashboard"
        )

@app.get("/analytics/performance/{user_id}", response_model=Dict[str, Any])
async def get_analytics_performance(
    user_id: str,
    days: int = 7,
    authenticated_user_id: str = Depends(verify_token)
):
    """Get performance analytics for a user"""
    try:
        # Verify user owns this data
        if user_id != authenticated_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view this data"
            )
        
        # Get performance data
        try:
            from analytics_engine import get_analytics_engine
            engine = get_analytics_engine()
            engine.set_user_id(user_id)
            
            performance = engine.get_performance_metrics(days)
            engagement = engine.get_engagement_metrics(days)
            
            return {
                "performance": {
                    "total_actions": performance.total_actions,
                    "successful_actions": performance.successful_actions,
                    "failed_actions": performance.failed_actions,
                    "success_rate": performance.success_rate,
                    "avg_response_time": performance.avg_response_time,
                    "errors_today": performance.errors_today,
                    "rate_limits_hit": performance.rate_limits_hit,
                    "uptime_percentage": performance.uptime_percentage
                },
                "engagement": {
                    "engagement_rate": engagement.engagement_rate,
                    "follower_growth": engagement.follower_growth,
                    "follower_growth_rate": engagement.follower_growth_rate,
                    "actions_today": engagement.actions_today,
                    "actions_trend": engagement.actions_trend,
                    "engagement_trend": engagement.engagement_trend
                },
                "period_days": days
            }
            
        except ImportError:
            debug_print("Analytics engine not available", "WARNING")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Analytics service not available"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error getting performance analytics: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get performance analytics"
        )

@app.get("/analytics/actions/{user_id}", response_model=List[Dict[str, Any]])
async def get_analytics_actions(
    user_id: str,
    limit: int = 20,
    authenticated_user_id: str = Depends(verify_token)
):
    """Get recent actions for a user"""
    try:
        # Verify user owns this data
        if user_id != authenticated_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to view this data"
            )
        
        # Get recent actions
        try:
            from analytics_engine import get_analytics_engine
            engine = get_analytics_engine()
            engine.set_user_id(user_id)  # Set user_id for analytics engine
            actions = engine.get_recent_actions(limit)
            return actions
            
        except ImportError:
            debug_print("Analytics engine not available", "WARNING")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Analytics service not available"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error getting recent actions: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get recent actions"
        )

# --- Stripe Webhook Endpoints ---

@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events"""
    try:
        # Get the raw body
        body = await request.body()
        signature = request.headers.get("stripe-signature")
        
        print(f"Webhook received - Body length: {len(body)}, Signature: {signature[:20] if signature else 'None'}...")
        
        if not STRIPE_WEBHOOK_SECRET:
            print("Warning: STRIPE_WEBHOOK_SECRET not configured")
            return {"status": "webhook secret not configured"}
        
        try:
            # Verify webhook signature
            event = stripe.Webhook.construct_event(
                body, signature, STRIPE_WEBHOOK_SECRET
            )
            print(f"Webhook signature verified successfully")
        except ValueError as e:
            print(f"Invalid payload: {e}")
            raise HTTPException(status_code=400, detail="Invalid payload")
        except stripe.error.SignatureVerificationError as e:
            print(f"Invalid signature: {e}")
            raise HTTPException(status_code=400, detail="Invalid signature")
        except Exception as e:
            print(f"Unexpected error during signature verification: {e}")
            raise HTTPException(status_code=400, detail="Signature verification failed")
        
        # Handle the event
        event_type = event['type']
        print(f"Received Stripe event: {event_type}")
        
        if event_type == 'checkout.session.completed':
            await handle_checkout_completed(event['data']['object'])
        elif event_type == 'customer.subscription.created':
            await handle_subscription_created(event['data']['object'])
        elif event_type == 'customer.subscription.updated':
            await handle_subscription_updated(event['data']['object'])
        elif event_type == 'customer.subscription.deleted':
            await handle_subscription_deleted(event['data']['object'])
        elif event_type == 'invoice.payment_succeeded':
            await handle_payment_succeeded(event['data']['object'])
        elif event_type == 'customer.updated':
            await handle_customer_updated(event['data']['object'])
        elif event_type == 'invoice.payment_method_attached':
            await handle_payment_method_attached(event['data']['object'])
        else:
            print(f"Unhandled event type: {event_type}")
        
        print(f"Webhook processed successfully for event: {event_type}")
        return {"status": "success"}
        
    except Exception as e:
        print(f"Error processing webhook: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")

# --- Customer Portal Session ---
@app.post("/create-portal-session")
async def create_portal_session(
    user_id: str,
    authenticated_user_id: str = Depends(verify_token)
):
    """Create Stripe Customer Portal session"""
    try:
        # Verify user owns this data
        if user_id != authenticated_user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this data"
            )
        
        # Get user from database
        user_data = supabase.table("users").select("*").eq("id", user_id).execute()
        
        if not user_data.data:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = user_data.data[0]
        stripe_customer_id = user.get("stripe_customer_id")
        
        if not stripe_customer_id:
            raise HTTPException(status_code=400, detail="No Stripe customer found")
        
        # Create portal session
        session = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url="https://costras.com/dashboard"
        )
        
        debug_print(f"Created portal session for user {user_id}")
        return {"url": session.url}
        
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error creating portal session: {str(e)}", "ERROR")
        raise HTTPException(status_code=500, detail="Failed to create portal session")

async def handle_checkout_completed(session):
    """Handle successful checkout completion"""
    try:
        customer_email = session.get('customer_details', {}).get('email')
        subscription_id = session.get('subscription')
        
        debug_print(f"Checkout completed for {customer_email}, subscription: {subscription_id}", force=True)
        
        # Create or update user account
        await create_or_update_user_from_payment(customer_email, session)
        
    except Exception as e:
        debug_print(f"Error handling checkout completed: {str(e)}", "ERROR")

async def handle_subscription_created(subscription):
    """Handle new subscription creation"""
    try:
        customer_id = subscription.get('customer')
        subscription_id = subscription.get('id')
        status = subscription.get('status')
        
        debug_print(f"Subscription created: {subscription_id} for customer {customer_id}, status: {status}", force=True)
        
        # Update user access based on subscription
        await update_user_access_from_subscription(subscription)
        
    except Exception as e:
        debug_print(f"Error handling subscription created: {str(e)}", "ERROR")

async def handle_subscription_updated(subscription):
    """Handle subscription updates"""
    try:
        subscription_id = subscription.get('id')
        status = subscription.get('status')
        
        debug_print(f"Subscription updated: {subscription_id}, status: {status}", force=True)
        
        # Update user access based on new subscription status
        await update_user_access_from_subscription(subscription)
        
    except Exception as e:
        debug_print(f"Error handling subscription updated: {str(e)}", "ERROR")

async def handle_subscription_deleted(subscription):
    """Handle subscription cancellation"""
    try:
        subscription_id = subscription.get('id')
        customer_id = subscription.get('customer')
        
        debug_print(f"Subscription deleted: {subscription_id} for customer {customer_id}", force=True)
        
        # Revoke user access
        await revoke_user_access(customer_id)
        
    except Exception as e:
        debug_print(f"Error handling subscription deleted: {str(e)}", "ERROR")

async def handle_payment_succeeded(invoice):
    """Handle successful payment"""
    try:
        subscription_id = invoice.get('subscription')
        amount_paid = invoice.get('amount_paid')
        
        debug_print(f"Payment succeeded for subscription {subscription_id}, amount: {amount_paid}", force=True)
        
        # Update user billing status
        await update_user_billing_status(subscription_id, 'paid')
        
    except Exception as e:
        debug_print(f"Error handling payment succeeded: {str(e)}", "ERROR")

async def create_or_update_user_from_payment(email: str, session_data: dict):
    """Create or update user account from payment data"""
    try:
        # Extract plan information from metadata or line items
        metadata = session_data.get('metadata', {})
        plan_type = metadata.get('plan_type', 'starter')
        
        # If no metadata, try to determine from line items
        if plan_type == 'starter':
            line_items = session_data.get('line_items', {}).get('data', [])
            if line_items:
                price_id = line_items[0].get('price', {}).get('id', '')
                print(f"Price ID from session: {price_id}")
                
                # Map price IDs to plan types
                if 'pro' in price_id.lower() or 'price_1RpTgPLtqXsog4BXV7SLE8xf' in price_id:
                    plan_type = 'pro'
                elif 'starter' in price_id.lower() or 'price_1RpTiVLtqXsog4BXrUigPvkw' in price_id:
                    plan_type = 'starter'
        
        print(f"Creating/updating user {email} with plan {plan_type}")
        
        # Create or update user in database
        if supabase:
            try:
                # Check if user exists
                user_response = supabase.table('users').select('*').eq('email', email).execute()
                
                if user_response.data:
                    # Update existing user
                    user_id = user_response.data[0]['id']
                    supabase.table('users').update({
                        'updated_at': 'now()'
                    }).eq('id', user_id).execute()
                    print(f"Updated existing user {email}")
                else:
                    # Create new user
                    user_response = supabase.table('users').insert({
                        'email': email,
                        'stripe_customer_id': session_data.get('customer')
                    }).execute()
                    user_id = user_response.data[0]['id']
                    print(f"Created new user {email} with ID {user_id}")
                
                # Store subscription data
                subscription_id = session_data.get('subscription')
                if subscription_id:
                    supabase.table('subscriptions').insert({
                        'user_id': user_id,
                        'stripe_subscription_id': subscription_id,
                        'stripe_price_id': session_data.get('line_items', {}).get('data', [{}])[0].get('price', {}).get('id', ''),
                        'plan_type': plan_type,
                        'status': 'trialing'
                    }).execute()
                    print(f"Stored subscription data for user {email}")
                
            except Exception as db_error:
                print(f"Database error: {str(db_error)}")
        
        print(f"User {email} granted {plan_type} access")
        
    except Exception as e:
        print(f"Error creating/updating user: {str(e)}")

async def update_user_access_from_subscription(subscription: dict):
    """Update user access based on subscription data"""
    try:
        customer_id = subscription.get('customer')
        status = subscription.get('status')
        items = subscription.get('items', {}).get('data', [])
        
        if items:
            price_id = items[0].get('price', {}).get('id')
            print(f"Updating access for customer {customer_id}, status: {status}, price: {price_id}")
            
            # Determine plan type from price ID
            plan_type = 'starter'  # Default
            
            # Map specific price IDs to plan types
            if price_id == 'price_1RpTgPLtqXsog4BXV7SLE8xf':
                plan_type = 'pro'
            elif price_id == 'price_1RpTiVLtqXsog4BXrUigPvkw':
                plan_type = 'starter'
            elif 'pro' in price_id.lower():
                plan_type = 'pro'
            elif 'starter' in price_id.lower():
                plan_type = 'starter'
            
            # Update user access in your system
            print(f"Customer {customer_id} has {plan_type} access, status: {status}")
            
            # Here you would typically:
            # 1. Update user in database with correct plan
            # 2. Grant appropriate access based on plan
            # 3. Send welcome email with plan details
        
    except Exception as e:
        print(f"Error updating user access: {str(e)}")

async def revoke_user_access(customer_id: str):
    """Revoke user access when subscription is cancelled"""
    try:
        debug_print(f"Revoking access for customer {customer_id}", force=True)
        
        # Here you would typically:
        # 1. Update user status in database
        # 2. Revoke API access
        # 3. Stop any running bots
        # 4. Send cancellation email
        
        # For now, just log the action
        debug_print(f"Access revoked for customer {customer_id}", force=True)
        
    except Exception as e:
        debug_print(f"Error revoking user access: {str(e)}", "ERROR")

async def update_user_billing_status(subscription_id: str, status: str):
    """Update user billing status"""
    try:
        debug_print(f"Updating billing status for subscription {subscription_id}: {status}", force=True)
        
        # Update billing status in your system
        # This could include updating payment history, sending receipts, etc.
        
    except Exception as e:
        debug_print(f"Error updating billing status: {str(e)}", "ERROR")

async def handle_customer_updated(customer):
    """Handle customer updates from portal"""
    try:
        customer_id = customer.get("id")
        
        # Update user data in database
        supabase.table("users").update({
            "stripe_customer_id": customer_id,
            "updated_at": datetime.now().isoformat()
        }).eq("stripe_customer_id", customer_id).execute()
        
        debug_print(f"Updated customer data for {customer_id}")
        
    except Exception as e:
        debug_print(f"Error handling customer update: {str(e)}", "ERROR")

async def handle_payment_method_attached(invoice):
    """Handle payment method updates from portal"""
    try:
        customer_id = invoice.get("customer")
        payment_method_id = invoice.get("payment_method")
        
        # Get payment method details from Stripe
        payment_method = stripe.PaymentMethod.retrieve(payment_method_id)
        
        # Update user payment method info
        supabase.table("users").update({
            "payment_method_id": payment_method_id,
            "payment_method_last4": payment_method.card.last4,
            "payment_method_brand": payment_method.card.brand,
            "updated_at": datetime.now().isoformat()
        }).eq("stripe_customer_id", customer_id).execute()
        
        debug_print(f"Updated payment method for customer {customer_id}")
        
    except Exception as e:
        debug_print(f"Error handling payment method update: {str(e)}", "ERROR")

@app.post("/auth/get-user-twitter-tokens")
async def get_user_twitter_tokens(request: Request):
    """
    Get Twitter tokens for a user from Supabase
    """
    try:
        debug_print("Get user Twitter tokens request received", "INFO")
        
        # Get request body
        body = await request.json()
        user_email = body.get('user_email')
        
        if not user_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="user_email is required"
            )
        
        debug_print(f"Getting Twitter tokens for user: {user_email}", "INFO")
        
        # Get user's Twitter tokens from Supabase
        if not supabase:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Supabase client not available"
            )
        
        try:
            # Get user's Twitter tokens
            user_response = supabase.table('users').select(
                'twitter_auth_token, twitter_ct0_token, twitter_handle, twitter_display_name, twitter_profile_image_url'
            ).eq('email', user_email).execute()
            
            if not user_response.data:
                return {
                    "success": False,
                    "message": "User not found"
                }
            
            user_data = user_response.data[0]
            
            # Check if user has Twitter tokens
            if not user_data.get('twitter_auth_token'):
                return {
                    "success": False,
                    "message": "No Twitter tokens found for user"
                }
            
            return {
                "success": True,
                "twitter_tokens": {
                    "auth_token": user_data.get('twitter_auth_token'),
                    "ct0_token": user_data.get('twitter_ct0_token'),
                    "user_handle": user_data.get('twitter_handle'),
                    "display_name": user_data.get('twitter_display_name'),
                    "profile_image_url": user_data.get('twitter_profile_image_url')
                }
            }
            
        except Exception as e:
            debug_print(f"Supabase query error: {str(e)}", "ERROR")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get Twitter tokens: {str(e)}"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Get Twitter tokens error: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get Twitter tokens: {str(e)}"
        )

@app.post("/auth/save-twitter-tokens")
async def save_twitter_tokens(token_data: dict):
    """
    Save Twitter authentication tokens to the database
    """
    try:
        debug_print(f"Received Twitter token save request for user: {token_data.get('user_email')}")
        
        # DEBUG: Log all received data
        debug_print(f"DEBUG - Received token_data: {token_data}", force=True)
        debug_print(f"DEBUG - profile_image field: {token_data.get('profile_image')}", force=True)
        debug_print(f"DEBUG - profile_image type: {type(token_data.get('profile_image'))}", force=True)
        debug_print(f"DEBUG - profile_image length: {len(token_data.get('profile_image')) if token_data.get('profile_image') else 0}", force=True)
        
        # Validate required fields
        required_fields = ['user_email', 'auth_token']
        for field in required_fields:
            if not token_data.get(field):
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        user_email = token_data['user_email']
        auth_token = token_data['auth_token']
        
        debug_print(f"Validating user exists in database: {user_email}")
        
        # Check if user exists in public.users
        user_response = supabase.table('users').select('id').eq('email', user_email).execute()
        
        if not user_response.data:
            debug_print(f"User not found in database: {user_email}")
            raise HTTPException(status_code=404, detail="User not found in database")
        
        user_id = user_response.data[0]['id']
        debug_print(f"User found with ID: {user_id}")
        
        # Prepare update data
        update_data = {
            'twitter_auth_token': auth_token,
            'twitter_connected_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }
        
        # Add optional fields if provided
        if token_data.get('ct0_token'):
            update_data['twitter_ct0_token'] = token_data['ct0_token']
        if token_data.get('user_handle'):
            update_data['twitter_handle'] = token_data['user_handle']
        if token_data.get('display_name'):
            update_data['twitter_display_name'] = token_data['display_name']
        if token_data.get('profile_image'):
            update_data['twitter_profile_image_url'] = token_data['profile_image']
            debug_print(f"DEBUG - Adding profile_image to update_data: {token_data['profile_image']}", force=True)
        else:
            debug_print(f"DEBUG - No profile_image found in token_data", force=True)
        
        debug_print(f"Updating user with Twitter tokens: {update_data}")
        
        # Update user with Twitter tokens
        update_response = supabase.table('users').update(update_data).eq('id', user_id).execute()
        
        if not update_response.data:
            debug_print("Failed to update user with Twitter tokens")
            raise HTTPException(status_code=500, detail="Failed to save Twitter tokens")
        
        debug_print(f"Successfully saved Twitter tokens for user: {user_email}")
        
        return {
            "success": True,
            "user_id": user_id,
            "updated_at": update_data['updated_at'],
            "message": "Twitter tokens saved successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error saving Twitter tokens: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# --- LMArenaBridge Integration Functions ---

async def generate_niche_specific_prompt(
    analysis_result: Dict[str, Any], 
    model: str = "llama-4-maverick-03-26-experimental"
) -> Dict[str, Any]:
    """
    Generate a custom Twitter bot prompt based on account analysis
    """
    try:
        debug_print(f"Generating custom prompt for account analysis using {model}")
        
        # Extract key analysis data for prompt generation
        niche = analysis_result.get('niche', 'general')
        tone = analysis_result.get('tone', 'professional')
        engagement_style = analysis_result.get('engagement_style', 'conversational')
        content_patterns = analysis_result.get('content_patterns', 'mixed')
        
        # Create prompt generation request using the user's preferred template
        prompt_generation_request = f"""
        You are an expert AI prompt engineer specializing in Twitter bot behavior customization. Your task is to create a custom Twitter bot prompt based on the analysis of a specific account.

        **ACCOUNT ANALYSIS DATA:**
        - Niche: {niche}
        - Communication Tone: {tone}
        - Engagement Style: {engagement_style}
        - Content Patterns: {content_patterns}
        - Full Analysis: {json.dumps(analysis_result.get('full_analysis', {}), indent=2)}

        **TASK:**
        Create a custom Twitter bot prompt that will make the bot behave like it belongs to the {niche} niche, using {tone} communication style, and {engagement_style} engagement approach.

        **REQUIREMENTS:**
        1. The prompt should be based on this template structure but customized for the specific account:
        {{
            "prompt_type": "custom_niche_prompt",
            "niche": "{niche}",
            "tone": "{tone}",
            "engagement_style": "{engagement_style}",
            "custom_prompt": "Your customized prompt here...",
            "bot_instructions": "Specific instructions for bot behavior...",
            "example_responses": ["Example 1", "Example 2", "Example 3"],
            "avoidance_topics": ["Topic 1", "Topic 2"],
            "success_indicators": ["Indicator 1", "Indicator 2"]
        }}

        2. The custom_prompt should be a complete, ready-to-use prompt that the Twitter bot can use directly
        3. Make it relevant to the {niche} industry with {tone} communication style
        4. Include specific examples and instructions for the bot
        5. Ensure the prompt maintains the JSON structure from the user's ai_prompt_backup.txt template

        **OUTPUT FORMAT:**
        Return ONLY a valid JSON object with the structure above. No additional text or explanations.

        Begin custom prompt generation now!
        """
        
        # Prepare request for LMArenaBridge
        lmarena_request = {
            "model": model,
            "messages": [
                {"role": "user", "content": prompt_generation_request}
            ],
            "stream": False
        }
        
        # Call LMArenaBridge API for prompt generation
        async with httpx.AsyncClient(timeout=LMARENA_BRIDGE_TIMEOUT) as client:
            response = await client.post(
                f"{LMARENA_BRIDGE_URL}/v1/chat/completions",
                json=lmarena_request,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"LMArenaBridge prompt generation error: {response.status_code}"
                )
            
            # Parse LMArenaBridge response
            lmarena_data = response.json()
            prompt_content = lmarena_data['choices'][0]['message']['content']
            
            debug_print(f"LMArenaBridge custom prompt generation completed for {niche} niche")
            
            # Try to parse JSON response from AI
            try:
                # Look for JSON content in the response
                json_start = prompt_content.find('{')
                json_end = prompt_content.rfind('}') + 1
                
                if json_start != -1 and json_end > json_start:
                    json_content = prompt_content[json_start:json_end]
                    parsed_prompt = json.loads(json_content)
                    
                    # Create structured prompt result
                    prompt_result = {
                        'prompt_type': parsed_prompt.get('prompt_type', 'custom_niche_prompt'),
                        'niche': parsed_prompt.get('niche', niche),
                        'tone': parsed_prompt.get('tone', tone),
                        'engagement_style': parsed_prompt.get('engagement_style', engagement_style),
                        'custom_prompt': parsed_prompt.get('custom_prompt', ''),
                        'bot_instructions': parsed_prompt.get('bot_instructions', ''),
                        'example_responses': parsed_prompt.get('example_responses', []),
                        'avoidance_topics': parsed_prompt.get('avoidance_topics', []),
                        'success_indicators': parsed_prompt.get('success_indicators', []),
                        'model_used': model,
                        'generation_timestamp': datetime.now().isoformat(),
                        'analysis_id': analysis_result.get('analysis_id'),
                        'full_prompt_data': parsed_prompt
                    }
                    
                    debug_print(f"Successfully generated custom prompt for {niche} niche")
                    return prompt_result
                    
            except json.JSONDecodeError as e:
                debug_print(f"Failed to parse JSON response: {str(e)}", "WARNING")
                debug_print(f"Raw response: {prompt_content[:500]}...", "WARNING")
            
            # Fallback: Create basic prompt result if JSON parsing fails
            fallback_prompt = f"You are a Twitter bot specialized in the {niche} niche. Use a {tone} communication style and {engagement_style} engagement approach. Be authentic and engaging while staying relevant to {niche} topics."
            
            prompt_result = {
                'prompt_type': 'custom_niche_prompt',
                'niche': niche,
                'tone': tone,
                'engagement_style': engagement_style,
                'custom_prompt': fallback_prompt,
                'bot_instructions': f'Focus on {niche} content, use {tone} tone, engage in {engagement_style} style',
                'example_responses': [f'Example {niche} response 1', f'Example {niche} response 2'],
                'avoidance_topics': ['offensive content', 'spam'],
                'success_indicators': ['engagement', 'relevance'],
                'model_used': model,
                'generation_timestamp': datetime.now().isoformat(),
                'analysis_id': analysis_result.get('analysis_id'),
                'full_prompt_data': None
            }
            
            return prompt_result
            
    except Exception as e:
        debug_print(f"Error generating custom prompt: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Custom prompt generation failed: {str(e)}"
        )

async def call_lmarena_bridge_analysis(
    twitter_handle: str, 
    auth_token: Optional[str] = None,  # Made optional since not needed for analysis
    model: str = "grok-4-0709"
) -> Dict[str, Any]:
    """
    Call LMArenaBridge to analyze a Twitter account using AI models
    
    Note: auth_token is not required for public account analysis.
    It's only needed when making authenticated Twitter API calls.
    """
    try:
        debug_print(f"Calling LMArenaBridge for analysis of @{twitter_handle} using {model}")
        
        # Create comprehensive analysis prompt using expert structure
        analysis_prompt = f"""
        You are an expert social media analyst and AI researcher specializing in Twitter/X account analysis. Your task is to perform a comprehensive, multi-dimensional analysis of a Twitter account to determine its niche, persona, and optimal engagement strategy.

        **ANALYSIS REQUIREMENTS:**

        1. **DEEP NICHE DETECTION:**
           - Primary niche 
           - Secondary niches if applicable
           - Sub-niche identification 
           - Industry vertical and market positioning

        2. **CONTENT ANALYSIS:**
           - Content type (educational, promotional, conversational, news, entertainment, etc.)
           - Content quality assessment (high, medium, low)
           - Content frequency and consistency
           - Visual vs text content ratio
           - Engagement patterns and timing

        3. **PERSONA & TONE ANALYSIS:**
           - Communication style (professional, casual, authoritative, friendly, humorous, etc.)
           - Brand voice characteristics
           - Emotional tone (positive, neutral, critical, enthusiastic, etc.)
           - Language complexity and vocabulary level
           - Cultural references and insider knowledge

        4. **AUDIENCE ANALYSIS:**
           - Target audience demographics
           - Audience expertise level (beginner, intermediate, expert)
           - Audience engagement style preferences
           - Community characteristics and values
           - Influencer vs community member positioning

        5. **ENGAGEMENT PATTERNS:**
           - Interaction style (conversational, authoritative, collaborative, etc.)
           - Response patterns and timing
           - Community building strategies
           - Controversy handling and conflict resolution
           - Cross-platform presence and strategy

        6. **COMPETITIVE POSITIONING:**
           - Unique value proposition
           - Differentiation factors
           - Market positioning within niche
           - Competitive advantages and disadvantages
           - Growth potential and scalability

        **OUTPUT FORMAT:**
        Return a comprehensive JSON analysis with the following structure:

        {{
            "analysis_metadata": {{
                "confidence_score": 0.95,
                "analysis_depth": "comprehensive",
                "data_points_analyzed": 150,
                "analysis_timestamp": "2025-08-03T11:00:00Z"
            }},
            "niche_analysis": {{
                "primary_niche": "string",
                "secondary_niches": ["array", "of", "niches"],
                "sub_niche": "string",
                "industry_vertical": "string",
                "market_positioning": "string",
                "niche_confidence": 0.95
            }},
            "content_analysis": {{
                "content_type": "string",
                "content_quality": "string",
                "content_frequency": "string",
                "visual_text_ratio": "string",
                "engagement_patterns": "string",
                "content_consistency": "string"
            }},
            "persona_analysis": {{
                "communication_style": "string",
                "brand_voice": "string",
                "emotional_tone": "string",
                "language_complexity": "string",
                "cultural_references": "string",
                "expertise_level": "string"
            }},
            "audience_analysis": {{
                "target_demographics": "string",
                "audience_expertise": "string",
                "engagement_preferences": "string",
                "community_characteristics": "string",
                "influencer_positioning": "string"
            }},
            "engagement_analysis": {{
                "interaction_style": "string",
                "response_patterns": "string",
                "community_building": "string",
                "conflict_handling": "string",
                "cross_platform_strategy": "string"
            }},
            "competitive_analysis": {{
                "unique_value_proposition": "string",
                "differentiation_factors": "string",
                "market_positioning": "string",
                "competitive_advantages": ["array", "of", "advantages"],
                "growth_potential": "string"
            }},
            "bot_strategy_recommendations": {{
                "optimal_persona": "string",
                "engagement_style": "string",
                "content_focus": "string",
                "target_audience": "string",
                "key_messaging_themes": ["array", "of", "themes"],
                "avoidance_topics": ["array", "of", "topics"],
                "success_indicators": ["array", "of", "indicators"]
            }},
            "short_summary": {{
                "niche_summary": "2-3 sentence summary of the account's primary niche and positioning",
                "persona_summary": "2-3 sentence summary of the account's communication style and tone",
                "bot_guidance": "2-3 sentence summary of how a Twitter bot should interact with this account"
            }}
        }}

        **ANALYSIS INSTRUCTIONS:**
        1. Perform a thorough analysis of the account's recent tweets, bio, profile information, and engagement patterns
        2. Consider the account's historical context and evolution
        3. Analyze the quality and consistency of content
        4. Assess the account's positioning within its niche
        5. Identify unique characteristics and differentiation factors
        6. Provide actionable insights for bot strategy development
        7. Ensure all confidence scores are realistic and justified
        8. Maintain professional objectivity while providing detailed analysis

        **QUALITY STANDARDS:**
        - Analysis must be comprehensive and multi-dimensional
        - All conclusions must be evidence-based
        - Confidence scores must reflect actual certainty levels
        - Recommendations must be actionable and specific
        - JSON output must be valid and parsable
        - No text outside the JSON structure

        Account to analyze: @{twitter_handle}

        Begin analysis now!
        """
        
        # Prepare request for LMArenaBridge
        lmarena_request = {
            "model": model,
            "messages": [
                {"role": "user", "content": analysis_prompt}
            ],
            "stream": False
        }
        
        # Call LMArenaBridge API
        async with httpx.AsyncClient(timeout=LMARENA_BRIDGE_TIMEOUT) as client:
            response = await client.post(
                f"{LMARENA_BRIDGE_URL}/v1/chat/completions",
                json=lmarena_request,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"LMArenaBridge API error: {response.status_code}"
                )
            
            # Parse LMArenaBridge response
            lmarena_data = response.json()
            analysis_content = lmarena_data['choices'][0]['message']['content']
            
            debug_print(f"LMArenaBridge analysis completed for @{twitter_handle}")
            
            # Try to parse JSON response from AI
            try:
                # Look for JSON content in the response
                json_start = analysis_content.find('{')
                json_end = analysis_content.rfind('}') + 1
                
                if json_start != -1 and json_end > json_start:
                    json_content = analysis_content[json_start:json_end]
                    parsed_analysis = json.loads(json_content)
                    
                    # Extract short summary from the dedicated short_summary section
                    short_summary = ""
                    if 'short_summary' in parsed_analysis:
                        summary = parsed_analysis['short_summary']
                        niche_summary = summary.get('niche_summary', '')
                        persona_summary = summary.get('persona_summary', '')
                        bot_guidance = summary.get('bot_guidance', '')
                        
                        short_summary = f"NICHE: {niche_summary} PERSONA: {persona_summary} BOT GUIDANCE: {bot_guidance}"
                    else:
                        # Fallback to bot strategy recommendations if short_summary not available
                        if 'bot_strategy_recommendations' in parsed_analysis:
                            bot_recs = parsed_analysis['bot_strategy_recommendations']
                            if 'optimal_persona' in bot_recs and 'engagement_style' in bot_recs:
                                short_summary = f"Optimal persona: {bot_recs['optimal_persona']}. Engagement style: {bot_recs['engagement_style']}. Content focus: {bot_recs.get('content_focus', 'N/A')}"
                    
                    # Create structured analysis result from parsed JSON
                    analysis_result = {
                        'twitter_handle': twitter_handle,
                        'niche': parsed_analysis.get('niche_analysis', {}).get('primary_niche', 'Unknown'),
                        'content_patterns': parsed_analysis.get('content_analysis', {}).get('content_type', 'Unknown'),
                        'engagement_style': parsed_analysis.get('engagement_analysis', {}).get('interaction_style', 'Unknown'),
                        'tone': parsed_analysis.get('persona_analysis', {}).get('communication_style', 'Unknown'),
                        'key_topics': ', '.join(parsed_analysis.get('bot_strategy_recommendations', {}).get('key_messaging_themes', ['Unknown'])),
                        'follower_count': 'Unknown',  # Not available in current analysis
                        'bio': 'Unknown',  # Not available in current analysis
                        'location': 'Unknown',  # Not available in current analysis
                        'analysis_data': analysis_content,
                        'short_summary': short_summary or "Analysis completed successfully",
                        'model_used': model,
                        'confidence_score': parsed_analysis.get('analysis_metadata', {}).get('confidence_score', 0.0),
                        'full_analysis': parsed_analysis  # Store the complete parsed analysis
                    }
                    
                    debug_print(f"Successfully parsed JSON analysis for @{twitter_handle}")
                    return analysis_result
                    
            except json.JSONDecodeError as e:
                debug_print(f"Failed to parse JSON response: {str(e)}", "WARNING")
                debug_print(f"Raw response: {analysis_content[:500]}...", "WARNING")
            
            # Fallback: Create basic analysis result if JSON parsing fails
            analysis_result = {
                'twitter_handle': twitter_handle,
                'niche': 'Unknown',
                'content_patterns': 'Unknown',
                'engagement_style': 'Unknown',
                'tone': 'Unknown',
                'key_topics': 'Unknown',
                'follower_count': 'Unknown',
                'bio': 'Unknown',
                'location': 'Unknown',
                'analysis_data': analysis_content,
                'short_summary': analysis_content[-200:] if len(analysis_content) > 200 else analysis_content,
                'model_used': model,
                'confidence_score': 0.0,
                'full_analysis': None
            }
            
            return analysis_result
            
    except Exception as e:
        debug_print(f"Error calling LMArenaBridge: {str(e)}", "ERROR")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"LMArenaBridge analysis failed: {str(e)}"
        )

# --- AI Analysis Endpoints ---

class AccountAnalysisRequest(BaseModel):
    """Request for account analysis"""
    twitter_handle: str = Field(..., description="Twitter handle or URL to analyze (e.g., 'elonmusk' or 'https://x.com/elonmusk')")
    auth_token: Optional[str] = Field(None, description="Twitter auth token for authenticated analysis")

class PromptGenerationRequest(BaseModel):
    """Request for prompt generation"""
    analysis_result: Dict[str, Any] = Field(..., description="Account analysis results")
    num_variations: int = Field(default=3, description="Number of prompt variations to generate")

class PromptUpdateRequest(BaseModel):
    """Request to update prompts"""
    prompts: List[Dict[str, Any]] = Field(..., description="Updated prompts")

class CustomPromptData(BaseModel):
    """Data structure for custom prompts"""
    prompt_type: str = Field(..., description="Type of prompt (e.g., 'custom_niche_prompt')")
    niche: str = Field(..., description="Account niche")
    tone: str = Field(..., description="Communication tone")
    engagement_style: str = Field(..., description="Engagement style")
    custom_prompt: str = Field(..., description="The actual custom prompt text")
    bot_instructions: str = Field(..., description="Specific instructions for bot behavior")
    example_responses: List[str] = Field(default=[], description="Example responses")
    avoidance_topics: List[str] = Field(default=[], description="Topics to avoid")
    success_indicators: List[str] = Field(default=[], description="Success indicators")
    model_used: str = Field(default="gpt-5", description="AI model used for generation")
    generation_timestamp: str = Field(..., description="When the prompt was generated")
    analysis_id: Optional[str] = Field(None, description="Linked analysis ID")
    full_prompt_data: Optional[Dict[str, Any]] = Field(None, description="Full prompt data")

@app.post("/api/analyze-account", response_model=Dict[str, Any])
async def analyze_account(
    request: AccountAnalysisRequest,
    user_id: str = Depends(verify_token)
):
    """
    Analyze a Twitter account to determine niche, content patterns, and engagement style
    """
    try:
        debug_print(f"Starting account analysis for @{request.twitter_handle}")
        
        # Twitter tokens are NOT needed for public account analysis
        # They are only required when actually running the Twitter bot
        debug_print(f"Proceeding with public account analysis for @{request.twitter_handle}")
        
        # Perform analysis using LMArenaBridge AI models with model rotation
        available_models = ["grok-4-0709", "llama-4-maverick-03-26-experimental", "llama-3.3-70b-instruct"]
        
        # Use first available model for initial analysis
        analysis_result = await call_lmarena_bridge_analysis(
            twitter_handle=request.twitter_handle,
            auth_token=None,  # Not needed for analysis
            model=available_models[0]  # Use first available model
        )
        
        # Convert to dictionary for database storage
        analysis_data = {
            'twitter_handle': request.twitter_handle,  # Use the request parameter instead
            'niche': analysis_result.get('niche', 'Unknown'),
            'content_patterns': analysis_result.get('content_patterns', 'Unknown'),
            'engagement_style': analysis_result.get('engagement_style', 'Unknown'),
            'tone': analysis_result.get('tone', 'Unknown'),
            'key_topics': analysis_result.get('key_topics', 'Unknown'),
            'follower_count': analysis_result.get('follower_count', 'Unknown'),
            'bio': analysis_result.get('bio', 'Unknown'),
            'location': analysis_result.get('location', 'Unknown'),
            'analysis_data': analysis_result.get('analysis_data', ''),
            'short_summary': analysis_result.get('short_summary', ''),
            'model_used': analysis_result.get('model_used', 'gpt-5'),
            'confidence_score': analysis_result.get('confidence_score', 0.0),
            'full_analysis': json.dumps(analysis_result.get('full_analysis', {})) if analysis_result.get('full_analysis') else None
        }
        
        # Store analysis in database
        analysis_id = None
        if supabase:
            try:
                # Check if analysis already exists
                existing_analysis = supabase.table('account_analyses').select('*').eq('user_id', user_id).eq('twitter_handle', request.twitter_handle).execute()
                
                if existing_analysis.data:
                    # Update existing analysis
                    supabase.table('account_analyses').update(analysis_data).eq('user_id', user_id).eq('twitter_handle', request.twitter_handle).execute()
                    analysis_id = existing_analysis.data[0].get('id')
                    debug_print(f"Updated existing analysis for @{request.twitter_handle}")
                else:
                    # Create new analysis
                    analysis_data['user_id'] = user_id
                    insert_result = supabase.table('account_analyses').insert(analysis_data).execute()
                    if insert_result.data:
                        analysis_id = insert_result.data[0].get('id')
                    debug_print(f"Created new analysis for @{request.twitter_handle}")
                    
            except Exception as e:
                debug_print(f"Error storing analysis in database: {str(e)}", "WARNING")
        
        # Generate custom prompt based on analysis
        custom_prompt_data = None
        try:
            if analysis_id:
                # Add analysis_id to analysis_result for prompt generation
                analysis_result['analysis_id'] = analysis_id
                
                # Generate custom prompt using LMArenaBridge with model rotation
                custom_prompt_data = await generate_niche_specific_prompt(
                    analysis_result=analysis_result,
                    model=available_models[1] if len(available_models) > 1 else available_models[0]  # Use second model for variety
                )
                
                # Store custom prompt in database
                if supabase and custom_prompt_data:
                    try:
                        prompt_storage_data = {
                            'user_id': user_id,
                            'analysis_id': analysis_id,
                            'twitter_handle': request.twitter_handle,
                            'prompt_type': custom_prompt_data.get('prompt_type'),
                            'niche': custom_prompt_data.get('niche'),
                            'tone': custom_prompt_data.get('tone'),
                            'engagement_style': custom_prompt_data.get('engagement_style'),
                            'custom_prompt': custom_prompt_data.get('custom_prompt'),
                            'bot_instructions': custom_prompt_data.get('bot_instructions'),
                            'example_responses': json.dumps(custom_prompt_data.get('example_responses', [])),
                            'avoidance_topics': json.dumps(custom_prompt_data.get('avoidance_topics', [])),
                            'success_indicators': json.dumps(custom_prompt_data.get('success_indicators', [])),
                            'model_used': custom_prompt_data.get('model_used'),
                            'generation_timestamp': custom_prompt_data.get('generation_timestamp'),
                            'full_prompt_data': json.dumps(custom_prompt_data.get('full_prompt_data', {})),
                            'created_at': datetime.now().isoformat()
                        }
                        
                        # Check if custom prompt already exists
                        existing_prompt = supabase.table('account_prompts').select('*').eq('user_id', user_id).eq('analysis_id', analysis_id).execute()
                        
                        if existing_prompt.data:
                            # Update existing prompt
                            supabase.table('account_prompts').update(prompt_storage_data).eq('user_id', user_id).eq('analysis_id', analysis_id).execute()
                            debug_print(f"Updated existing custom prompt for @{request.twitter_handle}")
                        else:
                            # Create new prompt
                            supabase.table('account_prompts').insert(prompt_storage_data).execute()
                            debug_print(f"Created new custom prompt for @{request.twitter_handle}")
                            
                    except Exception as e:
                        debug_print(f"Error storing custom prompt in database: {str(e)}", "WARNING")
                
                debug_print(f"Custom prompt generation completed for @{request.twitter_handle}")
                
        except Exception as e:
            debug_print(f"Error generating custom prompt: {str(e)}", "WARNING")
            # Continue without custom prompt - analysis still successful
        
        debug_print(f"Account analysis completed for @{request.twitter_handle}: {analysis_result['niche']} niche detected")
        
        return {
            "success": True,
            "analysis": analysis_data,
            "custom_prompt": custom_prompt_data,
            "message": f"Account analysis and custom prompt generation completed successfully"
        }
        
    except Exception as e:
        debug_print(f"Error analyzing account: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/generate-prompts", response_model=Dict[str, Any])
async def generate_prompts(
    request: PromptGenerationRequest,
    user_id: str = Depends(verify_token)
):
    """
    Generate personalized prompts based on account analysis
    """
    try:
        debug_print(f"Generating prompts for user {user_id}")
        
        # Import AI analysis modules
        import sys
        # Use current directory for imports (more portable)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.insert(0, current_dir)
        
        from prompt_generator import PromptGenerator
        
        # Initialize prompt generator
        generator = PromptGenerator()
        
        # Generate prompts
        prompts = await generator.generate_prompts(request.analysis_result)
        
        # Generate variations if requested
        if request.num_variations > 1:
            variations = await generator.generate_prompt_variations(request.analysis_result, request.num_variations)
            prompts.extend(variations)
        
        # Convert to dictionary format
        prompt_data = []
        for prompt in prompts:
            prompt_dict = {
                'prompt_type': prompt.prompt_type,
                'content': prompt.content,
                'niche': prompt.niche,
                'tone': prompt.tone,
                'engagement_style': prompt.engagement_style,
                'created_at': prompt.created_at
            }
            prompt_data.append(prompt_dict)
        
        # Store prompts in database
        if supabase:
            try:
                # Get account analysis ID
                analysis_result = supabase.table('account_analyses').select('id').eq('user_id', user_id).eq('twitter_handle', request.analysis_result.get('twitter_handle', '')).execute()
                
                if analysis_result.data:
                    account_id = analysis_result.data[0]['id']
                    
                    # Store each prompt
                    for prompt in prompt_data:
                        prompt['user_id'] = user_id
                        prompt['account_id'] = account_id
                        supabase.table('account_prompts').insert(prompt).execute()
                    
                    debug_print(f"Stored {len(prompt_data)} prompts in database")
                    
            except Exception as e:
                debug_print(f"Error storing prompts in database: {str(e)}", "WARNING")
        
        debug_print(f"Generated {len(prompts)} prompts successfully")
        
        return {
            "success": True,
            "prompts": prompt_data,
            "count": len(prompts),
            "message": f"Generated {len(prompts)} prompts successfully"
        }
        
    except Exception as e:
        debug_print(f"Error generating prompts: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Prompt generation failed: {str(e)}")

@app.get("/api/account-prompts/{user_id}/{account_id}", response_model=Dict[str, Any])
async def get_account_prompts(
    user_id: str,
    account_id: str,
    authenticated_user_id: str = Depends(verify_token)
):
    """
    Get prompts for a specific account
    """
    try:
        # Verify user access
        if user_id != authenticated_user_id:
            raise HTTPException(status_code=403, detail="Access denied")
        
        if not supabase:
            raise HTTPException(status_code=500, detail="Database not available")
        
        # Get prompts from database
        prompts_result = supabase.table('account_prompts').select('*').eq('user_id', user_id).eq('account_id', account_id).execute()
        
        if not prompts_result.data:
            return {
                "success": True,
                "prompts": [],
                "message": "No prompts found for this account"
            }
        
        debug_print(f"Retrieved {len(prompts_result.data)} prompts for account {account_id}")
        
        return {
            "success": True,
            "prompts": prompts_result.data,
            "count": len(prompts_result.data),
            "message": f"Retrieved {len(prompts_result.data)} prompts"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error retrieving prompts: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve prompts: {str(e)}")

@app.put("/api/update-prompts/{user_id}/{account_id}", response_model=Dict[str, Any])
async def update_account_prompts(
    user_id: str,
    account_id: str,
    request: PromptUpdateRequest,
    authenticated_user_id: str = Depends(verify_token)
):
    """
    Update prompts for a specific account
    """
    try:
        # Verify user access
        if user_id != authenticated_user_id:
            raise HTTPException(status_code=403, detail="Access denied")
        
        if not supabase:
            raise HTTPException(status_code=500, detail="Database not available")
        
        # Update each prompt
        updated_count = 0
        for prompt in request.prompts:
            if 'id' in prompt:
                # Update existing prompt
                update_data = {
                    'content': prompt.get('content'),
                    'is_active': prompt.get('is_active', True),
                    'updated_at': datetime.utcnow().isoformat()
                }
                
                supabase.table('account_prompts').update(update_data).eq('id', prompt['id']).eq('user_id', user_id).execute()
                updated_count += 1
        
        debug_print(f"Updated {updated_count} prompts for account {account_id}")
        
        return {
            "success": True,
            "updated_count": updated_count,
            "message": f"Updated {updated_count} prompts successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error updating prompts: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to update prompts: {str(e)}")

@app.get("/api/account-analysis/{user_id}/{twitter_handle}", response_model=Dict[str, Any])
async def get_account_analysis(
    user_id: str,
    twitter_handle: str,
    authenticated_user_id: str = Depends(verify_token)
):
    """
    Get stored account analysis
    """
    try:
        # Verify user access
        if user_id != authenticated_user_id:
            raise HTTPException(status_code=403, detail="Access denied")
        
        if not supabase:
            raise HTTPException(status_code=500, detail="Database not available")
        
        # Get analysis from database
        analysis_result = supabase.table('account_analyses').select('*').eq('user_id', user_id).eq('twitter_handle', twitter_handle).execute()
        
        if not analysis_result.data:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        debug_print(f"Retrieved analysis for @{twitter_handle}")
        
        return {
            "success": True,
            "analysis": analysis_result.data[0],
            "message": "Analysis retrieved successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error retrieving analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve analysis: {str(e)}")

@app.get("/api/custom-prompt/{user_id}/{twitter_handle}", response_model=Dict[str, Any])
async def get_custom_prompt(
    user_id: str,
    twitter_handle: str,
    authenticated_user_id: str = Depends(verify_token)
):
    """
    Get custom prompt for a specific account (used by Twitter bot)
    """
    try:
        # Verify user access
        if user_id != authenticated_user_id:
            raise HTTPException(status_code=403, detail="Access denied")
        
        if not supabase:
            raise HTTPException(status_code=500, detail="Database not available")
        
        # Get custom prompt from database
        prompt_result = supabase.table('account_prompts').select('*').eq('user_id', user_id).eq('twitter_handle', twitter_handle).execute()
        
        if not prompt_result.data:
            return {
                "success": True,
                "custom_prompt": None,
                "message": "No custom prompt found for this account"
            }
        
        prompt_data = prompt_result.data[0]
        
        # Parse JSON fields back to lists/dicts
        try:
            if prompt_data.get('example_responses'):
                prompt_data['example_responses'] = json.loads(prompt_data['example_responses'])
            if prompt_data.get('avoidance_topics'):
                prompt_data['avoidance_topics'] = json.loads(prompt_data['avoidance_topics'])
            if prompt_data.get('success_indicators'):
                prompt_data['success_indicators'] = json.loads(prompt_data['success_indicators'])
            if prompt_data.get('full_prompt_data'):
                prompt_data['full_prompt_data'] = json.loads(prompt_data['full_prompt_data'])
        except Exception as e:
            debug_print(f"Error parsing JSON fields in custom prompt: {str(e)}", "WARNING")
        
        debug_print(f"Retrieved custom prompt for @{twitter_handle}")
        
        return {
            "success": True,
            "custom_prompt": prompt_data,
            "message": "Custom prompt retrieved successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error retrieving custom prompt: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve custom prompt: {str(e)}")

@app.post("/api/regenerate-custom-prompt/{user_id}/{twitter_handle}", response_model=Dict[str, Any])
async def regenerate_custom_prompt(
    user_id: str,
    twitter_handle: str,
    authenticated_user_id: str = Depends(verify_token)
):
    """
    Regenerate custom prompt for an account (for "Scan Again" functionality)
    """
    try:
        # Verify user access
        if user_id != authenticated_user_id:
            raise HTTPException(status_code=403, detail="Access denied")
        
        if not supabase:
            raise HTTPException(status_code=500, detail="Database not available")
        
        # Get existing analysis
        analysis_result = supabase.table('account_analyses').select('*').eq('user_id', user_id).eq('twitter_handle', twitter_handle).execute()
        
        if not analysis_result.data:
            raise HTTPException(status_code=404, detail="Account analysis not found")
        
        analysis_data = analysis_result.data[0]
        analysis_id = analysis_data.get('id')
        
        # Use a different model for regeneration (model rotation)
        available_models = ["grok-4-0709", "llama-4-maverick-03-26-experimental", "llama-3.3-70b-instruct"]
        
        # Get the last model used
        last_prompt = supabase.table('account_prompts').select('model_used').eq('user_id', user_id).eq('twitter_handle', twitter_handle).execute()
        
        if last_prompt.data and last_prompt.data[0].get('model_used'):
            last_model = last_prompt.data[0]['model_used']
            # Choose next model in rotation
            try:
                current_index = available_models.index(last_model)
                next_model = available_models[(current_index + 1) % len(available_models)]
            except ValueError:
                next_model = available_models[0]
        else:
            next_model = available_models[0]
        
        debug_print(f"Regenerating custom prompt for @{twitter_handle} using {next_model}")
        
        # Add analysis_id to analysis_data for prompt generation
        analysis_data['analysis_id'] = analysis_id
        
        # Generate new custom prompt
        custom_prompt_data = await generate_niche_specific_prompt(
            analysis_result=analysis_data,
            model=next_model
        )
        
        # Store new custom prompt
        if custom_prompt_data:
            prompt_storage_data = {
                'user_id': user_id,
                'analysis_id': analysis_id,
                'twitter_handle': twitter_handle,
                'prompt_type': custom_prompt_data.get('prompt_type'),
                'niche': custom_prompt_data.get('niche'),
                'tone': custom_prompt_data.get('tone'),
                'engagement_style': custom_prompt_data.get('engagement_style'),
                'custom_prompt': custom_prompt_data.get('custom_prompt'),
                'bot_instructions': custom_prompt_data.get('bot_instructions'),
                'example_responses': json.dumps(custom_prompt_data.get('example_responses', [])),
                'avoidance_topics': json.dumps(custom_prompt_data.get('avoidance_topics', [])),
                'success_indicators': json.dumps(custom_prompt_data.get('success_indicators', [])),
                'model_used': custom_prompt_data.get('model_used'),
                'generation_timestamp': custom_prompt_data.get('generation_timestamp'),
                'full_prompt_data': json.dumps(custom_prompt_data.get('full_prompt_data', {})),
                'created_at': datetime.now().isoformat()
            }
            
            # Update existing prompt
            supabase.table('account_prompts').update(prompt_storage_data).eq('user_id', user_id).eq('twitter_handle', twitter_handle).execute()
            
            debug_print(f"Custom prompt regenerated for @{twitter_handle} using {next_model}")
            
            return {
                "success": True,
                "custom_prompt": custom_prompt_data,
                "model_used": next_model,
                "message": f"Custom prompt regenerated successfully using {next_model}"
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to generate custom prompt")
        
    except HTTPException:
        raise
    except Exception as e:
        debug_print(f"Error regenerating custom prompt: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to regenerate custom prompt: {str(e)}")

# --- Background Tasks ---

@app.on_event("startup")
async def startup_event():
    """Initialize API server on startup"""
    debug_print("Starting Twitter Bot API Server...", force=True)
    debug_print(f"API Version: {API_VERSION}", force=True)
    debug_print(f"Max concurrent bots: {MAX_CONCURRENT_BOTS}", force=True)
    debug_print("API Server started successfully!", force=True)

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    debug_print("Shutting down API Server...", force=True)
    
    # Stop all running bots
    for user_id in list(bot_manager.bots.keys()):
        try:
            bot_manager.stop_bot(user_id)
        except Exception as e:
            debug_print(f"Error stopping bot {user_id} during shutdown: {e}", "WARNING")
    
    debug_print("API Server shutdown complete!", force=True)

# --- Background task to cleanup stopped bots ---
async def cleanup_task():
    """Background task to cleanup stopped bots"""
    while True:
        try:
            bot_manager.cleanup_stopped_bots()
            await asyncio.sleep(60)  # Run every minute
        except Exception as e:
            debug_print(f"Error in cleanup task: {e}", "WARNING")
            await asyncio.sleep(60)

# Start cleanup task
@app.on_event("startup")
async def start_cleanup_task():
    """Start the cleanup background task"""
    asyncio.create_task(cleanup_task())

# --- Main execution ---
if __name__ == "__main__":
    debug_print("Starting Twitter Bot API Server...", force=True)
    
    # Create bots directory if it doesn't exist
    Path("bots").mkdir(exist_ok=True)
    
    # Try to use SSL certificates if available
    ssl_cert_file = "/etc/letsencrypt/live/api.costras.com/fullchain.pem"
    ssl_key_file = "/etc/letsencrypt/live/api.costras.com/privkey.pem"
    
    if os.path.exists(ssl_cert_file) and os.path.exists(ssl_key_file):
        debug_print("🔐 SSL certificates found, starting server with HTTPS...", force=True)
        
        # Run the server with HTTPS
        uvicorn.run(
            "api_server:app",
            host="0.0.0.0",
            port=443,
            reload=DEBUG_MODE,
            log_level="info",
            ssl_keyfile=ssl_key_file,
            ssl_certfile=ssl_cert_file
        )
    else:
        debug_print("⚠️ SSL certificates not found, starting server on HTTP port 80...", force=True)
        
        # Run the server on HTTP port 80 instead of trying to generate self-signed certificates
        uvicorn.run(
            "api_server:app",
            host="0.0.0.0",
            port=80,
            reload=DEBUG_MODE,
            log_level="info"
        ) 