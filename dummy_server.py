import sqlite3
import uvicorn
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse

# Initialize the core application
app = FastAPI(title="Stealth Hunter Calibration Target")

# ==========================================
# 1. SQL INJECTION (SQLi) CALIBRATION
# ==========================================
@app.get("/api/users")
def get_user_data(id: str = Query(..., description="The user ID to fetch")):
    """Intentionally vulnerable endpoint simulating a legacy database query."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    
    cursor.execute("CREATE TABLE users (id INTEGER, username TEXT, role TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'admin_erp', 'SuperAdmin')")
    cursor.execute("INSERT INTO users VALUES (2, 'guest', 'Viewer')")
    
    # THE FLAW: Direct string concatenation
    query = f"SELECT username, role FROM users WHERE id = {id}"
    
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        return {"status": "success", "data": result}
    except sqlite3.OperationalError as e:
        # Returns a 200 OK but leaks the syntax error to the scanner
        return {"status": "error", "message": f"Database syntax error: {str(e)}"}

# ==========================================
# 2. CROSS-SITE SCRIPTING (XSS) CALIBRATION
# ==========================================
@app.get("/search", response_class=HTMLResponse)
def search(q: str = Query("")):
    """Intentionally reflects user input directly into the DOM without sanitization."""
    # THE FLAW: No HTML escaping
    html_content = f"""
    <html>
        <body>
            <h2>Search Results for: {q}</h2>
            <p>No results found.</p>
        </body>
    </html>
    """
    return html_content

# ==========================================
# 3. OPEN REDIRECT CALIBRATION
# ==========================================
@app.get("/login")
def login(redirect: str = Query(None)):
    """Intentionally allows unvalidated external redirects after 'login'."""
    # THE FLAW: Blindly trusting the redirect parameter
    if redirect:
        return RedirectResponse(url=redirect, status_code=302)
    return {"message": "Provide a redirect parameter to proceed."}

# ==========================================
# 4. EXPOSED .ENV CALIBRATION
# ==========================================
@app.get("/.env", response_class=PlainTextResponse)
def get_env():
    """Simulates a misconfigured web server serving environment variables."""
    return "DB_HOST=127.0.0.1\nDB_PASSWORD=super_secret_admin_pass\nAPI_KEY=xyz123"

if __name__ == "__main__":
    print("[*] Starting Stealth Hunter Calibration Server on http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
  
