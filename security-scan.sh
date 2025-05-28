#!/bin/bash

echo "🔒 Running comprehensive security scan..."
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Files to scan (only the ones that will be published)
FILES_TO_SCAN="index.js README.md package.json"

# Extended patterns to search for
declare -a PATTERNS=(
    # API Keys and Tokens
    "api[_-]?key"
    "apikey"
    "access[_-]?token"
    "auth[_-]?token"
    "authentication[_-]?token"
    "private[_-]?key"
    "secret[_-]?key"
    
    # Credentials
    "password"
    "passwd"
    "pwd"
    "credential"
    "username.*:.*password"
    
    # AWS
    "aws[_-]?access[_-]?key"
    "aws[_-]?secret"
    "AKIA[0-9A-Z]{16}"
    
    # URLs with embedded credentials
    "https?://[^:]+:[^@]+@"
    
    # Private keys
    "BEGIN.*PRIVATE KEY"
    "BEGIN.*RSA.*KEY"
    
    # Environment variables that might contain secrets
    "process\.env\.[A-Z_]*KEY"
    "process\.env\.[A-Z_]*SECRET"
    "process\.env\.[A-Z_]*TOKEN"
    
    # Base64 encoded secrets (common patterns)
    "ey[A-Za-z0-9+/]{20,}={0,2}"
    
    # Hex encoded secrets (32+ chars)
    "[0-9a-fA-F]{32,}"
    
    # JWT tokens
    "eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"
)

# Whitelist patterns (things we know are safe)
declare -a WHITELIST=(
    "crypto.randomBytes"
    "config.secret"
    "generateSyncHash"
    "sha256"
)

echo "Scanning files: $FILES_TO_SCAN"
echo ""

FOUND_ISSUES=0

for file in $FILES_TO_SCAN; do
    if [ -f "$file" ]; then
        echo "Scanning $file..."
        
        for pattern in "${PATTERNS[@]}"; do
            # Use grep with case-insensitive search
            matches=$(grep -inE "$pattern" "$file" 2>/dev/null || true)
            
            if [ ! -z "$matches" ]; then
                # Check if match is whitelisted
                is_whitelisted=false
                while IFS= read -r line; do
                    for whitelist in "${WHITELIST[@]}"; do
                        if echo "$line" | grep -q "$whitelist"; then
                            is_whitelisted=true
                            break
                        fi
                    done
                    
                    if [ "$is_whitelisted" = false ]; then
                        echo -e "${YELLOW}  ⚠️  Potential sensitive data (pattern: $pattern):${NC}"
                        echo "     $line"
                        FOUND_ISSUES=$((FOUND_ISSUES + 1))
                    fi
                done <<< "$matches"
            fi
        done
        
        # Special check for long strings that might be keys
        long_strings=$(grep -E "['\"][a-zA-Z0-9+/=-]{40,}['\"]" "$file" 2>/dev/null || true)
        if [ ! -z "$long_strings" ]; then
            echo -e "${YELLOW}  ⚠️  Found long strings that might be keys:${NC}"
            echo "$long_strings" | head -5
        fi
        
        echo -e "${GREEN}  ✓ Completed scanning $file${NC}"
        echo ""
    fi
done

# Check for common secret files that shouldn't exist
echo "Checking for secret files that shouldn't be present..."
SECRET_FILES=(".env" ".env.local" ".env.production" "config.json" "secrets.json" "credentials.json" ".npmrc")

for secret_file in "${SECRET_FILES[@]}"; do
    if [ -f "$secret_file" ]; then
        echo -e "${RED}  ❌ Found potentially sensitive file: $secret_file${NC}"
        FOUND_ISSUES=$((FOUND_ISSUES + 1))
    fi
done

echo ""
echo "========================================"
if [ $FOUND_ISSUES -eq 0 ]; then
    echo -e "${GREEN}✅ Security scan complete. No issues found!${NC}"
else
    echo -e "${RED}❌ Security scan found $FOUND_ISSUES potential issues. Please review above.${NC}"
    exit 1
fi 