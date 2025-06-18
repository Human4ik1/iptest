#!/usr/bin/env bash

# Shell script to check IP country code from various sources
# Requires: curl, jq

DEPENDENCIES="jq curl"
INSTALL_CONFIRM="yes"

while [ $# -gt 0 ]; do
  case "$1" in
    --socks | --socks-port | -s)
      SOCKS_PORT="$2"
      shift 2
      ;;
    -y)
      INSTALL_CONFIRM="yes"
      shift
      ;;
    -n)
      INSTALL_CONFIRM="no"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [ -n "$SOCKS_PORT" ]; then
  export ALL_PROXY="socks5://127.0.0.1:$SOCKS_PORT"
  echo "Using SOCKS 127.0.0.1:$SOCKS_PORT"
fi

# Define services and their lookup functions
SERVICES=(
  "rdap.db.ripe.net:ripe_rdap_lookup:ripe_rdap_lookup_v6"
  "ipinfo.io:ipinfo_io_lookup:ipinfo_io_lookup_v6"
  "ipregistry.co:ipregistry_co_lookup:ipregistry_co_lookup_v6"
  "cloudflare.com:cloudflare_lookup:cloudflare_lookup_v6"
  "spotify.com:spotify_lookup:spotify_lookup_v6"
  "store.steampowered.com:steam_lookup:steam_lookup_v6"
  "youtube.com:youtube_lookup:youtube_lookup_v6"
  "netflix.com:netflix_lookup:netflix_lookup_v6"
  "apple.com:apple_lookup:apple_lookup_v6"
  "discord.com:discord_lookup:discord_lookup_v6"
  "ipapi.com:ipapi_com_lookup:ipapi_com_lookup_v6"
  "db-ip.com:db_ip_com_lookup:db_ip_com_lookup_v6"
  "ipdata.co:ipdata_co_lookup:ipdata_co_lookup_v6"
  "ipwhois.io:ipwhois_io_lookup:ipwhois_io_lookup_v6"
  "ifconfig.co:ifconfig_co_lookup:ifconfig_co_lookup_v6"
  "whoer.net:whoer_net_lookup:whoer_net_lookup_v6"
  "ipquery.io:ipquery_io_lookup:ipquery_io_lookup_v6"
  "country.is:country_is_lookup:country_is_lookup_v6"
  "ip-api.com:ip_api_com_lookup:ip_api_com_lookup_v6"
  "ipapi.co:ipapi_co_lookup:ipapi_co_lookup_v6"
  "findip.net:findip_net_lookup"
  "geojs.io:geojs_io_lookup:geojs_io_lookup_v6"
  "iplocation.com:iplocation_com_lookup:iplocation_com_lookup_v6"
  "geoapify.com:geoapify_com_lookup:geoapify_com_lookup_v6"
  "ipapi.is:ipapi_is_lookup:ipapi_is_lookup_v6"
  "freeipapi.com:freeipapi_com_lookup:freeipapi_com_lookup_v6"
  "ipbase.com:ipbase_com_lookup:ipbase_com_lookup_v6"
  "ip.sb:ip_sb_lookup:ip_sb_lookup_v6"
  "maxmind.com:maxmind_com_lookup:maxmind_com_lookup_v6"
  "ip2location.com:ip2location_com_lookup:ip2location_com_lookup_v6"
  "iplocation.net:iplocation_net_lookup:iplocation_net_lookup_v6"
  "ipstack.com:ipstack_com_lookup:ipstack_com_lookup_v6"
)

IDENTITY_SERVICES="https://ident.me https://ifconfig.me https://api64.ipify.org"
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
COLOR_BOLD_GREEN="\033[1;32;40m"
COLOR_BOLD_CYAN="\033[1;36;40m"
COLOR_BOLD_GRAY="\033[38;5;238;40m"
COLOR_BOLD_WHITE="\033[38;5;15;40m"
COLOR_RESET="\033[0m"

# Progress bar function
progress_bar() {
  local current=$1
  local total=$2
  local width=50
  local percent=$((current * 100 / total))
  local filled=$((width * current / total))
  local empty=$((width - filled))
  local bar=$(printf "%${filled}s" | tr ' ' '#')
  local spaces=$(printf "%${empty}s" | tr ' ' '-')
  printf "\rProgress: [${bar}${spaces}] %d%% Checking: %s" "$percent" "[$3]"
}

log_message() {
  local log_level="$1"
  local message="${*:2}"
  local timestamp=$(date +"%d.%m.%Y %H:%M:%S")
  echo "[$timestamp] [$log_level]: $message"
}

is_installed() {
  command -v "$1" >/dev/null 2>&1
}

install_dependencies() {
  local use_sudo=""
  local missing_packages=()

  if [ "$(id -u)" -ne 0 ]; then
    use_sudo="sudo"
  fi

  for pkg in $DEPENDENCIES; do
    if ! is_installed "$pkg"; then
      missing_packages+=("$pkg")
    fi
  done

  if [ ${#missing_packages[@]} -eq 0 ]; then
    return 0
  fi

  log_message "INFO" "Missing dependencies: ${missing_packages[*]}."
  if [ "$INSTALL_CONFIRM" == "no" ]; then
    log_message "INFO" "Exiting script due to -n flag"
    exit 0
  fi

  log_message "INFO" "Installing missing dependencies"
  if [ -d /data/data/com.termux ]; then
    log_message "INFO" "Detected Termux environment"
    apt update
    apt install -y "${missing_packages[@]}"
    return
  fi

  if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
      debian | ubuntu)
        $use_sudo apt update
        NEEDRESTART_MODE=a $use_sudo apt install -y "${missing_packages[@]}"
        ;;
      arch)
        $use_sudo pacman -Syy --noconfirm "${missing_packages[@]}"
        ;;
      fedora)
        $use_sudo dnf install -y "${missing_packages[@]}"
        ;;
      *)
        log_message "ERROR" "Unknown or unsupported distribution: $ID"
        exit 1
        ;;
    esac
  else
    log_message "ERROR" "File /etc/os-release not found, unable to determine distribution"
    exit 1
  fi
}

get_random_identity_service() {
  printf "%s" "$IDENTITY_SERVICES" | tr ' ' '\n' | shuf -n 1
}

get_ipv4() {
  external_ip=$(curl -4 -qs "$(get_random_identity_service)" 2>/dev/null)
  hidden_ip="$(printf "%s" "$external_ip" | cut -d'.' -f1-2).***.***"
}

get_ipv6() {
  external_ipv6=$(curl -6 -s https://6.ipwho.de/ip 2>/dev/null)
  hidden_ipv6=$(mask_ipv6 "$external_ipv6")
}

mask_ipv6() {
  local ipv6="$1"
  IFS=":" read -ra segments <<<"$ipv6"
  for i in "${!segments[@]}"; do
    if ((i > 1 && i < ${#segments[@]} - 2)); then
      segments[i]="****"
    fi
  done
  echo "${segments[*]}" | sed 's/ /:/g'
}

check_service() {
  local domain="$1"
  local lookup_function="$2"
  local lookup_function_v6="${3:-null}"
  local result result_v6

  result="$($lookup_function)"
  if [[ -n "$result" ]]; then
    domain_str="${COLOR_BOLD_GREEN}${domain}${COLOR_RESET}"
    padding_length=$((29 - ${#domain} - ${#result} - 2))
    padding=$(printf '%*s' "$padding_length" | tr ' ' '.')
    padding="${COLOR_BOLD_GRAY}${padding}${COLOR_RESET}"
    result="${COLOR_BOLD_WHITE}${result}${COLOR_RESET}"

    if [[ "$lookup_function_v6" == "null" ]]; then
      results+=("$domain_str$padding$result")
    else
      result_v6="$($lookup_function_v6)"
      if [[ "$result_v6" == "null" || -z "$result_v6" ]]; then
        results+=("$domain_str$padding$result")
      else
        result_v6="${COLOR_BOLD_WHITE}${result_v6}${COLOR_RESET}"
        results+=("$domain_str$padding$result${COLOR_BOLD_GRAY}........${COLOR_RESET}${result_v6}")
      fi
    fi
  fi
}

get_asn() {
  local ip="$1"
  asn_response=$(curl -s "https://ipinfo.io/widget/demo/$ip" | jq -r ".data.asn")
  asn=$(jq -r '.asn' <<<"$asn_response")
  asn_owner=$(jq -r '.name' <<<"$asn_response")
}

print_results() {
  get_asn "$external_ip"
  if [ -n "$IPV6_ADDR" ]; then
    printf "\n\n%bResults for IP %b%s %s %s%b\n\n" "${COLOR_BOLD_GREEN}" "${COLOR_BOLD_CYAN}" "$hidden_ip" "and" "$hidden_ipv6" "${COLOR_RESET}"
    printf "%bASN:%b %s, %s%b\n\n" "$COLOR_BOLD_GREEN" "$COLOR_BOLD_CYAN" "$asn" "$asn_owner" "${COLOR_RESET}"
    printf "                        IPv4      IPv6\n\n"
  else
    printf "\n\n%bResults for IP %b%s%b\n\n" "${COLOR_BOLD_GREEN}" "${COLOR_BOLD_CYAN}" "$hidden_ip" "${COLOR_RESET}"
    printf "%bASN:%b %s, %s%b\n\n" "$COLOR_BOLD_GREEN" "$COLOR_BOLD_CYAN" "$asn" "$asn_owner" "${COLOR_RESET}"
    printf "                        IPv4\n\n"
  fi

  for result in "${results[@]}"; do
    printf "%b\n" "$result"
  done
  printf "\n"
}

# Lookup functions
discord_lookup() {
  result=$(timeout 3 curl -4 -s "https://discord.com/api/v9/users/@me/settings" -H "User-Agent: ${USER_AGENT}" | jq -r ".locale" | grep -oP '^[A-Z]{2}' 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

discord_lookup_v6() {
  result=$(timeout 3 curl -6 -s "https://discord.com/api/v9/users/@me/settings" -H "User-Agent: ${USER_AGENT}" | jq -r ".locale" | grep -oP '^[A-Z]{2}' 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ripe_rdap_lookup() {
  result=$(timeout 3 curl -4 -s "https://rdap.db.ripe.net/ip/$external_ip" | jq -r ".country" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ripe_rdap_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://rdap.db.ripe.net/ip/$external_ipv6" | jq -r ".country" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipinfo_io_lookup() {
  result=$(timeout 3 curl -4 -s "https://ipinfo.io/widget/demo/$external_ip" | jq -r ".data.country" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipinfo_io_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://ipinfo.io/widget/demo/$external_ipv6" | jq -r ".data.country" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipregistry_co_lookup() {
  api_key="sb69ksjcajfs4c"
  result=$(timeout 3 curl -4 -s "https://api.ipregistry.co/$external_ip?hostname=true&key=$api_key" -H "Origin: https://ipregistry.co" | jq -r ".location.country.code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipregistry_co_lookup_v6() {
  api_key="sb69ksjcajfs4c"
  result=$(timeout 3 curl -4 -s "https://api.ipregistry.co/$external_ipv6?hostname=true&key=$api_key" -H "Origin: https://ipregistry.co" | jq -r ".location.country.code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

cloudflare_lookup() {
  result=$(timeout 3 curl -4 -s "https://www.cloudflare.com/cdn-cgi/trace" | grep loc | cut -d= -f2)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

cloudflare_lookup_v6() {
  result=$(timeout 3 curl -6 -s "https://www.cloudflare.com/cdn-cgi/trace" | grep loc | cut -d= -f2)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

spotify_lookup() {
  result=$(curl -4 -s 'https://spclient.wg.spotify.com/signup/public/v1/account' -d "birth_day=11&birth_month=11&birth_year=2000&collect_personal_info=undefined&creation_flow=&creation_point=https%3A%2F%2Fwww.spotify.com%2Fhk-en%2F&displayname=Gay%20Lord&gender=male&iagree=1&key=a1e486e2729f46d6bb368d6b2bcda326&platform=www&referrer=&send-email=0&thirdpartyemail=0&identifier_token=AgE6YTvEzkReHNfJpO114514" -X POST -H "Accept-Language: en" --user-agent "${USER_AGENT}" | jq -r ".country")
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

spotify_lookup_v6() {
  result=$(curl -6 -s 'https://spclient.wg.spotify.com/signup/public/v1/account' -d "birth_day=11&birth_month=11&birth_year=2000&collect_personal_info=undefined&creation_flow=&creation_point=https%3A%2F%2Fwww.spotify.com%2Fhk-en%2F&displayname=Gay%20Lord&gender=male&iagree=1&key=a1e486e2729f46d6bb368d6b2bcda326&platform=www&referrer=&send-email=0&thirdpartyemail=0&identifier_token=AgE6YTvEzkReHNfJpO114514" -X POST -H "Accept-Language: en" --user-agent "${USER_AGENT}" | jq -r ".country")
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

steam_lookup() {
  result=$(timeout 3 curl -4 -s "https://store.steampowered.com/" | grep -o '"countrycode":"[^"]*"' | sed -E 's/.*:"([^"]*)"/\1/')
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

steam_lookup_v6() {
  result=$(timeout 3 curl -6 -s "https://store.steampowered.com/" | grep -o '"countrycode":"[^"]*"' | sed -E 's/.*:"([^"]*)"/\1/')
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

youtube_lookup() {
  result=$(timeout 3 curl -4 -s --user-agent "$USER_AGENT" https://www.google.com | sed -n 's/.*"[a-z]\{2\}_\([A-Z]\{2\}\)".*/\1/p')
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

youtube_lookup_v6() {
  result=$(timeout 3 curl -6 -s --user-agent "$USER_AGENT" https://www.google.com | sed -n 's/.*"[a-z]\{2\}_\([A-Z]\{2\}\)".*/\1/p')
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

netflix_lookup() {
  local result1=$(timeout 3 curl -4 -fsL 'https://www.netflix.com/title/81280792' -w %{http_code} -o /dev/null -H 'host: www.netflix.com' -H 'accept-language: en-US,en;q=0.9' -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-site: none' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-user: ?1' -H 'sec-fetch-dest: document' --user-agent "${USER_AGENT}")
  local result2=$(timeout 3 curl -4 -fsL 'https://www.netflix.com/title/70143836' -w %{http_code} -o /dev/null -H 'host: www.netflix.com' -H 'accept-language: en-US,en;q=0.9' -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-site: none' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-user: ?1' -H 'sec-fetch-dest: document' --user-agent "${USER_AGENT}")
  if [ "$result1" == '200' ] || [ "$result2" == '200' ]; then
    local tmpresult=$(timeout 3 curl -4 -sL 'https://www.netflix.com/' -H 'accept-language: en-US,en;q=0.9' -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-site: none' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-user: ?1' -H 'sec-fetch-dest: document' --user-agent "${USER_AGENT}")
    result=$(echo "$tmpresult" | grep -oP '"id":"\K[^"]+' | grep -E '^[A-Z]{2}$' | head -n 1)
  fi
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

netflix_lookup_v6() {
  local result1=$(timeout 3 curl -6 -fsL 'https://www.netflix.com/title/81280792' -w %{http_code} -o /dev/null -H 'host: www.netflix.com' -H 'accept-language: en-US,en;q=0.9' -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-site: none' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-user: ?1' -H 'sec-fetch-dest: document' --user-agent "${USER_AGENT}")
  local result2=$(timeout 3 curl -6 -fsL 'https://www.netflix.com/title/70143836' -w %{http_code} -o /dev/null -H 'host: www.netflix.com' -H 'accept-language: en-US,en;q=0.9' -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-site: none' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-user: ?1' -H 'sec-fetch-dest: document' --user-agent "${USER_AGENT}")
  if [ "$result1" == '200' ] || [ "$result2" == '200' ]; then
    local tmpresult=$(timeout 3 curl -6 -sL 'https://www.netflix.com/' -H 'accept-language: en-US,en;q=0.9' -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-site: none' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-user: ?1' -H 'sec-fetch-dest: document' --user-agent "${USER_AGENT}")
    result=$(echo "$tmpresult" | grep -oP '"id":"\K[^"]+' | grep -E '^[A-Z]{2}$' | head -n 1)
  fi
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

apple_lookup() {
  result=$(timeout 3 curl -4 -sL 'https://gspe1-ssl.ls.apple.com/pep/gcc')
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

apple_lookup_v6() {
  result=$(timeout 3 curl -6 -sL 'https://gspe1-ssl.ls.apple.com/pep/gcc')
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipapi_com_lookup() {
  result=$(timeout 3 curl -4 -s "https://ipapi.com/ip_api.php?ip=$external_ip" | jq -r ".country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipapi_com_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://ipapi.com/ip_api.php?ip=$external_ipv6" | jq -r ".country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

db_ip_com_lookup() {
  result=$(timeout 3 curl -4 -s "https://db-ip.com/demo/home.php?s=$external_ip" | jq -r ".demoInfo.countryCode" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

db_ip_com_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://db-ip.com/demo/home.php?s=$external_ipv6" | jq -r ".demoInfo.countryCode" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipdata_co_lookup() {
  html=$(timeout 3 curl -4 -s "https://ipdata.co")
  api_key=$(printf "%s" "$html" | grep -oP '(?<=api-key=)[a-zA-Z0-9]+')
  result=$(timeout 3 curl -4 -s -H "Referer: https://ipdata.co" "https://api.ipdata.co/?api-key=$api_key" | jq -r ".country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipdata_co_lookup_v6() {
  html=$(timeout 3 curl -6 -s "https://ipdata.co")
  api_key=$(printf "%s" "$html" | grep -oP '(?<=api-key=)[a-zA-Z0-9]+')
  result=$(timeout 3 curl -6 -s -H "Referer: https://ipdata.co" "https://api.ipdata.co/?api-key=$api_key" | jq -r ".country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipwhois_io_lookup() {
  result=$(timeout 3 curl -4 -s -H "Referer: https://ipwhois.io" "https://ipwhois.io/widget?ip=$external_ip&lang=en" | jq -r ".country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipwhois_io_lookup_v6() {
  result=$(timeout 3 curl -4 -s -H "Referer: https://ipwhois.io" "https://ipwhois.io/widget?ip=$external_ipv6&lang=en" | jq -r ".country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ifconfig_co_lookup() {
  result=$(timeout 3 curl -4 -s "https://ifconfig.co/country-iso?ip=$external_ip")
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ifconfig_co_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://ifconfig.co/country-iso?ip=$external_ipv6")
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

whoer_net_lookup() {
  result=$(timeout 3 curl -4 -s "https://whoer.net/whois?host=$external_ip" | grep "country" | awk 'NR==1 {print $2}')
  [[ $? -eq 124 || "$result" == "null" || "$result" == "ZZ" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

whoer_net_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://whoer.net/whois?host=$external_ipv6" | grep "country" | awk 'NR==1 {print $2}')
  [[ $? -eq 124 || "$result" == "null" || "$result" == "ZZ" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipquery_io_lookup() {
  result=$(timeout 3 curl -4 -s "https://api.ipquery.io/$external_ip" | jq -r ".location.country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipquery_io_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://api.ipquery.io/$external_ipv6" | jq -r ".location.country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

country_is_lookup() {
  result=$(timeout 3 curl -4 -s "https://api.country.is/$external_ip" | jq -r ".country" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

country_is_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://api.country.is/$external_ipv6" | jq -r ".country" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ip_api_com_lookup() {
  result=$(timeout 3 curl -4 -s "https://demo.ip-api.com/json/$external_ip" -H "Origin: https://ip-api.com" | jq -r ".countryCode" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ip_api_com_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://demo.ip-api.com/json/$external_ipv6" -H "Origin: https://ip-api.com" | jq -r ".countryCode" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipapi_co_lookup() {
  result=$(timeout 3 curl -4 -s "https://ipapi.co/$external_ip/json" | jq -r ".country" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipapi_co_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://ipapi.co/$external_ipv6/json" | jq -r ".country" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

findip_net_lookup() {
  cookie_file=$(mktemp)
  html=$(curl -s -c "$cookie_file" "https://findip.net")
  request_verification_token=$(printf "%s" "$html" | grep -oP 'value="\K[^"]+')
  response=$(timeout 3 curl -s -X POST "https://findip.net" \
    --data-urlencode "__RequestVerificationToken=$request_verification_token" \
    --data-urlencode "ip=$external_ip" \
    -b "$cookie_file")
  rm "$cookie_file"
  [[ $? -eq 124 ]] && echo "" || printf "%s" "$response" | grep -oP 'ISO Code: <span class="text-success">\K[^<]+'
}

geojs_io_lookup() {
  result=$(timeout 3 curl -4 -s "https://get.geojs.io/v1/ip/country.json?ip=$external_ip" | jq -r ".[0].country" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

geojs_io_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://get.geojs.io/v1/ip/country.json?ip=$external_ipv6" | jq -r ".[0].country" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

iplocation_com_lookup() {
  result=$(timeout 3 curl -4 -s -X POST "https://iplocation.com" -A "$USER_AGENT" --form "ip=$external_ip" | jq -r ".country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

iplocation_com_lookup_v6() {
  result=$(timeout 3 curl -4 -s -X POST "https://iplocation.com" -A "$USER_AGENT" --form "ip=$external_ipv6" | jq -r ".country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

geoapify_com_lookup() {
  api_key="b8568cb9afc64fad861a69edbddb2658"
  result=$(timeout 3 curl -4 -s "https://api.geoapify.com/v1/ipinfo?&ip=$external_ip&apiKey=$api_key" | jq -r ".country.iso_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

geoapify_com_lookup_v6() {
  api_key="b8568cb9afc64fad861a69edbddb2658"
  result=$(timeout 3 curl -4 -s "https://api.geoapify.com/v1/ipinfo?&ip=$external_ipv6&apiKey=$api_key" | jq -r ".country.iso_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipapi_is_lookup() {
  result=$(timeout 3 curl -4 -s "https://api.ipapi.is/?q=$external_ip" | jq -r ".location.country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipapi_is_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://api.ipapi.is/?q=$external_ipv6" | jq -r ".location.country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

freeipapi_com_lookup() {
  result=$(timeout 3 curl -4 -s "https://freeipapi.com/api/json/$external_ip" | jq -r ".countryCode" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

freeipapi_com_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://freeipapi.com/api/json/$external_ipv6" | jq -r ".countryCode" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipbase_com_lookup() {
  result=$(timeout 3 curl -4 -s "https://api.ipbase.com/v2/info?ip=$external_ip" | jq -r ".data.location.country.alpha2" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipbase_com_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://api.ipbase.com/v2/info?ip=$external_ipv6" | jq -r ".data.location.country.alpha2" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ip_sb_lookup() {
  result=$(timeout 3 curl -4 -s "https://api.ip.sb/geoip/$external_ip" -A "$USER_AGENT" | jq -r ".country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ip_sb_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://api.ip.sb/geoip/$external_ipv6" -A "$USER_AGENT" | jq -r ".country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

maxmind_com_lookup() {
  result=$(timeout 3 curl -4 -s "https://geoip.maxmind.com/geoip/v2.1/city/me" -H "Referer: https://www.maxmind.com" | jq -r ".country.iso_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

maxmind_com_lookup_v6() {
  result=$(timeout 3 curl -6 -s "https://geoip.maxmind.com/geoip/v2.1/city/me" -H "Referer: https://www.maxmind.com" | jq -r ".country.iso_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ip2location_com_lookup() {
  result=$(timeout 3 curl -4 -s "https://api.ip2location.io/?ip=$external_ip" | jq -r ".country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ip2location_com_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://api.ip2location.io/?ip=$external_ipv6" | jq -r ".country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

iplocation_net_lookup() {
  result=$(timeout 3 curl -4 -s "https://api.iplocation.net/?ip=$external_ip" | jq -r ".country_code2" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

iplocation_net_lookup_v6() {
  result=$(timeout 3 curl -4 -s "https://api.iplocation.net/?ip=$external_ipv6" | jq -r ".country_code2" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipstack_com_lookup() {
  api_key="your_ipstack_api_key" # Replace with actual API key
  result=$(timeout 3 curl -4 -s "http://api.ipstack.com/$external_ip?access_key=$api_key" | jq -r ".country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

ipstack_com_lookup_v6() {
  api_key="your_ipstack_api_key" # Replace with actual API key
  result=$(timeout 3 curl -4 -s "http://api.ipstack.com/$external_ipv6?access_key=$api_key" | jq -r ".country_code" 2>/dev/null)
  [[ $? -eq 124 || "$result" == "null" || ${#result} -gt 7 ]] && echo "" || echo "$result"
}

main() {
  install_dependencies
  declare -a results
  get_ipv4
  IPV6_ADDR=$(ip -o -6 addr show scope global 2>/dev/null | awk '{split($4, a, "/"); print a[1]; exit}')
  if [ -n "$IPV6_ADDR" ]; then
    get_ipv6
  fi

  total_services=${#SERVICES[@]}
  current_service=0

  for service in "${SERVICES[@]}"; do
    IFS=':' read -r domain lookup_function lookup_function_v6 <<< "$service"
    ((current_service++))
    progress_bar $current_service $total_services "$domain"
    if [ -n "$IPV6_ADDR" ]; then
      check_service "$domain" "$lookup_function" "$lookup_function_v6"
    else
      check_service "$domain" "$lookup_function"
    fi
  done
  printf "\n"

  print_results
}

main
