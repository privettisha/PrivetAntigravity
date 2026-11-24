#!/bin/sh
set -eu
if [ "$(id -u)" -eq 0 ]; then
  echo 'Запустите установку от обычного пользователя, без sudo.' >&2
  exit 1
fi
case "$(uname -m)" in x86_64) ;; *) echo 'Этот пакет предназначен для Linux x86_64.' >&2; exit 1;; esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
package_dir=$(dirname "$script_dir")
[ -f "$script_dir/PrivetAntigravity" ] && package_dir=$script_dir
app_dir="${XDG_DATA_HOME:-$HOME/.local/share}/PrivetAntigravity"
bin_dir="$HOME/.local/bin"
mkdir -p "$app_dir/bin" "$bin_dir" "$HOME/.local/share/applications"
install -m755 "$package_dir/PrivetAntigravity" "$app_dir/bin/PrivetAntigravity"
install -m644 "$package_dir/icon.svg" "$app_dir/icon.svg"
install -m644 "$package_dir/INSTRUCTION.txt" "$app_dir/INSTRUCTION.txt"
ln -sfn "$app_dir/bin/PrivetAntigravity" "$bin_dir/privetantigravity"
escaped_dir=$(printf '%s' "$app_dir" | sed 's/\\/\\\\/g;s/"/\\"/g;s/%/%%/g;s/`/\\`/g;s/\$/\\$/g')
cat > "$HOME/.local/share/applications/privetantigravity.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=PrivetAntigravity
Comment=Патч и настройка Antigravity
Exec="$escaped_dir/bin/PrivetAntigravity"
Icon=$app_dir/icon.svg
Terminal=true
Categories=Utility;Development;
DESKTOP
cat > "$HOME/.local/share/applications/privetantigravity-launch.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=PrivetAntigravity — запуск
Comment=Запустить Antigravity через локальную службу
Exec="$escaped_dir/bin/PrivetAntigravity" --launch
Icon=$app_dir/icon.svg
Terminal=false
Categories=Development;
DESKTOP
printf '\nУстановлено. Откройте PrivetAntigravity в меню приложений.\nИли запустите: %s/privetantigravity\n' "$bin_dir"
