#!/bin/bash

set -e

echo ""
echo "🛠️  Installing 'swarm-info' (Docker Swarm Information CLI)"
echo "=========================================================="

# Step 1: Create target directory and clone swarm-info
if [[ ! -d ~/tools/swarm-info/.git ]]; then
  echo "🔧 Cloning swarm-info..."
  mkdir -p ~/tools/swarm-info
  cd ~/tools/swarm-info
  git clone https://github.com/Sokrates1989/swarm-info.git .
else
  echo "ℹ️  swarm-info already cloned – skipping git clone."
  cd ~/tools/swarm-info
fi

# Step 2: Ensure script is executable
chmod +x ~/tools/swarm-info/get_info.sh

# Step 3: Create local bin directory if needed
mkdir -p ~/.local/bin

# Step 4: Create symlink
ln -sf ~/tools/swarm-info/get_info.sh ~/.local/bin/swarm-info
echo "✅ Shortcut 'swarm-info' created in ~/.local/bin"

# Step 5: Add ~/.local/bin to PATH persistently and immediately
EXPORT_LINE='export PATH="$HOME/.local/bin:$PATH"'

append_export_line() {
  local file="$1"
  if [ -f "$file" ]; then
    if ! grep -Fxq "$EXPORT_LINE" "$file"; then
      echo "$EXPORT_LINE" >> "$file"
      echo "✅ Added PATH update to $file"
    else
      echo "ℹ️  PATH already set in $file"
    fi
  fi
}

append_export_line "$HOME/.bashrc"
append_export_line "$HOME/.profile"

# Export for current shell
export PATH="$HOME/.local/bin:$PATH"

echo ""
echo "🚀 All set! You can now launch the Docker Swarm Information tool from any terminal with:"
echo ""
echo "   swarm-info"
echo ""
echo "🧩 If 'swarm-info' is not recognized yet, you can try the following to make it work immediately:"
echo '   export PATH="$HOME/.local/bin:$PATH"; hash -r'
