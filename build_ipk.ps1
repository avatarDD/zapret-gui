# build_ipk.ps1 — Сборка ipk-пакета для Entware (Windows)
$ErrorActionPreference = "Stop"

$PKG_NAME = "zapret-gui"
$raw = Get-Content core/version.py -Raw
if ($raw -match 'GUI_VERSION\s*=\s*"([^"]+)"') { $PKG_VERSION = $Matches[1] } else { throw "version not found" }
$PKG_RELEASE = "1"
$PKG_ARCH = "all"
$PKG_FULLNAME = "${PKG_NAME}_${PKG_VERSION}-${PKG_RELEASE}_${PKG_ARCH}"

$DEST_APP = "/opt/share/$PKG_NAME"
$DEST_CONFIG = "/opt/etc/$PKG_NAME"
$DEST_INITD = "/opt/etc/init.d"

$BUILD_DIR = "build"
$DATA_DIR = "$BUILD_DIR/data"
$CONTROL_DIR = "$BUILD_DIR/control"
$IPK_DIR = "$BUILD_DIR/ipk"
$DIST_DIR = "dist"

$APP_DIRS = @("api", "core", "config", "web", "catalogs", "data", "import", "vendor", "tests")

Write-Host "=== Сборка $PKG_FULLNAME.ipk ===" -ForegroundColor Cyan

# 1. Очистка
Write-Host "--- Очистка ---" -ForegroundColor Yellow
if (Test-Path $BUILD_DIR) { Remove-Item -Recurse -Force $BUILD_DIR }
if (-not (Test-Path $DIST_DIR)) { New-Item -ItemType Directory -Path $DIST_DIR | Out-Null }

# 2. Подготовка data
Write-Host "--- Подготовка data ---" -ForegroundColor Yellow
New-Item -ItemType Directory -Path "$DATA_DIR$DEST_APP" -Force | Out-Null
New-Item -ItemType Directory -Path "$DATA_DIR$DEST_CONFIG" -Force | Out-Null
New-Item -ItemType Directory -Path "$DATA_DIR$DEST_INITD" -Force | Out-Null
New-Item -ItemType Directory -Path "$DATA_DIR/opt/var/log" -Force | Out-Null
New-Item -ItemType Directory -Path "$DATA_DIR/opt/bin" -Force | Out-Null

Copy-Item "app.py" "$DATA_DIR$DEST_APP/"
foreach ($dir in $APP_DIRS) {
    if (Test-Path $dir) { Copy-Item -Recurse $dir "$DATA_DIR$DEST_APP/" }
}

Get-ChildItem -Path $DATA_DIR -Directory -Recurse -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $DATA_DIR -File -Recurse -Include "*.pyc","*.pyo",".DS_Store" | Remove-Item -Force -ErrorAction SilentlyContinue

Copy-Item "packaging/entware/S99zapret-gui" "$DATA_DIR$DEST_INITD/S99zapret-gui"
Copy-Item "packaging/entware/zapret-gui-cli" "$DATA_DIR/opt/bin/zapret-gui"

Write-Host "  data: OK" -ForegroundColor Green

# 3. Подготовка control
Write-Host "--- Подготовка control ---" -ForegroundColor Yellow
New-Item -ItemType Directory -Path $CONTROL_DIR -Force | Out-Null
Copy-Item "packaging/entware/control" "$CONTROL_DIR/control"
Copy-Item "packaging/entware/postinst" "$CONTROL_DIR/postinst"
Copy-Item "packaging/entware/prerm" "$CONTROL_DIR/prerm"
Copy-Item "packaging/entware/conffiles" "$CONTROL_DIR/conffiles"

$control = Get-Content "$CONTROL_DIR/control" -Raw
$control = $control -replace "@VERSION@", "$PKG_VERSION-$PKG_RELEASE"
$dataSize = (Get-ChildItem -Path $DATA_DIR -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1KB
$control = $control -replace "@SIZE@", [math]::Round($dataSize)
Set-Content "$CONTROL_DIR/control" $control

Write-Host "  control: OK" -ForegroundColor Green

# 4. Сборка ipk
Write-Host "--- Сборка ipk ---" -ForegroundColor Yellow
New-Item -ItemType Directory -Path $IPK_DIR -Force | Out-Null

Set-Content "$IPK_DIR/debian-binary" "2.0"

Push-Location $CONTROL_DIR
tar czf "../../$IPK_DIR/control.tar.gz" ./*
Pop-Location

Push-Location $DATA_DIR
tar czf "../../$IPK_DIR/data.tar.gz" ./*
Pop-Location

$ipkPath = "$DIST_DIR/$PKG_FULLNAME.ipk"
if (Test-Path $ipkPath) { Remove-Item $ipkPath }

Push-Location $IPK_DIR
tar cf "../../$ipkPath" debian-binary control.tar.gz data.tar.gz
Pop-Location

Write-Host ""
Write-Host "=== Готово ===" -ForegroundColor Green
Write-Host "Пакет: $ipkPath"
$sizeMB = [math]::Round((Get-Item $ipkPath).Length / 1MB, 2)
Write-Host "Размер: $sizeMB MB"
$hash = (Get-FileHash $ipkPath -Algorithm SHA256).Hash
$hashLower = $hash.ToLower()
Write-Host "SHA256: $hashLower"
