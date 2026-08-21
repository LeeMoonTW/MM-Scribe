#!/usr/bin/env bash
# ============================================================
#  MM Scribe — 發版腳本
#
#  用途:把「改版號 → commit → 打 tag → 推上去 → 開 draft release」
#        這串固定動作收成一個指令,順序或步驟漏掉的機會降到零。
#
#  原始碼檔名不再帶版號 (見 RELEASING.md),版號的唯一來源是
#  Source/MabinogiMobileScribe_Beta.py 裡的 VERSION_STR。本腳本負責
#  讓 VERSION_STR 與 git tag 永遠對得上 — 這也是 build-macos.yml
#  決定發布 zip 檔名的依據。
#
#  用法:
#    ./release.sh 0.53                 版號 0.53,tag 自動補成 v0.53-beta-mac
#    ./release.sh v0.53-beta-mac       直接指定完整 tag 名
#    ./release.sh 0.53 --dry-run       只印出會做什麼,不動任何東西
#    ./release.sh 0.53 --no-push       只在本機 commit + tag,不推遠端
#    ./release.sh --help               完整選項說明
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

SRC="Source/MabinogiMobileScribe_Beta.py"
TAG_SUFFIX="-beta-mac"   # 只給了數字時補在後面,沿用 v0.50-beta-mac / v0.52-beta-mac 的慣例
REMOTE="origin"
BRANCH="main"

DRY_RUN=0
DO_PUSH=1
ASSUME_YES=0
MAKE_RELEASE="auto"      # auto = 裝了 gh 就開 draft release,沒裝就略過
VERSION_INPUT=""

usage() {
    cat <<'EOF'
用法: ./release.sh <版號|完整tag> [選項]

參數:
  <版號>            例如 0.53 — 會補成 tag v0.53-beta-mac
  <完整tag>         例如 v0.53-beta-mac 或 v1.0 — 原樣使用

選項:
  --dry-run         只印出將要執行的指令,不做任何實際變更
  --no-push         做完本機 commit 與 tag 就停,不推遠端(也不開 release)
  --no-release      推 tag,但不建立 GitHub draft release
  --release         強制建立 draft release(沒有 gh 指令時會直接失敗)
  --remote <名稱>   推送目標,預設 origin
  --branch <名稱>   允許發版的分支,預設 main
  -y, --yes         不要互動確認,直接執行(給 CI 或很有把握時用)
  -h, --help        顯示這段說明

流程:
  1. 檢查:分支、工作區乾淨、與遠端同步、tag 尚未存在
  2. 把 VERSION_STR 改成新版號並 commit(已經是新版號就跳過)
  3. 打 annotated tag
  4. 推送分支與 tag → 觸發 .github/workflows/build-macos.yml 建置 .app
  5. 建立 draft release,讓 workflow 建好的 zip 有地方掛

詳細說明見 RELEASING.md
EOF
}

die() { echo "[錯誤] $*" >&2; exit 1; }
info() { echo "  $*"; }
step() { echo; echo "── $* ──"; }

# 印出指令再執行;--dry-run 時只印不跑。
# 所有會改到 repo 或遠端的動作都必須走這裡,否則 --dry-run 就不成立了。
run() {
    # 帶空白的參數補上引號,印出來的指令才能直接複製貼上重跑
    local shown="" arg
    for arg in "$@"; do
        case "$arg" in
            ""|*[[:space:]]*) shown="${shown} \"${arg}\"" ;;
            *)                shown="${shown} ${arg}" ;;
        esac
    done
    echo "  \$${shown}"
    [[ "$DRY_RUN" -eq 1 ]] && return 0
    "$@"
}

# ------------------------------------------------------------
# 參數
# ------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)    usage; exit 0 ;;
        --dry-run)    DRY_RUN=1 ;;
        --no-push)    DO_PUSH=0 ;;
        --no-release) MAKE_RELEASE="no" ;;
        --release)    MAKE_RELEASE="yes" ;;
        -y|--yes)     ASSUME_YES=1 ;;
        --remote)     shift; [[ $# -gt 0 ]] || die "--remote 後面要接遠端名稱"; REMOTE="$1" ;;
        --branch)     shift; [[ $# -gt 0 ]] || die "--branch 後面要接分支名稱"; BRANCH="$1" ;;
        -*)           die "不認得的選項: $1(用 --help 看說明)" ;;
        *)
            [[ -z "$VERSION_INPUT" ]] || die "只能給一個版號,已經收到「${VERSION_INPUT}」又收到「$1」"
            VERSION_INPUT="$1"
            ;;
    esac
    shift
done

[[ -n "$VERSION_INPUT" ]] || { usage; exit 1; }

# ------------------------------------------------------------
# 版號 / tag 名稱
# ------------------------------------------------------------
# 允許兩種輸入:純數字 (0.53) 或完整 tag (v0.53-beta-mac)。
# 統一成 TAG(推上去的名字) 與 NUM(寫進 VERSION_STR 的數字)。
if [[ "$VERSION_INPUT" == v* ]]; then
    TAG="$VERSION_INPUT"
else
    TAG="v${VERSION_INPUT}${TAG_SUFFIX}"
fi
NUM="${TAG#v}"
NUM="${NUM%%-*}"

[[ "$NUM" =~ ^[0-9]+(\.[0-9]+)*$ ]] \
    || die "從「${TAG}」取不出合理的版號 (得到「${NUM}」)。預期像 0.53 或 v0.53-beta-mac"

# 名字不合法的話,git tag 要到最後一步才會失敗 — 那時 VERSION_STR 已經
# commit 下去了,會留下一個沒有對應 tag 的版號 commit。先擋在這裡。
git check-ref-format "refs/tags/${TAG}" \
    || die "「${TAG}」不是合法的 git tag 名稱 (不能有空白、~^:?*[、連續的點等)"

[[ -f "$SRC" ]] || die "找不到原始碼 ${SRC} — 這支腳本要放在專案根目錄執行"

# VERSION_STR 只換數字,前後綴 (Beta / V) 原樣保留,
# 這樣哪天從 "Beta V0.52" 改成 "V1.0" 也不必回來改腳本。
read_version_str() {
    sed -n 's/^VERSION_STR[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$SRC" | head -1
}

# sed 的 replacement 裡 & 代表「整個 match」、\ 是跳脫字元、/ 會撞到 s/// 的分隔符。
# NEW_VER 是從檔案裡既有的字串衍生出來的,使用者自訂前後綴時就可能帶到這些字元,
# 不跳脫的話會把原始碼寫壞(而且是在讀回驗證之前就已經覆蓋掉了)。
escape_sed_replacement() {
    printf '%s' "$1" | sed -e 's/[\\&/]/\\&/g'
}

CURRENT_VER="$(read_version_str)"
[[ -n "$CURRENT_VER" ]] || die "在 ${SRC} 裡找不到 VERSION_STR = \"...\""
NEW_VER="$(printf '%s' "$CURRENT_VER" | sed "s/[0-9][0-9.]*/${NUM}/")"

# ------------------------------------------------------------
# 前置檢查
# ------------------------------------------------------------
step "檢查"

git rev-parse --git-dir >/dev/null 2>&1 || die "這裡不是 git repo"

CUR_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
# detached HEAD 時 --abbrev-ref 回的是字面上的 "HEAD"。不特別擋的話,
# 下面那句 die 會建議 --branch HEAD,而那組合能通過所有檢查一路跑到 git push,
# 等於把人導向一個更難收拾的狀態。
if [[ "$CUR_BRANCH" == "HEAD" ]]; then
    die "目前是 detached HEAD,不在任何分支上。先 git checkout ${BRANCH} 再發版"
fi
if [[ "$CUR_BRANCH" != "$BRANCH" ]]; then
    die "目前在 ${CUR_BRANCH},發版預期在 ${BRANCH}。要從這個分支發版請加 --branch ${CUR_BRANCH}"
fi
info "分支          : ${CUR_BRANCH}"

# 工作區必須乾淨:待會要 commit VERSION_STR,夾帶到別的改動就洗不掉了
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    git status --short --untracked-files=no >&2
    die "工作區有未提交的改動,先 commit 或 stash"
fi
info "工作區        : 乾淨"

git ls-remote --exit-code "$REMOTE" >/dev/null 2>&1 || die "連不上遠端 ${REMOTE}"

# 這行刻意不走 run():--dry-run 也必須真的 fetch,否則下面的 ahead/behind 是拿
# 過期的 refs/remotes 算的,會在最需要它的落後 / 分歧情境給出全綠的假答案。
# fetch 只寫 refs/remotes 與本機 tag,不動工作區也不動任何分支。
echo "  \$ git fetch --quiet ${REMOTE} --tags   (--dry-run 也會執行:只更新遠端追蹤 ref)"
git fetch --quiet "$REMOTE" --tags

# tag 已存在就停手。覆蓋既有 tag 會讓已經下載過的人拿到對不上的版本,
# 要重打得由人明確決定,腳本不代勞。
if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
    die "tag ${TAG} 在本機已存在。真要重打:git tag -d ${TAG} && git push ${REMOTE} :refs/tags/${TAG}"
fi
if git ls-remote --tags --exit-code "$REMOTE" "refs/tags/${TAG}" >/dev/null 2>&1; then
    die "tag ${TAG} 在 ${REMOTE} 已存在。真要重打:git push ${REMOTE} :refs/tags/${TAG}"
fi
info "tag ${TAG} : 可用"

# 遠端有本機沒有的 commit 時,tag 會打在少東西的版本上,而且待會 git push 也會被拒
if git rev-parse -q --verify "refs/remotes/${REMOTE}/${BRANCH}" >/dev/null; then
    BEHIND="$(git rev-list --count "HEAD..${REMOTE}/${BRANCH}")"
    AHEAD="$(git rev-list --count "${REMOTE}/${BRANCH}..HEAD")"
    if [[ "$BEHIND" -gt 0 && "$AHEAD" -gt 0 ]]; then
        die "與 ${REMOTE}/${BRANCH} 分歧了 (本機領先 ${AHEAD}、落後 ${BEHIND})。
       先決定要 rebase 還是覆蓋遠端,處理完再發版。"
    elif [[ "$BEHIND" -gt 0 ]]; then
        die "落後 ${REMOTE}/${BRANCH} ${BEHIND} 個 commit,先 git pull"
    fi
    info "與遠端        : 領先 ${AHEAD} 個 commit,沒有落後"
else
    info "與遠端        : ${REMOTE}/${BRANCH} 尚不存在,將由本次推送建立"
fi

# GitHub release 只有 gh 存在且登入過才能開
GH_OK=0
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    GH_OK=1
fi
case "$MAKE_RELEASE" in
    yes) [[ "$GH_OK" -eq 1 ]] || die "指定了 --release,但 gh 不存在或尚未登入 (gh auth login)" ;;
    auto) MAKE_RELEASE=$([[ "$GH_OK" -eq 1 ]] && echo yes || echo no) ;;
esac
[[ "$DO_PUSH" -eq 1 ]] || MAKE_RELEASE="no"

# ------------------------------------------------------------
# 確認
# ------------------------------------------------------------
step "即將執行"
if [[ "$CURRENT_VER" == "$NEW_VER" ]]; then
    info "VERSION_STR   : 「${CURRENT_VER}」已經是目標版號,不會產生 commit"
else
    info "VERSION_STR   : 「${CURRENT_VER}」→「${NEW_VER}」(會產生一個 commit)"
fi
# 會產生版號 commit 的話,tag 落在那個還不存在的 commit 上,不是現在的 HEAD —
# 在要求 [y/N] 的畫面上印一個 tag 不會落到的 sha 只會誤導。
if [[ "$CURRENT_VER" == "$NEW_VER" ]]; then
    info "tag           : ${TAG}  (annotated,打在 $(git rev-parse --short HEAD))"
else
    info "tag           : ${TAG}  (annotated,打在即將產生的版號 commit 上)"
fi
if [[ "$DO_PUSH" -eq 1 ]]; then
    info "推送          : ${REMOTE} ${BRANCH} + ${TAG} → 觸發 macOS 建置"
else
    info "推送          : 略過 (--no-push)"
fi
if [[ "$MAKE_RELEASE" == "yes" ]]; then
    info "draft release : 會建立 (草稿,不會直接公開)"
else
    info "draft release : 略過"
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
    step "以下是 --dry-run,只印指令不執行"
elif [[ "$ASSUME_YES" -eq 0 ]]; then
    echo
    printf "確定要發版 %s ? [y/N] " "$TAG"
    # 沒有 tty 時 read 會直接 EOF,那就當成沒答應 — 發版不該在非互動環境靜默進行
    read -r reply || reply=""
    [[ "$reply" == "y" || "$reply" == "Y" ]] || die "已取消"
fi

# ------------------------------------------------------------
# 1. 更新 VERSION_STR
# ------------------------------------------------------------
if [[ "$CURRENT_VER" != "$NEW_VER" ]]; then
    step "更新 VERSION_STR"
    echo "  \$ sed -i 's/VERSION_STR = \"${CURRENT_VER}\"/VERSION_STR = \"${NEW_VER}\"/' ${SRC}"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        # 不用 sed -i:BSD 與 GNU 的參數不相容。寫到暫存檔再 cat 回去,
        # 順便保住原檔的權限與 inode(檔案開頭有 UTF-8 BOM,cat 不會動到)。
        TMP="$(mktemp)"
        trap 'rm -f "$TMP"' EXIT
        NEW_VER_ESC="$(escape_sed_replacement "$NEW_VER")"
        sed "s/^\(VERSION_STR[[:space:]]*=[[:space:]]*\"\)[^\"]*\(\".*\)$/\1${NEW_VER_ESC}\2/" "$SRC" > "$TMP"
        cat "$TMP" > "$SRC"
        rm -f "$TMP"
        trap - EXIT

        WROTE="$(read_version_str)"
        [[ "$WROTE" == "$NEW_VER" ]] \
            || die "VERSION_STR 寫入後讀回是「${WROTE}」,不是預期的「${NEW_VER}」— 已中止,請手動檢查 ${SRC}"
        info "已寫入:VERSION_STR = \"${NEW_VER}\""
    fi
    run git add "$SRC"
    run git commit -q -m "chore: 版號更新 ${NEW_VER}"
fi

# ------------------------------------------------------------
# 2. 打 tag
# ------------------------------------------------------------
step "打 tag"
run git tag -a "$TAG" -m "MM Scribe ${NEW_VER}"

# ------------------------------------------------------------
# 3. 推送
# ------------------------------------------------------------
if [[ "$DO_PUSH" -eq 1 ]]; then
    step "推送"
    run git push "$REMOTE" "$BRANCH"
    run git push "$REMOTE" "$TAG"
fi

# ------------------------------------------------------------
# 4. draft release
# ------------------------------------------------------------
# 建成草稿而非正式發布:workflow 只負責把 zip 掛上來,發版說明要人寫,
# 寫完再自己按 Publish。先建好也讓 workflow 有地方掛 — 沒有 release 的話
# 它只會留 artifact,得事後手動補。
if [[ "$MAKE_RELEASE" == "yes" ]]; then
    step "建立 draft release"
    # tag 這時已經推出去了,gh 失敗(版本太舊、權限不足…)不該讓整支腳本以錯誤收場 —
    # 少的只是一個草稿,補建很便宜,而中斷會讓人以為 tag 也沒推成功。
    if ! run gh release create "$TAG" --draft --title "MM Scribe ${NEW_VER}" --notes ""; then
        echo "  [略過] gh release create 失敗,tag 已經推出去了,可稍後手動建立 release"
        MAKE_RELEASE="failed"
    fi
fi

# ------------------------------------------------------------
step "完成"
if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "  (--dry-run:上面都沒有真的執行)"
    exit 0
fi
if [[ "$DO_PUSH" -eq 1 ]]; then
    REMOTE_URL="$(git remote get-url "$REMOTE")"
    case "$REMOTE_URL" in
        *github.com*)
            REPO_URL="$(printf '%s' "$REMOTE_URL" \
                | sed -e 's#^git@github\.com:#https://github.com/#' \
                      -e 's#^ssh://git@github\.com/#https://github.com/#' \
                      -e 's#\.git$##')"
            echo "  1. macOS 建置進度  : ${REPO_URL}/actions"
            echo "  2. 建好的 zip 會自動掛到 release(約數分鐘)"
            echo "  3. 寫發版說明並發布: ${REPO_URL}/releases"
            ;;
        *)
            echo "  已推送 ${BRANCH} 與 ${TAG} 到 ${REMOTE}"
            ;;
    esac
    echo
    echo "  Windows 版 exe 仍需在 Windows 上跑 Source/MabinogiMobileScribe_BuildTool.bat,"
    echo "  再手動附到同一個 release。"
else
    echo "  本機已完成 commit 與 tag。推送:"
    echo "    git push ${REMOTE} ${BRANCH} && git push ${REMOTE} ${TAG}"
fi
