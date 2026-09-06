# -*- coding: utf-8 -*-
"""產生 Windows PE 版本資源檔,給 PyInstaller 的 --version-file 使用。

沒有版本資源的 exe 在 Defender 的 ML 啟發式裡是扣分項 —— 正常軟體都會填
公司/產品/版權,一片空白的 metadata 是 Trojan:Win32/Wacatac.B!ml 這類誤判
的成因之一(另外兩項是 UPX 加殼與未簽章)。

版號的唯一來源仍是主程式的 VERSION_STR(見 RELEASING.md),這裡只負責把
"Beta V0.65" 轉成 PE 需要的四元數字 (0, 65, 0, 0)。

用法:
    python make_version_file.py <輸出檔> <exe 檔名> [產品顯示名]
"""
import re
import sys

SOURCE = "MabinogiMobileScribe_Beta.py"
COMPANY = "LeeMoon"
DESCRIPTION = "《瑪奇Mobile》個人傷害統計工具"


def read_version_str():
    """從主程式抄 VERSION_STR。只認行首的定義,才不會撈到字串內嵌的 f"...{VERSION_STR}"。"""
    with open(SOURCE, encoding="utf-8-sig") as f:
        for line in f:
            if line.startswith("VERSION_STR"):
                m = re.search(r'"([^"]*)"', line)
                if m:
                    return m.group(1)
    raise SystemExit(f"[ERROR] 在 {SOURCE} 讀不到 VERSION_STR")


def to_quad(ver):
    """"Beta V0.65" -> (0, 65, 0, 0)。PE 的版號欄位只吃四個 16-bit 整數。"""
    nums = [int(n) for n in re.findall(r"\d+", ver)][:4]
    return tuple(nums + [0] * (4 - len(nums)))


TEMPLATE = """\
# 由 make_version_file.py 自動產生,不要手改 —— 版號跟著主程式的 VERSION_STR 走。
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={quad},
    prodvers={quad},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040404b0',
        [StringStruct('CompanyName', {company!r}),
         StringStruct('FileDescription', {description!r}),
         StringStruct('FileVersion', {ver!r}),
         StringStruct('InternalName', {product!r}),
         StringStruct('LegalCopyright', {copyright!r}),
         StringStruct('OriginalFilename', {filename!r}),
         StringStruct('ProductName', {product!r}),
         StringStruct('ProductVersion', {ver!r})])
    ]),
    VarFileInfo([VarStruct('Translation', [0x404, 1200])])
  ]
)
"""


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    out, filename = sys.argv[1], sys.argv[2]
    product = sys.argv[3] if len(sys.argv) > 3 else filename.rsplit(".", 1)[0]

    ver = read_version_str()
    text = TEMPLATE.format(
        quad=to_quad(ver),
        company=COMPANY,
        description=DESCRIPTION,
        ver=ver,
        product=product,
        copyright=f"Copyright (c) {COMPANY}",
        filename=filename,
    )
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"Version resource : {product} {ver} -> {out}")


if __name__ == "__main__":
    main()
