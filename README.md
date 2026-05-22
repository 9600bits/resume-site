# 陈绩个人加密简历页

这是一个准备发布到 GitHub Pages 的静态简历站点。公开页面展示基础信息、学校、证书和工作经历；联系方式与补充信息通过浏览器端 `PBKDF2-SHA-256 + AES-GCM` 加密后展示。

## 本地加密

1. 按需编辑 `private-resume.json`，补充最终联系方式和补充信息。

2. 生成密文：

```powershell
node scripts\encrypt-private-resume.mjs --input private-resume.json --output private-resume.enc.json
```

脚本会提示输入访问密码。密码不会写入仓库，也不能从密文反推。请自行妥善保存正式访问密码。

## 本地预览

页面已经内嵌加密数据，可以直接打开 `index.html` 预览。也可以使用项目自带预览服务：

```powershell
node scripts\serve-preview.mjs 4173
```

然后打开：

```text
http://127.0.0.1:4173/
```

## 发布前检查

确认仓库中没有明文联系方式，并确认 `private-resume.json` 没有被提交：

```powershell
git status --short
git check-ignore -v private-resume.json
Get-ChildItem -Recurse -File | Select-String -Pattern "手机号|邮箱|微信|访问密码"
```

发布前再次提醒：如需更换访问密码，请重新生成 `private-resume.enc.json`。
