const form = document.querySelector("#unlock-form");
const passwordInput = document.querySelector("#password");
const statusEl = document.querySelector("#unlock-status");
const privateContent = document.querySelector("#private-content");

const textDecoder = new TextDecoder();
let activePassword = "";

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const password = passwordInput.value;
  if (!password) {
    setStatus("请输入访问密码。");
    return;
  }

  const button = form.querySelector("button");
  button.disabled = true;
  setStatus("正在解锁...");

  try {
    const encrypted = await fetchEncryptedResume();
    const resume = await decryptResume(encrypted, password);
    activePassword = password;
    renderResume(resume);
    form.hidden = true;
    privateContent.hidden = false;
    setStatus("");
  } catch (error) {
    console.error(error);
    setStatus("密码不正确，或加密数据无法读取。");
  } finally {
    button.disabled = false;
  }
});

async function fetchEncryptedResume() {
  const embedded = document.querySelector("#encrypted-resume-data");
  if (embedded?.textContent.trim()) {
    return JSON.parse(embedded.textContent);
  }

  const response = await fetch("private-resume.enc.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error("Encrypted resume file could not be loaded.");
  }
  return response.json();
}

async function decryptResume(payload, password) {
  validatePayload(payload);

  const salt = base64ToBytes(payload.salt);
  const iv = base64ToBytes(payload.iv);
  const ciphertext = base64ToBytes(payload.ciphertext);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: payload.iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );

  return JSON.parse(textDecoder.decode(plaintext));
}

function validatePayload(payload) {
  const required = ["version", "algorithm", "kdf", "iterations", "salt", "iv", "ciphertext"];
  for (const key of required) {
    if (!payload[key]) {
      throw new Error(`Encrypted resume is missing ${key}.`);
    }
  }
  if (payload.algorithm !== "AES-GCM" || payload.kdf !== "PBKDF2-SHA-256") {
    throw new Error("Unsupported encryption settings.");
  }
}

function renderResume(resume) {
  privateContent.innerHTML = "";
  privateContent.append(createPrivateGrid(resume));
}

function createPrivateGrid(resume) {
  const grid = element("div", "private-grid");

  appendIfAny(grid, resume.contact, () => createContactBlock(resume.contact));
  appendIfAny(grid, resume.education, () => createListBlock("补充教育信息", resume.education, (item) => [
    element("span", "item-title", item.school),
    element("span", "item-meta", [item.degree, item.major].filter(Boolean).join(" / ")),
  ]));
  appendIfAny(grid, resume.certificates, () => createListBlock("补充证书信息", resume.certificates, (item) => [
    element("span", "item-title", item.name),
    element("span", "item-meta", item.date || item.status || ""),
  ]));
  appendIfAny(grid, resume.experience, () => createListBlock("补充工作信息", resume.experience, (item) => [
    element("span", "item-title", item.company),
    element("span", "item-meta", [item.period, item.role].filter(Boolean).join(" / ")),
  ], "timeline full-width"));
  grid.append(createAttachmentBlock());
  appendIfAny(grid, resume.notes, () => createTagsBlock("备注", resume.notes));

  if (!grid.children.length) {
    grid.append(createEmptyPrivateBlock());
  }

  return grid;
}

function appendIfAny(parent, items = [], factory) {
  if (Array.isArray(items) && items.length > 0) {
    parent.append(factory());
  }
}

function createListBlock(title, items = [], renderer, listClass = "clean-list") {
  const block = element("section", "private-block");
  block.append(element("h3", "", title));

  const list = element("ul", listClass);
  for (const item of items) {
    const listItem = element("li");
    listItem.append(...renderer(item));
    list.append(listItem);
  }
  block.append(list);
  return block;
}

function createAttachmentBlock() {
  const block = element("section", "private-block attachment-block full-width");
  block.append(
    element("h3", "", "附件简历"),
    element("p", "item-meta", "附件已加密保存，点击后将在浏览器本地解密并下载。")
  );

  const button = element("button", "download-attachment-btn", "下载附件简历");
  button.type = "button";
  button.addEventListener("click", async () => {
    button.disabled = true;
    button.textContent = "正在解密...";
    try {
      await downloadAttachment(activePassword);
      button.textContent = "下载附件简历";
    } catch (error) {
      console.error(error);
      button.textContent = "下载失败，请重试";
      setTimeout(() => {
        button.textContent = "下载附件简历";
      }, 1800);
    } finally {
      button.disabled = false;
    }
  });

  block.append(button);
  return block;
}

async function downloadAttachment(password) {
  const response = await fetch("resume-attachment.enc.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error("Encrypted attachment file could not be loaded.");
  }
  const payload = await response.json();
  const bytes = await decryptBinaryPayload(payload, password);
  const blob = new Blob([bytes], { type: payload.mimeType || "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = payload.fileName || "resume.pdf";
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function decryptBinaryPayload(payload, password) {
  validatePayload(payload);

  const salt = base64ToBytes(payload.salt);
  const iv = base64ToBytes(payload.iv);
  const ciphertext = base64ToBytes(payload.ciphertext);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: payload.iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
}

function createContactBlock(contact = []) {
  const block = element("section", "private-block contact-block full-width");
  block.append(element("h3", "", "联系方式"));

  const list = element("ul", "contact-list contact-card-list");
  for (const item of contact) {
    const listItem = element("li", "contact-card");
    listItem.tabIndex = 0;
    listItem.setAttribute("role", "button");
    listItem.setAttribute("aria-label", `复制${item.label}: ${item.value}`);

    const icon = element("span", `contact-icon ${getContactIconClass(item.label)}`);
    icon.innerHTML = getContactIcon(item.label);
    icon.setAttribute("aria-hidden", "true");

    const content = element("div", "contact-copy");
    content.append(
      element("span", "item-title", item.label),
      element("span", "item-meta", item.value)
    );

    listItem.append(icon, content);
    if (item.qrImage) {
      listItem.classList.add("has-qr");
      listItem.append(createWechatQr(item.qrImage));
    }

    // 添加点击复制功能
    listItem.addEventListener("click", () => copyToClipboard(item.value, item.label));
    listItem.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        copyToClipboard(item.value, item.label);
      }
    });

    list.append(listItem);
  }

  block.append(list);
  return block;
}

function createWechatQr(src) {
  const preview = element("div", "wechat-qr-preview");
  const image = document.createElement("img");
  image.src = src;
  image.alt = "微信二维码";
  image.loading = "lazy";
  preview.append(
    image,
    element("span", "", "扫码添加微信")
  );
  return preview;
}

function getContactIconClass(label = "") {
  if (label.includes("手机") || label.includes("电话")) return "is-phone";
  if (label.includes("微信")) return "is-wechat";
  if (label.includes("邮箱") || label.includes("邮件") || label.toLowerCase().includes("email")) return "is-mail";
  if (label.toLowerCase().includes("x") || label.toLowerCase().includes("twitter")) return "is-x";
  if (label.includes("GitHub") || label.toLowerCase().includes("github")) return "is-github";
  if (label.includes("LinkedIn") || label.toLowerCase().includes("linkedin")) return "is-linkedin";
  return "is-default";
}

function getContactIcon(label = "") {
  if (label.includes("手机") || label.includes("电话")) {
    return '<svg viewBox="0 0 24 24"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path></svg>';
  }
  if (label.includes("微信")) {
    return '<svg viewBox="0 0 24 24"><path d="M8.5 12c-3.2 0-5.8-2.2-5.8-4.9S5.3 2.2 8.5 2.2c3.1 0 5.8 2.2 5.8 4.9 0 1-.3 1.9-.8 2.7" stroke-linecap="round" stroke-linejoin="round"></path><path d="M15.3 8.9c4 0 7.2 2.5 7.2 5.6s-3.2 5.6-7.2 5.6c-.8 0-1.5-.1-2.1-.4l-2.3 1.1.6-2.1c-1.5-1-2.4-2.7-2.4-4.5 0-3.1 3.2-5.6 7.2-5.6Z" stroke-linecap="round" stroke-linejoin="round"></path><circle cx="6.5" cy="6.5" r=".8" fill="currentColor"></circle><circle cx="10.5" cy="6.5" r=".8" fill="currentColor"></circle><circle cx="12.8" cy="13.5" r=".8" fill="currentColor"></circle><circle cx="17.8" cy="13.5" r=".8" fill="currentColor"></circle></svg>';
  }
  if (label.includes("邮箱") || label.includes("邮件") || label.toLowerCase().includes("email")) {
    return '<svg viewBox="0 0 24 24"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6" stroke-linecap="round" stroke-linejoin="round"></polyline></svg>';
  }
  if (label.toLowerCase().includes("x") || label.toLowerCase().includes("twitter")) {
    return '<svg viewBox="0 0 24 24"><path d="M4 4l9.5 13L4 20h2l8-8.5L19 20h5l-9.5-13L23 4h-2l-7.5 8L9 4z" stroke-width="0" fill="currentColor"></path></svg>';
  }
  if (label.includes("GitHub") || label.toLowerCase().includes("github")) {
    return '<svg viewBox="0 0 24 24"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" stroke-linecap="round" stroke-linejoin="round"></path></svg>';
  }
  if (label.includes("LinkedIn") || label.toLowerCase().includes("linkedin")) {
    return '<svg viewBox="0 0 24 24"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z" stroke-linecap="round" stroke-linejoin="round"></path><rect x="2" y="9" width="4" height="12"></rect><circle cx="4" cy="4" r="2"></circle></svg>';
  }
  return '<svg viewBox="0 0 24 24"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z" stroke-linecap="round" stroke-linejoin="round"></path><circle cx="12" cy="10" r="3"></circle></svg>';
}

function createEmptyPrivateBlock() {
  const block = element("section", "private-block full-width");
  block.append(
    element("h3", "", "暂未填写"),
    element("p", "item-meta", "联系方式和补充信息会在最终发布前补充并重新加密。")
  );
  return block;
}

function createTagsBlock(title, notes = []) {
  const block = element("section", "private-block");
  block.append(element("h3", "", title));

  const tags = element("div", "private-tags");
  for (const note of notes) {
    tags.append(element("span", "", note));
  }
  block.append(tags);
  return block;
}

function element(tagName, className = "", text = "") {
  const node = document.createElement(tagName);
  if (className) {
    node.className = className;
  }
  if (text) {
    node.textContent = text;
  }
  return node;
}

function setStatus(message) {
  statusEl.textContent = message;
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function copyToClipboard(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    showCopyToast(`已复制${label}`);
  } catch (error) {
    console.error("复制失败:", error);
    showCopyToast("复制失败，请手动复制", true);
  }
}

function showCopyToast(message, isError = false) {
  // 移除已存在的提示
  const existing = document.querySelector(".copy-toast");
  if (existing) {
    existing.remove();
  }

  const toast = element("div", "copy-toast");
  if (isError) {
    toast.classList.add("is-error");
  }

  const icon = element("span", "toast-icon");
  icon.innerHTML = isError
    ? '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>'
    : '<svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"></polyline></svg>';

  const text = element("span", "toast-text", message);
  toast.append(icon, text);

  document.body.append(toast);

  // 触发动画
  setTimeout(() => toast.classList.add("show"), 10);

  // 3秒后移除
  setTimeout(() => {
    toast.classList.remove("show");
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}
