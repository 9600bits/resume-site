const form = document.querySelector("#unlock-form");
const passwordInput = document.querySelector("#password");
const statusEl = document.querySelector("#unlock-status");
const privateContent = document.querySelector("#private-content");

const textDecoder = new TextDecoder();

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

function createContactBlock(contact = []) {
  const block = element("section", "private-block contact-block full-width");
  block.append(element("h3", "", "联系方式"));

  const list = element("ul", "contact-list contact-card-list");
  for (const item of contact) {
    const listItem = element("li", "contact-card");
    listItem.tabIndex = 0;
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
  if (label.includes("手机")) return "is-phone";
  if (label.includes("微信")) return "is-wechat";
  if (label.includes("邮箱")) return "is-mail";
  if (label.toLowerCase().includes("x")) return "is-x";
  return "is-default";
}

function getContactIcon(label = "") {
  if (label.includes("手机")) {
    return '<svg viewBox="0 0 24 24"><rect x="7" y="2.5" width="10" height="19" rx="2.4"></rect><path d="M10 18h4"></path></svg>';
  }
  if (label.includes("微信")) {
    return '<svg viewBox="0 0 24 24"><path d="M10.6 17.4c-4.1 0-7.4-2.6-7.4-5.9s3.3-5.9 7.4-5.9 7.4 2.6 7.4 5.9-3.3 5.9-7.4 5.9Z"></path><path d="M14.2 14.3c.8 2.2 3 3.7 5.5 3.7.7 0 1.3-.1 1.9-.3l-.7 1.9-2.1-1c-2.4-.2-4.4-1.6-5.2-3.5"></path><circle cx="8.3" cy="10.5" r=".7"></circle><circle cx="12.8" cy="10.5" r=".7"></circle></svg>';
  }
  if (label.includes("邮箱")) {
    return '<svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"></rect><path d="m4 7 8 6 8-6"></path></svg>';
  }
  if (label.toLowerCase().includes("x")) {
    return '<svg viewBox="0 0 24 24"><path d="M5 4l14 16"></path><path d="M19 4 5 20"></path></svg>';
  }
  return '<svg viewBox="0 0 24 24"><path d="M12 21s7-5.2 7-11a7 7 0 0 0-14 0c0 5.8 7 11 7 11Z"></path><circle cx="12" cy="10" r="2.5"></circle></svg>';
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
