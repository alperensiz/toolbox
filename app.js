"use strict";

// All parsing is local. URL is used only as a parser; it does not send requests.
function parseIndicator(input) {
  let value = input.trim().replace(/\[\.\]|\(\.\)/g, ".").replace(/^hxxps:/i, "https:").replace(/^hxxp:/i, "http:");
  if (!value || value.length > 2048 || /[\s\\<>"'@%]/u.test(value)) {
    throw new Error("Tek bir geçerli IP adresi veya domain girin.");
  }
  if (/^[a-z][a-z\d+.-]*:\/\//i.test(value)) {
    if (!/^https?:\/\//i.test(value)) throw new Error("URL için yalnızca http veya https desteklenir.");
    value = value.replace(/^https?:\/\//i, "").split(/[/?#]/)[0];
  }
  if (value.startsWith("[")) {
    const match = value.match(/^\[([\da-f:.]+)\](?::(\d{1,5}))?$/i);
    if (!match || (match[2] && Number(match[2]) > 65535)) throw new Error("Geçerli bir IPv6 adresi girin.");
    value = match[1];
  } else if ((value.match(/:/g) || []).length === 1) {
    const match = value.match(/^([^:]+):(\d{1,5})$/);
    if (!match || Number(match[2]) > 65535) throw new Error("Geçerli bir adres veya port girin.");
    value = match[1];
  }
  if (value.includes(":")) {
    try {
      const host = new URL("https://[" + value + "]/").hostname;
      return { value: host.slice(1, -1), type: "IPv6", isIP: true };
    } catch {
      throw new Error("Geçerli bir IPv6 adresi girin.");
    }
  }
  value = value.replace(/\.$/, "").toLowerCase();
  if (/^[\d.]+$/.test(value)) {
    const parts = value.split(".");
    if (parts.length !== 4 || !parts.every(part => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)) {
      throw new Error("IPv4 adresi 0–255 aralığında dört sayıdan oluşmalı (ör. 104.28.244.150).");
    }
    return { value, type: "IPv4", isIP: true };
  }
  if (!/^[\p{L}\p{N}.-]+$/u.test(value)) throw new Error("Geçerli bir domain girin (ör. example.com).");
  let domain;
  try { domain = new URL("https://" + value + "/").hostname; }
  catch { throw new Error("Geçerli bir domain girin."); }
  const labels = domain.split(".");
  if (domain.length > 253 || labels.length < 2 || /^[\d.]+$/.test(domain) || /^\d+$/.test(labels.at(-1)) || !labels.every(label => label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) {
    throw new Error("Geçerli bir domain girin (ör. example.com).");
  }
  return { value: domain, type: "DOMAIN", isIP: false };
}

function getAddressNotice(indicator) {
  if (!indicator.isIP) return "";
  const value = indicator.value;
  const localMessage = " Bu adres genel internette yönlendirilmez. Dış servisler ağınızdaki cihazı tanımlayamaz; inceleme için yerel ağ kayıtlarını kullanın.";
  if (indicator.type === "IPv4") {
    const [a, b] = value.split(".").map(Number);
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) {
      return "Özel / yerel IP adresi (RFC 1918)." + localMessage;
    }
    if (a === 127) return "Loopback adresi (127.0.0.0/8): cihazın kendisini ifade eder." + localMessage;
    if (a === 169 && b === 254) return "Link-local adresi (169.254.0.0/16): yalnızca aynı ağ bağlantısında kullanılır." + localMessage;
    if (a === 100 && b >= 64 && b <= 127) return "Paylaşımlı adres alanı (100.64.0.0/10, CGNAT): genellikle servis sağlayıcının iç ağında kullanılır." + localMessage;
    if (a === 0) return "Bu ağ için ayrılmış adres (0.0.0.0/8). 0.0.0.0, bağlama göre belirtilmemiş adresi veya tüm yerel arayüzleri ifade eder." + localMessage;
    return "";
  }
  if (value === "::1") return "IPv6 loopback adresi (::1): cihazın kendisini ifade eder." + localMessage;
  if (value === "::") return "Belirtilmemiş IPv6 adresi (::): belirli bir cihaz adresi değildir." + localMessage;
  const first = parseInt(value.split(":")[0] || "0", 16);
  if ((first & 0xfe00) === 0xfc00) return "Özel / yerel IPv6 adresi (fc00::/7, ULA)." + localMessage;
  if ((first & 0xffc0) === 0xfe80) return "IPv6 link-local adresi (fe80::/10): yalnızca aynı ağ bağlantısında kullanılır." + localMessage;
  // The parser normalizes mapped IPv4 tails to two hexadecimal groups.
  const mapped = value.match(/^::ffff:([a-f0-9]{1,4}):([a-f0-9]{1,4})$/);
  if (mapped) {
    const high = parseInt(mapped[1], 16);
    const low = parseInt(mapped[2], 16);
    const ipv4 = [high >> 8, high & 255, low >> 8, low & 255].join(".");
    const notice = getAddressNotice({ value: ipv4, type: "IPv4", isIP: true });
    if (notice) return "IPv4 eşlemeli IPv6 (" + ipv4 + "): " + notice;
  }
  return "";
}

function buildLinks(indicator) {
  const value = encodeURIComponent(indicator.value);
  return [
    { name: "AbuseIPDB", mark: "AB", description: "IP kötüye kullanım raporları", url: indicator.isIP ? "https://www.abuseipdb.com/check/" + value : null },
    { name: "IPinfo", mark: "IP", description: "IP, ağ ve konum bilgileri", url: indicator.isIP ? "https://ipinfo.io/" + value : null },
    { name: "VirusTotal", mark: "VT", description: "İtibar ve ilişkili göstergeler", url: "https://www.virustotal.com/gui/" + (indicator.isIP ? "ip-address/" : "domain/") + value },
    { name: "Whois", mark: "WI", description: "Kayıt ve sahiplik bilgileri", url: "https://www.whois.com/whois/" + value }
  ];
}

if (typeof module !== "undefined" && module.exports) module.exports = { parseIndicator, buildLinks, getAddressNotice };

if (typeof document !== "undefined") {
  const input = document.getElementById("indicator");
  const results = document.getElementById("results");
  const empty = document.getElementById("empty");
  const services = document.getElementById("services");
  const output = document.getElementById("output");
  const error = document.getElementById("error");
  const status = document.getElementById("status");
  const ipNotice = document.getElementById("ip-notice");

  function element(tag, className, text) {
    const node = document.createElement(tag);
    node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  async function copy(text) {
    status.textContent = "";
    try {
      if (!navigator.clipboard || !window.isSecureContext) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(text);
      status.textContent = "Panoya kopyalandı.";
    } catch {
      // Standard manual fallback for file:// or restricted clipboard permissions.
      output.value = text;
      output.focus();
      output.select();
      status.textContent = "Otomatik kopyalama kullanılamıyor. Metin seçildi; Ctrl+C (Mac: ⌘C) ile kopyalayın.";
    }
  }

  let currentLinks = [];
  function resetResults() {
    results.hidden = true;
    empty.hidden = false;
    error.hidden = true;
    ipNotice.hidden = true;
    ipNotice.textContent = "";
    input.removeAttribute("aria-invalid");
    status.textContent = "";
    services.replaceChildren();
    output.value = "";
    currentLinks = [];
  }

  function generate() {
    resetResults();
    let indicator;
    try { indicator = parseIndicator(input.value); }
    catch (issue) {
      error.textContent = issue.message;
      error.hidden = false;
      input.setAttribute("aria-invalid", "true");
      input.focus();
      return;
    }
    const links = buildLinks(indicator);
    const notice = getAddressNotice(indicator);
    ipNotice.textContent = notice;
    ipNotice.hidden = !notice;
    document.getElementById("target").textContent = indicator.value;
    document.getElementById("target-type").textContent = indicator.type;
    for (const service of links) {
      const card = element("article", "service" + (service.url ? "" : " unavailable"));
      const top = element("div", "service-top");
      const title = element("div", "");
      title.append(element("h3", "", service.name), element("p", "", service.description));
      top.append(element("span", "service-mark", service.mark), title);
      const url = element("span", "service-url", service.url || "Bu araçta IP adresiyle kullanılır; domain için DNS çözümlemesi yapılmaz.");
      if (service.url) url.title = service.url;
      card.append(top, url);
      if (service.url) {
        const actions = element("div", "service-actions");
        const copyButton = element("button", "secondary", "Kopyala");
        copyButton.type = "button";
        copyButton.setAttribute("aria-label", service.name + " bağlantısını kopyala");
        copyButton.addEventListener("click", () => copy(service.url));
        const open = element("a", "open-link", "Aç ↗");
        open.href = service.url;
        open.target = "_blank";
        open.rel = "noopener noreferrer";
        open.referrerPolicy = "no-referrer";
        open.setAttribute("aria-label", service.name + " analizini yeni sekmede aç");
        actions.append(copyButton, open);
        card.append(actions);
      }
      services.append(card);
    }
    currentLinks = links.filter(link => link.url).map(link => link.url);
    output.value = currentLinks.join("\n");
    results.hidden = false;
    empty.hidden = true;
    status.textContent = indicator.type + " algılandı. " + currentLinks.length + " bağlantı hazır. Henüz sorgu gönderilmedi.";
  }

  document.getElementById("lookup-form").addEventListener("submit", event => { event.preventDefault(); generate(); });
  input.addEventListener("input", resetResults);
  document.querySelectorAll("[data-example]").forEach(button => button.addEventListener("click", () => { input.value = button.dataset.example; generate(); }));
  document.getElementById("copy-all").addEventListener("click", () => { output.value = currentLinks.join("\n"); copy(output.value); });
  document.getElementById("clear").addEventListener("click", () => { input.value = ""; resetResults(); input.focus(); });
}
