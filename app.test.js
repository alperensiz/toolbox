"use strict";
const assert = require("node:assert/strict");
const { test } = require("node:test");
const { parseIndicator, buildLinks, getAddressNotice } = require("./app.js");

for (const [input, expected, type] of [
  ["104.28.244.150", "104.28.244.150", "IPv4"],
  ["  EXAMPLE.COM  ", "example.com", "DOMAIN"],
  ["hxxps://example[.]com/login?q=1", "example.com", "DOMAIN"],
  ["104[.]28[.]244[.]150", "104.28.244.150", "IPv4"],
  ["https://sub.example.com:8443/path?q=1#x", "sub.example.com", "DOMAIN"],
  ["https://104.28.244.150:443/path", "104.28.244.150", "IPv4"],
  ["example.com.", "example.com", "DOMAIN"],
  ["2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1", "IPv6"],
  ["[2001:db8::1]:443", "2001:db8::1", "IPv6"],
  ["https://[2001:db8::1]:443/path", "2001:db8::1", "IPv6"],
  ["::1", "::1", "IPv6"],
  ["bücher.de", "xn--bcher-kva.de", "DOMAIN"]
]) test("Parses " + input, () => {
  assert.deepEqual(parseIndicator(input), { value: expected, type, isIP: type !== "DOMAIN" });
});

for (const input of ["", "999.1.1.1", "1.2.3", "01.2.3.4", "2130706433", "0x7f000001", "example..com", "-bad.com", "bad-.com", "localhost", "example.123", "1::2::3", "ftp://example.com", "https://user@example.com", "javascript:alert(1)", "<img src=x>", "example.com\\@evil.com", "1.1.1.1\n2.2.2.2", "example.com:65536", "[::1]:65536"]) {
  test("Rejects " + JSON.stringify(input), () => assert.throws(() => parseIndicator(input)));
}

test("IPv4 links use the same indicator and correct service paths", () => {
  assert.deepEqual(buildLinks(parseIndicator("104.28.244.150")).map(link => link.url), [
    "https://www.abuseipdb.com/check/104.28.244.150",
    "https://ipinfo.io/104.28.244.150",
    "https://www.virustotal.com/gui/ip-address/104.28.244.150",
    "https://www.whois.com/whois/104.28.244.150"
  ]);
});
test("Domain routes preserve domain type without resolving DNS", () => {
  assert.deepEqual(buildLinks(parseIndicator("example.com")).map(link => link.url), [
    null, null, "https://www.virustotal.com/gui/domain/example.com", "https://www.whois.com/whois/example.com"
  ]);
});
test("IPv6 indicators are encoded as URL path values", () => {
  for (const link of buildLinks(parseIndicator("2001:db8::1"))) {
    assert.equal(decodeURIComponent(new URL(link.url).pathname.split("/").at(-1)), "2001:db8::1");
  }
});

for (const [input, category] of [
  ["10.0.0.0", "RFC 1918"], ["10.255.255.255", "RFC 1918"],
  ["172.16.0.0", "RFC 1918"], ["172.31.255.255", "RFC 1918"],
  ["192.168.0.0", "RFC 1918"], ["192.168.255.255", "RFC 1918"],
  ["hxxps://192[.]168[.]1[.]1:443/login", "RFC 1918"],
  ["127.0.0.1", "Loopback"], ["127.255.255.255", "Loopback"],
  ["169.254.0.0", "Link-local"], ["169.254.255.255", "Link-local"],
  ["100.64.0.0", "CGNAT"], ["100.127.255.255", "CGNAT"],
  ["0.0.0.0", "0.0.0.0/8"],
  ["::1", "loopback"], ["::", "Belirtilmemiş"],
  ["fc00::", "ULA"], ["fdff:ffff::1", "ULA"],
  ["fe80::", "link-local"], ["febf:ffff::1", "link-local"],
  ["::ffff:192.168.1.1", "RFC 1918"], ["::ffff:10.0.0.1", "RFC 1918"],
  ["::ffff:127.0.0.1", "Loopback"]
]) test("Explains local range: " + input, () => {
  assert.ok(getAddressNotice(parseIndicator(input)).includes(category));
});

for (const input of ["9.255.255.255", "11.0.0.0", "172.15.255.255", "172.32.0.0", "192.167.255.255", "192.169.0.0", "176.16.1.1", "176.255.255.255", "169.253.255.255", "169.255.0.0", "100.63.255.255", "100.128.0.0", "8.8.8.8", "example.com", "2001:4860:4860::8888", "fbff::1", "fe00::1", "fe7f::1", "fec0::1", "::ffff:8.8.8.8"]) {
  test("Does not mislabel as local: " + input, () => {
    assert.equal(getAddressNotice(parseIndicator(input)), "");
  });
}
