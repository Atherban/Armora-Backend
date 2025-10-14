import dns from "dns";
const dnsPromises = dns.promises;

export const resolveDNS = async (hostname) => {
  try {
    await dnsPromises.lookup(hostname);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
};
